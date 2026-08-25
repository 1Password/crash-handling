#[cfg(not(target_os = "windows"))]
use super::Connection;
use super::{Header, Listener, SocketName};
use crate::{Error, LoopAction};
#[cfg(not(target_os = "windows"))]
use polling::{Event, Poller};
use std::io::Write;
#[cfg(not(target_os = "windows"))]
use std::io::{Cursor, ErrorKind};
#[cfg(not(target_os = "windows"))]
use std::time::{Duration, Instant};

/// Server side of the connection, which runs in the monitor process that is
/// meant to monitor the process where the [`super::Client`] resides
pub struct Server {
    listener: Option<Listener>,
    #[cfg(target_os = "macos")]
    port: crash_context::ipc::Server,
    #[cfg(not(target_os = "windows"))]
    socket_path: Option<std::path::PathBuf>,
}

#[cfg(not(target_os = "windows"))]
struct ClientConn {
    /// The actual socket connection we established with accept
    socket: Connection,
    /// The key we associated with the socket
    key: usize,
    /// Last time a message was sent from the client
    last_update: Instant,
    /// We pair the pid of the client process so that we know which connection
    /// to drop when a crash is received on the mach port
    #[cfg(target_os = "macos")]
    pid: Option<u32>,
}

#[cfg(not(target_os = "windows"))]
impl ClientConn {
    fn recv(&mut self, handler: &dyn crate::ServerHandler) -> Option<(u32, Vec<u8>)> {
        use std::io::IoSliceMut;

        let mut hdr_buf = [0u8; std::mem::size_of::<Header>()];
        cfg_if::cfg_if! {
            if #[cfg(any(target_os = "linux", target_os = "android"))] {
                let len = self.socket.0.peek(&mut hdr_buf).ok()?;
            } else {
                let len = self.socket.peek(&mut hdr_buf).ok()?;
            }
        }

        if len == 0 {
            return None;
        }

        let header = Header::from_bytes(&hdr_buf)?;

        if header.size == 0 {
            self.socket.recv(&mut hdr_buf).ok()?;
            Some((header.kind, Vec::new()))
        } else {
            let mut buffer = handler.message_alloc();

            buffer.resize(header.size as usize, 0);

            self.socket
                .recv_vectored(&mut [IoSliceMut::new(&mut hdr_buf), IoSliceMut::new(&mut buffer)])
                .ok()?;

            Some((header.kind, buffer))
        }
    }
}

impl Server {
    /// Creates a new server with the given name.
    ///
    /// Note that in the case of a path socket name, this method always attempts
    /// to delete the specified path if it exists as both Windows and Macos have
    /// issues around cleaning up these files if the process the server runs in
    /// aborts abnormally.
    ///
    /// # Errors
    ///
    /// The provided socket name is invalid, or the listener socket was unable
    /// to be bound to the specified socket name.
    pub fn with_name<'scope>(name: impl Into<SocketName<'scope>>) -> Result<Self, Error> {
        let sn = name.into();

        cfg_if::cfg_if! {
            if #[cfg(any(target_os = "linux", target_os = "android"))] {
                #[allow(irrefutable_let_patterns)]
                let socket_path = if let SocketName::Path(path) = &sn {
                    let _res = std::fs::remove_file(path);
                    Some(std::path::PathBuf::from(path))
                } else {
                    None
                };

                let socket_addr = match sn {
                    SocketName::Path(path) => {
                        uds::UnixSocketAddr::from_path(path).map_err(|_err| Error::InvalidName)?
                    }
                    SocketName::Abstract(name) => {
                        uds::UnixSocketAddr::from_abstract(name).map_err(|_err| Error::InvalidName)?
                    }
                };

                let listener = Listener(uds::nonblocking::UnixSeqpacketListener::bind_unix_addr(&socket_addr)?);
            } else if #[cfg(target_os = "windows")] {
                let SocketName::Path(path) = sn;
                let listener = Listener::bind(path)?;
            } else if #[cfg(target_os = "macos")] {
                let SocketName::Path(path) = sn;

                let socket_path = {
                    let _res = std::fs::remove_file(path);
                    Some(std::path::PathBuf::from(path))
                };

                // Note that sun_path is limited to 108 characters including null,
                // while a mach port name is limited to 128 including null, so
                // the length is already effectively checked here

                // We setup the mach port first so no one can race to creating the
                // port.
                let port_name = std::ffi::CString::new(path.to_str().ok_or(Error::InvalidPortName)?).map_err(|_err| Error::InvalidPortName)?;
                let port = crash_context::ipc::Server::create(&port_name)?;

                let listener = Listener::bind(path)?;
                listener.set_nonblocking(true)?;
            } else {
                compile_error!("unimplemented target platform");
            }
        }

        Ok(Self {
            listener: Some(listener),
            #[cfg(target_os = "macos")]
            port,
            #[cfg(not(target_os = "windows"))]
            socket_path,
        })
    }

    /// Runs the server loop, accepting client connections and receiving IPC
    /// messages.
    ///
    /// On Windows, this uses blocking named-pipe I/O with a 200 ms accept/read
    /// timeout so the shutdown flag is polled regularly. On other platforms it
    /// uses the `polling` crate for event-driven I/O.
    ///
    /// If `stale_timeout` is specified, client connections that have not sent
    /// a message within that period will be shut down (non-Windows only).
    ///
    /// # Errors
    ///
    /// Underlying I/O errors from the OS.
    #[allow(unsafe_code)]
    #[cfg(target_os = "windows")]
    pub fn run(
        &mut self,
        handler: Box<dyn crate::ServerHandler>,
        shutdown: &std::sync::atomic::AtomicBool,
        _stale_timeout: Option<std::time::Duration>,
    ) -> Result<(), Error> {
        use std::sync::atomic::Ordering;

        let mut listener = self.listener.take().unwrap();

        'accept: loop {
            if shutdown.load(Ordering::Relaxed) {
                return Ok(());
            }

            // Poll for an incoming connection every 200ms so we can check shutdown.
            const TIMEOUT_MS: u32 = 200;
            let conn = match listener.accept_timeout_ms(TIMEOUT_MS)? {
                None => continue 'accept,
                Some(c) => c,
            };

            // Verify that the connecting process is who we expect. The pipe DACL
            // already blocks other users. This check ensures the right process
            // within the same user session is the one connecting.
            let client_pid = match conn.client_pid() {
                Ok(pid) => pid,
                Err(e) => {
                    log::error!("GetNamedPipeClientProcessId failed: {e}");
                    continue 'accept;
                }
            };

            if handler.on_client_connected(1) == LoopAction::Exit {
                return Ok(());
            }

            'messages: loop {
                if shutdown.load(Ordering::Relaxed) {
                    return Ok(());
                }

                // Read the fixed-size header with a 200 ms timeout.
                let mut hdr_buf = [0u8; std::mem::size_of::<Header>()];
                match conn.recv_timeout_ms(&mut hdr_buf, TIMEOUT_MS)? {
                    None => continue 'messages, // timeout — check shutdown
                    Some(0) => break 'messages, // pipe closed
                    Some(n) if n < hdr_buf.len() => {
                        log::error!("dropping connection due to short header read ({n} bytes)");
                        break 'messages;
                    }
                    Some(_) => {}
                }

                let header = match Header::from_bytes(&hdr_buf) {
                    Some(h) => h,
                    None => break 'messages,
                };

                // Read the variable-length body.
                let mut buffer = handler.message_alloc();
                if header.size > 0 {
                    buffer.resize(header.size as usize, 0);
                    let mut total = 0;
                    while total < buffer.len() {
                        match conn.recv_timeout_ms(&mut buffer[total..], 1000)? {
                            None | Some(0) => break 'messages,
                            Some(n) => total += n,
                        }
                    }
                }

                match header.kind {
                    super::CRASH => {
                        use scroll::Pread;
                        let mut offset = 0;
                        let dump_request: super::DumpRequest = match buffer.gread(&mut offset) {
                            Ok(r) => r,
                            Err(e) => {
                                log::error!("failed to parse dump request: {e}");
                                break 'messages;
                            }
                        };

                        // Verify that the process that connected is the one claiming to crash.
                        if dump_request.process_id != client_pid {
                            log::warn!(
                                "rejecting dump request: PID mismatch (pipe={client_pid}, \
                                 request={})",
                                dump_request.process_id
                            );
                            break 'messages;
                        }

                        let crash_ctx = crash_context::CrashContext {
                            exception_pointers: dump_request.exception_pointers
                                as *const crash_context::EXCEPTION_POINTERS,
                            process_id: dump_request.process_id,
                            thread_id: dump_request.thread_id,
                            exception_code: dump_request.exception_code,
                        };

                        let action = match Self::handle_crash_request(crash_ctx, handler.as_ref()) {
                            Err(err) => {
                                log::error!("failed to capture minidump: {err}");
                                handler.on_minidump_created(Err(err))
                            }
                            Ok(action) => {
                                log::info!("captured minidump");
                                action
                            }
                        };

                        let ack_header = Header {
                            kind: super::CRASH_ACK,
                            size: 0,
                        };
                        let _ = conn.send(ack_header.as_bytes());

                        if action == LoopAction::Exit {
                            return Ok(());
                        }
                        break 'messages;
                    }
                    super::PING => {
                        let pong = Header {
                            kind: super::PONG,
                            size: 0,
                        };
                        if let Err(e) = conn.send(pong.as_bytes()) {
                            log::error!("failed to send PONG: {e}");
                            break 'messages;
                        }
                    }
                    super::PONG => {}
                    kind => {
                        handler.on_message(kind - super::USER, buffer);
                    }
                }
            }

            if handler.on_client_disconnected(0) == LoopAction::Exit {
                return Ok(());
            }
        }
    }

    #[allow(unsafe_code)]
    #[cfg(not(target_os = "windows"))]
    pub fn run(
        &mut self,
        handler: Box<dyn crate::ServerHandler>,
        shutdown: &std::sync::atomic::AtomicBool,
        stale_timeout: Option<std::time::Duration>,
    ) -> Result<(), Error> {
        let mut events = polling::Events::new();
        let listener = self.listener.take().unwrap();

        struct Poll {
            listener: Listener,
            clients: Vec<ClientConn>,
            poll: Poller,
        }

        impl Poll {
            fn new(listener: Listener) -> std::io::Result<Self> {
                let s = Self {
                    listener,
                    poll: Poller::new()?,
                    clients: Vec::new(),
                };

                // SAFETY: We ensure we delete the listener during drop
                unsafe {
                    s.poll.add(&s.listener, Event::readable(0))?;
                }

                Ok(s)
            }

            #[inline]
            fn add(
                &mut self,
                src: impl polling::AsRawSource,
                interest: Event,
            ) -> std::io::Result<()> {
                // SAFETY: We ensure we delete all sources we add before dropping the poll
                unsafe { self.poll.add(src, interest) }
            }
        }

        impl Drop for Poll {
            fn drop(&mut self) {
                for client in std::mem::take(&mut self.clients) {
                    if let Err(err) = self.poll.delete(client.socket) {
                        log::error!("failed to deregister socket: {err}");
                    }
                }

                if let Err(err) = self.poll.delete(&self.listener) {
                    log::error!("failed to deregister listener: {err}");
                }
            }
        }

        let mut polling = Poll::new(listener)?;
        let mut id = 1;

        loop {
            if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                return Ok(());
            }

            events.clear();
            let timeout = Duration::from_millis(200);
            let deadline = Instant::now() + timeout;
            let mut remaining = Some(timeout);
            while let Some(timeout) = remaining {
                match polling.poll.wait(&mut events, Some(timeout)) {
                    Ok(_) => {
                        break;
                    }
                    Err(e) => {
                        if matches!(e.kind(), ErrorKind::Interrupted) {
                            remaining = deadline.checked_duration_since(Instant::now());
                        } else {
                            return Err(e.into());
                        }
                    }
                }
            }

            #[cfg(target_os = "macos")]
            if self.check_mach_port(&polling.poll, &mut polling.clients, handler.as_ref())?
                == LoopAction::Exit
            {
                return Ok(());
            }

            for event in events.iter() {
                if event.key == 0 {
                    match polling.listener.accept_unix_addr() {
                        Ok((accepted, _addr)) => {
                            let key = id;
                            id += 1;

                            polling.add(&accepted, Event::readable(key))?;

                            log::debug!("accepted connection {key}");
                            polling.clients.push(ClientConn {
                                socket: accepted,
                                key,
                                last_update: Instant::now(),
                                #[cfg(target_os = "macos")]
                                pid: None,
                            });

                            if handler.on_client_connected(polling.clients.len())
                                == LoopAction::Exit
                            {
                                log::debug!("on_client_connected exited message loop");
                                return Ok(());
                            }
                        }
                        Err(err) => {
                            log::error!("failed to accept socket connection: {err}");
                        }
                    }

                    // We need to reregister insterest every time
                    polling.poll.modify(&polling.listener, Event::readable(0))?;
                } else if let Some(pos) = polling.clients.iter().position(|cc| cc.key == event.key)
                {
                    polling.clients[pos].last_update = Instant::now();

                    let deregister = match polling.clients[pos].recv(handler.as_ref()) {
                        Some((super::CRASH, buffer)) => {
                            cfg_if::cfg_if! {
                                if #[cfg(target_os = "macos")] {
                                    use scroll::Pread;
                                    let pid: u32 = buffer.pread(0)?;
                                    polling.clients[pos].pid = Some(pid);

                                    if let Err(err) = polling.clients[pos].socket.send(&[1]) {
                                        log::error!("failed to send ack: {err}");
                                    }

                                    None
                                } else {
                                    let cc = polling.clients.swap_remove(pos);

                                    let crash_ctx: Option<crash_context::CrashContext>;
                                    {
                                        let peer_creds = cc.socket.0.initial_peer_credentials()?;

                                        let pid = peer_creds.pid().ok_or(Error::UnknownClientPid)?;

                                        let parsed = crash_context::CrashContext::from_bytes(&buffer).ok_or_else(|| {
                                            Error::from(std::io::Error::new(
                                                std::io::ErrorKind::InvalidData,
                                                "client sent an incorrectly sized buffer",
                                            ))
                                        })?;

                                        // Validate that the crash info and the socket agree on the pid
                                        if pid.get() != parsed.pid as u32 {
                                            return Err(Error::UnknownClientPid);
                                        }

                                        crash_ctx = Some(parsed);
                                    }

                                    if let Some(crash_ctx) = crash_ctx {
                                        let action =
                                            match Self::handle_crash_request(crash_ctx, handler.as_ref()) {
                                                Err(err) => {
                                                    log::error!("failed to capture minidump: {err}");
                                                    handler.on_minidump_created(Err(err))
                                                }
                                                Ok(action) => {
                                                    log::info!("captured minidump");
                                                    action
                                                }
                                            };

                                        let ack = Header {
                                            kind: super::CRASH_ACK,
                                            size: 0,
                                        };

                                        if let Err(err) = cc.socket.send(ack.as_bytes()) {
                                            log::error!("failed to send ack: {err}");
                                        }

                                        if action == LoopAction::Exit {
                                            log::debug!("user handler requested exit after minidump creation");
                                            return Ok(());
                                        }
                                    }

                                    Some(cc.socket)
                                }
                            }
                        }
                        Some((super::PING, _buffer)) => {
                            let pong = Header {
                                kind: super::PONG,
                                size: 0,
                            };

                            if let Err(err) = polling.clients[pos].socket.send(pong.as_bytes()) {
                                log::error!("failed to send PONG: {err}");

                                let cc = polling.clients.swap_remove(pos);
                                Some(cc.socket)
                            } else {
                                None
                            }
                        }
                        Some((super::PONG, _buffer)) => None,
                        Some((kind, buffer)) => {
                            handler.on_message(
                                kind - super::USER, /* give the user back the original code they specified */
                                buffer,
                            );

                            // We only send acks for crash dump requests
                            // if let Err(e) = clients[pos].socket.send(&[1]) {
                            //     log::error!("failed to send ack: {}", e);
                            // }

                            None
                        }
                        None => {
                            log::debug!("client closed socket {pos}");
                            let cc = polling.clients.swap_remove(pos);
                            Some(cc.socket)
                        }
                    };

                    if let Some(socket) = deregister {
                        if let Err(err) = polling.poll.delete(&socket) {
                            log::error!("failed to deregister socket: {err}");
                        }

                        if handler.on_client_disconnected(polling.clients.len()) == LoopAction::Exit
                        {
                            log::debug!("on_client_disconnected exited message loop");
                            return Ok(());
                        }
                    } else {
                        let conn = &polling.clients[pos];
                        polling
                            .poll
                            .modify(&conn.socket, Event::readable(conn.key))?;
                    }
                }
            }

            if let Some(st) = stale_timeout {
                let before = polling.clients.len();

                // Reap any connections that haven't sent a message in the period
                // specified by the user
                polling.clients.retain(|conn| {
                    let keep = conn.last_update.elapsed() < st;

                    if !keep {
                        log::debug!("dropping stale connection {:?}", conn.last_update.elapsed());
                        if let Err(err) = polling.poll.delete(&conn.socket) {
                            log::error!("failed to deregister timed-out socket: {err}");
                        }
                    }

                    keep
                });

                if before > polling.clients.len()
                    && handler.on_client_disconnected(polling.clients.len()) == LoopAction::Exit
                {
                    log::debug!("on_client_disconnected exited message loop");
                    return Ok(());
                }
            }
        }
    }

    fn handle_crash_request(
        crash_context: crash_context::CrashContext,
        handler: &dyn crate::ServerHandler,
    ) -> Result<LoopAction, Error> {
        let (mut minidump_hard_file, minidump_path) = handler.create_minidump_file()?.unzip();
        #[cfg(not(target_os = "windows"))]
        let mut minidump_file: Cursor<Vec<u8>> = Cursor::new(Vec::new());

        cfg_if::cfg_if! {
            if #[cfg(any(target_os = "linux", target_os = "android"))] {
                let mut writer =
                    minidump_writer::minidump_writer::MinidumpWriter::new(crash_context.pid, crash_context.tid);
                writer.set_crash_context(minidump_writer::crash_context::CrashContext { inner: crash_context });
            } else if #[cfg(target_os = "windows")] {
                // The exception_pointers field in DumpRequest is a pointer into the crashing
                // process's memory. MiniDumpWriteDump reads it via ReadProcessMemory, so if the
                // process has already exited or that memory has been freed the dump may be
                // incomplete. Windows handles this gracefully rather than faulting.
                let process_handle = handler.process_handle_for_pid(crash_context.process_id);
                handler.pre_dump(process_handle.unwrap_or(0), crash_context.process_id);
                let mut result =
                    minidump_writer::minidump_writer::MinidumpWriter::dump_crash_context(crash_context, process_handle, None, None);
            } else if #[cfg(target_os = "macos")] {
                let mut writer = minidump_writer::minidump_writer::MinidumpWriter::with_crash_context(crash_context);
            }
        }
        #[cfg(not(target_os = "windows"))]
        let result = writer.dump(&mut minidump_file);
        if let Some(minidump_hard_file) = minidump_hard_file.as_mut() {
            #[cfg(not(target_os = "windows"))]
            {
                let buffer = &minidump_file.clone().into_inner();
                minidump_hard_file.write_all(buffer).unwrap();
                minidump_hard_file.flush().unwrap();
            }
            #[cfg(target_os = "windows")]
            {
                result = result.and_then(
                    |buffer| -> Result<Vec<u8>, minidump_writer::errors::Error> {
                        minidump_hard_file.write_all(&buffer)?;
                        Ok(buffer)
                    },
                );
            }
        }
        // Notify the user handler about the minidump, even if we failed to write it
        Ok(handler.on_minidump_created(
            result
                .map(|contents| crate::MinidumpBinary {
                    file: minidump_hard_file,
                    path: minidump_path,
                    contents: contents,
                })
                .map_err(crate::Error::from),
        ))
    }

    #[cfg(target_os = "macos")]
    fn check_mach_port(
        &mut self,
        poll: &Poller,
        clients: &mut Vec<ClientConn>,
        handler: &dyn crate::ServerHandler,
    ) -> Result<LoopAction, Error> {
        // We use a really short timeout for receiving on the mach port since we check it
        // frequently rather than spawning a separate thread and blocking
        if let Some(mut rcc) = self
            .port
            .try_recv_crash_context(Some(Duration::from_millis(1)))?
        {
            // Try to find a client connection that matches the port sender
            let pos = clients
                .iter()
                .position(|cc| cc.pid == Some(rcc.pid))
                .ok_or(Error::UnknownClientPid)?;
            let cc = clients.swap_remove(pos);

            let action = match Self::handle_crash_request(rcc.crash_context, handler) {
                Err(err) => {
                    log::error!("failed to capture minidump: {err}");
                    LoopAction::Continue
                }
                Ok(action) => {
                    log::info!("captured minidump");
                    action
                }
            };

            if let Err(err) = rcc.acker.send_ack(1, Some(Duration::from_secs(2))) {
                log::error!("failed to send ack: {err}");
            }

            if let Err(err) = poll.delete(&cc.socket) {
                log::error!("failed to deregister socket: {err}");
            }

            Ok(action)
        } else {
            Ok(LoopAction::Continue)
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.listener.take();

        #[cfg(not(target_os = "windows"))]
        if let Some(path) = self.socket_path.take() {
            // Note we don't check for the existence of the path since there
            // appears to be a bug on MacOS, or at least an oversight in std,
            // where checking the existence of the path always fails.
            let _res = std::fs::remove_file(path);
        }
    }
}
