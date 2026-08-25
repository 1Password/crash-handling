//! Named pipe IPC transport for Windows.

#![allow(
    unsafe_code,
    non_camel_case_types,
    non_snake_case,
    clippy::upper_case_acronyms
)]

use std::io;

type HANDLE = isize;
type BOOL = i32;
type DWORD = u32;
type ULONG_PTR = usize;
type LPVOID = *mut core::ffi::c_void;
type LPCWSTR = *const u16;
type LPDWORD = *mut DWORD;
type PSID = *mut core::ffi::c_void;

const INVALID_HANDLE_VALUE: HANDLE = -1_isize;
const INFINITE: DWORD = 0xFFFF_FFFF;
const WAIT_OBJECT_0: DWORD = 0;
const WAIT_TIMEOUT: DWORD = 258;

const ERROR_IO_PENDING: DWORD = 997;
const ERROR_PIPE_CONNECTED: DWORD = 535;
const ERROR_BROKEN_PIPE: DWORD = 109;
const ERROR_OPERATION_ABORTED: DWORD = 995;
const ERROR_FILE_NOT_FOUND: DWORD = 2;

const FILE_FLAG_OVERLAPPED: DWORD = 0x4000_0000;
const FILE_FLAG_FIRST_PIPE_INSTANCE: DWORD = 0x0008_0000;
const PIPE_ACCESS_DUPLEX: DWORD = 0x0000_0003;
const PIPE_TYPE_BYTE: DWORD = 0x0000_0000;
const PIPE_READMODE_BYTE: DWORD = 0x0000_0000;
const PIPE_WAIT: DWORD = 0x0000_0000;
const PIPE_UNLIMITED_INSTANCES: DWORD = 255;
const PIPE_BUFFER_SIZE: DWORD = 65536;
const GENERIC_READ: DWORD = 0x8000_0000;
const GENERIC_WRITE: DWORD = 0x4000_0000;
const OPEN_EXISTING: DWORD = 3;
const FILE_ATTRIBUTE_NORMAL: DWORD = 0x0000_0080;
const TOKEN_QUERY: DWORD = 0x0000_0008;
const TOKEN_USER: u32 = 1;

#[repr(C)]
struct OVERLAPPED {
    Internal: ULONG_PTR,
    InternalHigh: ULONG_PTR,
    Offset: DWORD,
    OffsetHigh: DWORD,
    hEvent: HANDLE,
}

#[repr(C)]
struct SECURITY_ATTRIBUTES {
    nLength: DWORD,
    lpSecurityDescriptor: LPVOID,
    bInheritHandle: BOOL,
}


#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateNamedPipeW(
        lpName: LPCWSTR,
        dwOpenMode: DWORD,
        dwPipeMode: DWORD,
        nMaxInstances: DWORD,
        nOutBufferSize: DWORD,
        nInBufferSize: DWORD,
        nDefaultTimeOut: DWORD,
        lpSecurityAttributes: *mut SECURITY_ATTRIBUTES,
    ) -> HANDLE;
    fn ConnectNamedPipe(hNamedPipe: HANDLE, lpOverlapped: *mut OVERLAPPED) -> BOOL;
    fn DisconnectNamedPipe(hNamedPipe: HANDLE) -> BOOL;
    fn CreateFileW(
        lpFileName: LPCWSTR,
        dwDesiredAccess: DWORD,
        dwShareMode: DWORD,
        lpSecurityAttributes: *mut SECURITY_ATTRIBUTES,
        dwCreationDisposition: DWORD,
        dwFlagsAndAttributes: DWORD,
        hTemplateFile: HANDLE,
    ) -> HANDLE;
    fn ReadFile(
        hFile: HANDLE,
        lpBuffer: *mut u8,
        nNumberOfBytesToRead: DWORD,
        lpNumberOfBytesRead: LPDWORD,
        lpOverlapped: *mut OVERLAPPED,
    ) -> BOOL;
    fn WriteFile(
        hFile: HANDLE,
        lpBuffer: *const u8,
        nNumberOfBytesToWrite: DWORD,
        lpNumberOfBytesWritten: LPDWORD,
        lpOverlapped: *mut OVERLAPPED,
    ) -> BOOL;
    fn PeekNamedPipe(
        hNamedPipe: HANDLE,
        lpBuffer: *mut u8,
        nBufferSize: DWORD,
        lpBytesRead: LPDWORD,
        lpTotalBytesAvail: LPDWORD,
        lpBytesLeftThisMessage: LPDWORD,
    ) -> BOOL;
    fn GetNamedPipeClientProcessId(Pipe: HANDLE, ClientProcessId: *mut DWORD) -> BOOL;
    fn CreateEventW(
        lpEventAttributes: *mut SECURITY_ATTRIBUTES,
        bManualReset: BOOL,
        bInitialState: BOOL,
        lpName: LPCWSTR,
    ) -> HANDLE;
    fn SetEvent(hEvent: HANDLE) -> BOOL;
    fn ResetEvent(hEvent: HANDLE) -> BOOL;
    fn WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: DWORD) -> DWORD;
    fn GetOverlappedResult(
        hFile: HANDLE,
        lpOverlapped: *mut OVERLAPPED,
        lpNumberOfBytesTransferred: LPDWORD,
        bWait: BOOL,
    ) -> BOOL;
    fn CancelIoEx(hFile: HANDLE, lpOverlapped: *const OVERLAPPED) -> BOOL;
    fn WaitNamedPipeW(lpNamedPipeName: LPCWSTR, nTimeOut: DWORD) -> BOOL;
    fn Sleep(dwMilliseconds: DWORD);
    fn GetTickCount64() -> u64;
    fn GetCurrentProcess() -> HANDLE;
    fn GetLastError() -> DWORD;
    fn CloseHandle(hObject: HANDLE) -> BOOL;
    fn LocalFree(hMem: LPVOID) -> LPVOID;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(
        ProcessHandle: HANDLE,
        DesiredAccess: DWORD,
        TokenHandle: *mut HANDLE,
    ) -> BOOL;
    fn GetTokenInformation(
        TokenHandle: HANDLE,
        TokenInformationClass: u32,
        TokenInformation: *mut u8,
        TokenInformationLength: DWORD,
        ReturnLength: *mut DWORD,
    ) -> BOOL;
    fn ConvertSidToStringSidW(Sid: PSID, StringSid: *mut *mut u16) -> BOOL;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        StringSecurityDescriptor: LPCWSTR,
        StringSDRevision: DWORD,
        SecurityDescriptor: *mut LPVOID,
        SecurityDescriptorSize: *mut DWORD,
    ) -> BOOL;
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0)).collect()
}

fn last_error() -> io::Error {
    io::Error::last_os_error()
}

/// Derives a `\\.\pipe\<stem>` wide path. Only the final path component is
/// used so callers can pass either a full temp path or a bare name.
pub(crate) fn pipe_path_from(path: &std::path::Path) -> io::Result<Vec<u16>> {
    let stem = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid pipe name"))?;
    Ok(to_wide(&format!(r"\\.\pipe\{stem}")))
}

#[inline]
fn win32_ok(result: BOOL) -> io::Result<()> {
    if result == 0 {
        Err(last_error())
    } else {
        Ok(())
    }
}

// RAII guard for an OS HANDLE.
struct HandleGuard(HANDLE);
impl Drop for HandleGuard {
    fn drop(&mut self) {
        if self.0 != 0 && self.0 != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.0) };
        }
    }
}

// RAII guard for a `LocalAlloc` allocation.
struct LocalGuard(LPVOID);
impl Drop for LocalGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}

/// Returns a `SECURITY_ATTRIBUTES` whose DACL grants `GENERIC_ALL` only to
/// the current user. The two `LocalGuard` values must remain alive as long as
/// the `SECURITY_ATTRIBUTES` is in use.
fn owner_only_security_attributes() -> io::Result<(SECURITY_ATTRIBUTES, LocalGuard)> {
    // 1. Get the current user's SID via the process token.
    let mut token: HANDLE = 0;
    win32_ok(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) })?;
    let _token_guard = HandleGuard(token);

    let mut length: DWORD = 0;
    unsafe { GetTokenInformation(token, TOKEN_USER, std::ptr::null_mut(), 0, &mut length) };
    let mut user_buf = vec![0u8; length as usize];
    win32_ok(unsafe {
        GetTokenInformation(
            token,
            TOKEN_USER,
            user_buf.as_mut_ptr(),
            length,
            &mut length,
        )
    })?;

    // TOKEN_USER.User.Sid is the first pointer-sized field in the buffer.
    let sid: PSID = unsafe { *(user_buf.as_ptr() as *const PSID) };

    // 2. Convert SID → string for use in the SDDL string.
    let mut sid_str_ptr: *mut u16 = std::ptr::null_mut();
    win32_ok(unsafe { ConvertSidToStringSidW(sid, &mut sid_str_ptr) })?;
    let _sid_str_guard = LocalGuard(sid_str_ptr as LPVOID);

    let sid_wcs_len = unsafe { (0_usize..).find(|&i| *sid_str_ptr.add(i) == 0).unwrap_or(0) };
    let sid_string =
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(sid_str_ptr, sid_wcs_len) });

    // "D:P" = Protected DACL (no inheritance). "(A;;GA;;;SID)" = Allow Generic-All.
    let sddl = to_wide(&format!("D:P(A;;GA;;;{sid_string})"));

    // 3. Convert SDDL > a self-relative security descriptor (LocalAlloc'd by the OS).
    // This descriptor already contains the DACL so no further modification is needed.
    let mut descriptor: LPVOID = std::ptr::null_mut();
    let mut descriptor_size: DWORD = 0;
    win32_ok(unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1, // SDDL_REVISION_1
            &mut descriptor,
            &mut descriptor_size,
        )
    })?;
    let sd_guard = LocalGuard(descriptor);

    let security_attributes = SECURITY_ATTRIBUTES {
        nLength: core::mem::size_of::<SECURITY_ATTRIBUTES>() as DWORD,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };

    Ok((security_attributes, sd_guard))
}

/// Server-side named pipe listener.
pub(crate) struct PipeListener {
    /// Full `\\.\pipe\<name>` path as a wide string.
    pipe_path: Vec<u16>,
    /// Current pipe instance waiting for a connection.
    handle: HANDLE,
    /// Manual-reset event signaled when `ConnectNamedPipe` completes.
    event: HANDLE,
    /// Heap-allocated overlapped keeps the I/O state alive across method calls.
    overlapped: Box<OVERLAPPED>,
    /// True when a client connected before `ConnectNamedPipe` was called, so we
    /// manually signaled the event.
    connected: bool,
}

impl PipeListener {
    pub(crate) fn bind(path: &std::path::Path) -> io::Result<Self> {
        let pipe_path = pipe_path_from(path)?;

        let event = unsafe { CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null()) };
        if event == 0 {
            return Err(last_error());
        }

        let mut overlapped = Box::new(OVERLAPPED {
            Internal: 0,
            InternalHigh: 0,
            Offset: 0,
            OffsetHigh: 0,
            hEvent: event,
        });

        let handle = create_pipe_instance(&pipe_path, true)?;
        let mut connected = false;
        if let Err(e) = start_connect(handle, &mut overlapped, event, &mut connected) {
            unsafe {
                CloseHandle(handle);
                CloseHandle(event);
            }
            return Err(e);
        }

        Ok(Self {
            pipe_path,
            handle,
            event,
            overlapped,
            connected,
        })
    }

    /// Waits up to `timeout_ms` for a client connection.
    /// Returns `None` on timeout, `Some(stream)` on success.
    pub(crate) fn accept_timeout_ms(&mut self, timeout_ms: u32) -> io::Result<Option<PipeStream>> {
        let result = unsafe { WaitForSingleObject(self.event, timeout_ms) };
        match result {
            WAIT_TIMEOUT => return Ok(None),
            WAIT_OBJECT_0 => {}
            _ => return Err(last_error()),
        }

        // Confirm the overlapped result (skip when we signaled manually).
        if !self.connected {
            let mut bytes: DWORD = 0;
            let ok =
                unsafe { GetOverlappedResult(self.handle, &mut *self.overlapped, &mut bytes, 0) };
            if ok == 0 {
                let err = unsafe { GetLastError() };
                if err != ERROR_PIPE_CONNECTED {
                    return Err(io::Error::from_raw_os_error(err as i32));
                }
            }
        }

        let connected_handle = core::mem::replace(&mut self.handle, INVALID_HANDLE_VALUE);

        // Ready the listener for the next connection.
        match create_pipe_instance(&self.pipe_path, false) {
            Ok(next) => {
                self.handle = next;
                unsafe { ResetEvent(self.event) };
                self.overlapped.hEvent = self.event;
                self.connected = false;
                if let Err(e) = start_connect(
                    self.handle,
                    &mut self.overlapped,
                    self.event,
                    &mut self.connected,
                ) {
                    log::warn!("failed to start next ConnectNamedPipe: {e}");
                }
            }
            Err(e) => log::warn!("failed to create next pipe instance: {e}"),
        }

        Ok(Some(PipeStream {
            handle: connected_handle,
        }))
    }
}

impl Drop for PipeListener {
    fn drop(&mut self) {
        if self.handle != INVALID_HANDLE_VALUE {
            unsafe {
                DisconnectNamedPipe(self.handle);
                CloseHandle(self.handle);
            }
        }
        if self.event != 0 {
            unsafe { CloseHandle(self.event) };
        }
    }
}

fn create_pipe_instance(pipe_path: &[u16], first_instance: bool) -> io::Result<HANDLE> {
    let (mut security_attributes, _sd_guard) = owner_only_security_attributes()?;

    let mut open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
    if first_instance {
        // Prevents another process from squatting this pipe name before we start.
        open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }

    let handle = unsafe {
        CreateNamedPipeW(
            pipe_path.as_ptr(),
            open_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUFFER_SIZE,
            PIPE_BUFFER_SIZE,
            0,
            &mut security_attributes,
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        return Err(last_error());
    }
    Ok(handle)
}

fn start_connect(
    handle: HANDLE,
    overlapped: &mut Box<OVERLAPPED>,
    event: HANDLE,
    connected: &mut bool,
) -> io::Result<()> {
    *connected = false;
    unsafe {
        ResetEvent(event);
        let ok = ConnectNamedPipe(handle, overlapped.as_mut() as *mut OVERLAPPED);
        if ok != 0 {
            // Synchronous success is unusual for overlapped so treat as immediate.
            *connected = true;
            SetEvent(event);
            return Ok(());
        }
        let err = GetLastError();
        match err {
            ERROR_IO_PENDING => {}
            ERROR_PIPE_CONNECTED => {
                // Client connected before ConnectNamedPipe so signal manually.
                *connected = true;
                SetEvent(event);
            }
            _ => return Err(io::Error::from_raw_os_error(err as i32)),
        }
    }
    Ok(())
}

/// A connected named pipe handle, used for both server-accepted connections and
/// the client side. All I/O goes through overlapped operations so that server
/// reads can be given a timeout.
pub(crate) struct PipeStream {
    handle: HANDLE,
}

unsafe impl Send for PipeStream {}
unsafe impl Sync for PipeStream {}

impl PipeStream {
    /// Connects to `\\.\pipe\<stem(path)>` as a client.
    pub(crate) fn connect(path: &std::path::Path) -> io::Result<Self> {
        let pipe_path = pipe_path_from(path)?;

        // WaitNamedPipeW only blocks when the pipe exists but all instances are
        // busy. If the server hasn't created the pipe yet it returns immediately
        // with ERROR_FILE_NOT_FOUND. Retry until the pipe appears or we time out.
        const TOTAL_TIMEOUT_MS: DWORD = 10_000;
        const POLL_INTERVAL_MS: DWORD = 10;

        let deadline = unsafe { GetTickCount64() } + TOTAL_TIMEOUT_MS as u64;

        loop {
            let now = unsafe { GetTickCount64() };
            let remaining_ms = deadline.saturating_sub(now).min(TOTAL_TIMEOUT_MS as u64) as DWORD;
            if remaining_ms == 0 {
                return Err(io::Error::from_raw_os_error(ERROR_FILE_NOT_FOUND as i32));
            }

            let ok = unsafe { WaitNamedPipeW(pipe_path.as_ptr(), remaining_ms) };
            if ok != 0 {
                break;
            }

            let err = unsafe { GetLastError() };
            if err == ERROR_FILE_NOT_FOUND {
                unsafe { Sleep(POLL_INTERVAL_MS) };
                continue;
            }

            return Err(io::Error::from_raw_os_error(err as i32));
        }

        let handle = unsafe {
            CreateFileW(
                pipe_path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                0,
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            return Err(last_error());
        }

        Ok(Self { handle })
    }

    /// Returns the PID of the client process connected to this server-side pipe.
    pub(crate) fn client_pid(&self) -> io::Result<u32> {
        let mut pid: DWORD = 0;
        win32_ok(unsafe { GetNamedPipeClientProcessId(self.handle, &mut pid) })?;
        Ok(pid)
    }

    /// Non-blocking peek operation that copies up to `buf.len()` bytes without consuming them.
    #[allow(dead_code)]
    pub(crate) fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut bytes_read: DWORD = 0;
        let ok = unsafe {
            PeekNamedPipe(
                self.handle,
                buf.as_mut_ptr(),
                buf.len() as DWORD,
                &mut bytes_read,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            if err == ERROR_BROKEN_PIPE {
                return Ok(0);
            }
            return Err(io::Error::from_raw_os_error(err as i32));
        }
        Ok(bytes_read as usize)
    }

    /// Blocking read.
    pub(crate) fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        Ok(self.read_overlapped(buf, INFINITE)?.unwrap_or(0))
    }

    /// Vectored, sequential read.
    #[allow(dead_code)]
    pub(crate) fn recv_vectored(&self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<usize> {
        let mut total = 0;
        for buf in bufs {
            if buf.is_empty() {
                continue;
            }
            match self.recv(buf) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(e) if total > 0 => {
                    let _ = e;
                    break;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(total)
    }

    /// Read with timeout.
    ///
    /// `None` = timeout
    ///
    /// `Some(0)` = EOF
    ///
    /// `Some(n)` = data
    pub(crate) fn recv_timeout_ms(
        &self,
        buf: &mut [u8],
        timeout_ms: u32,
    ) -> io::Result<Option<usize>> {
        self.read_overlapped(buf, timeout_ms)
    }

    /// Blocking write.
    pub(crate) fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.write_overlapped(buf)
    }

    /// Vectored, sequential write.
    pub(crate) fn send_vectored(&self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        let mut total = 0;
        for buf in bufs {
            if buf.is_empty() {
                continue;
            }
            match self.send(buf) {
                Ok(n) => total += n,
                Err(e) if total > 0 => {
                    let _ = e;
                    break;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(total)
    }

    fn read_overlapped(&self, buf: &mut [u8], timeout_ms: u32) -> io::Result<Option<usize>> {
        if buf.is_empty() {
            return Ok(Some(0));
        }

        let event = unsafe { CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null()) };
        if event == 0 {
            return Err(last_error());
        }
        struct EvGuard(HANDLE);
        impl Drop for EvGuard {
            fn drop(&mut self) {
                unsafe { CloseHandle(self.0) };
            }
        }
        let _ev = EvGuard(event);

        let mut overlapped = OVERLAPPED {
            Internal: 0,
            InternalHigh: 0,
            Offset: 0,
            OffsetHigh: 0,
            hEvent: event,
        };
        let mut bytes_read: DWORD = 0;

        let ok = unsafe {
            ReadFile(
                self.handle,
                buf.as_mut_ptr(),
                buf.len() as DWORD,
                &mut bytes_read,
                &mut overlapped,
            )
        };
        if ok != 0 {
            return Ok(Some(bytes_read as usize));
        }

        let err = unsafe { GetLastError() };
        match err {
            ERROR_IO_PENDING => {}
            ERROR_BROKEN_PIPE => return Ok(Some(0)),
            _ => return Err(io::Error::from_raw_os_error(err as i32)),
        }

        let wait = unsafe { WaitForSingleObject(event, timeout_ms) };
        if wait == WAIT_TIMEOUT {
            // Cancel and wait for cancellation to complete before overlapped goes out of scope.
            unsafe { CancelIoEx(self.handle, &overlapped) };
            let _ =
                unsafe { GetOverlappedResult(self.handle, &mut overlapped, &mut bytes_read, 1) };
            return Ok(None);
        }
        if wait != WAIT_OBJECT_0 {
            return Err(last_error());
        }

        let ok = unsafe { GetOverlappedResult(self.handle, &mut overlapped, &mut bytes_read, 0) };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            if err == ERROR_BROKEN_PIPE || err == ERROR_OPERATION_ABORTED {
                return Ok(Some(0));
            }
            return Err(io::Error::from_raw_os_error(err as i32));
        }

        Ok(Some(bytes_read as usize))
    }

    fn write_overlapped(&self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let event = unsafe { CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null()) };
        if event == 0 {
            return Err(last_error());
        }
        struct EvGuard(HANDLE);
        impl Drop for EvGuard {
            fn drop(&mut self) {
                unsafe { CloseHandle(self.0) };
            }
        }
        let _ev = EvGuard(event);

        let mut overlapped = OVERLAPPED {
            Internal: 0,
            InternalHigh: 0,
            Offset: 0,
            OffsetHigh: 0,
            hEvent: event,
        };
        let mut bytes_written: DWORD = 0;

        let ok = unsafe {
            WriteFile(
                self.handle,
                buf.as_ptr(),
                buf.len() as DWORD,
                &mut bytes_written,
                &mut overlapped,
            )
        };
        if ok != 0 {
            return Ok(bytes_written as usize);
        }

        let err = unsafe { GetLastError() };
        if err != ERROR_IO_PENDING {
            return Err(io::Error::from_raw_os_error(err as i32));
        }

        // Block until write completes (no timeout needed for writes).
        win32_ok(unsafe {
            GetOverlappedResult(self.handle, &mut overlapped, &mut bytes_written, 1)
        })?;

        Ok(bytes_written as usize)
    }
}

impl Drop for PipeStream {
    fn drop(&mut self) {
        if self.handle != INVALID_HANDLE_VALUE && self.handle != 0 {
            unsafe { CloseHandle(self.handle) };
        }
    }
}
