// ── Cache configuration constants ─────────────────────────────────────

/// Maximum number of entries in the PID/exe caches before eviction.
const EXE_CACHE_CAPACITY: usize = 1000;
/// Time-to-live for cache entries; stale entries are evicted on capacity overflow.
const EXE_CACHE_TTL_SECS: u64 = 30;

/// ETW session name, shared between startup and cleanup.
const ETW_SESSION_NAME: &str = "SimpleFwd-NetTrace";

// ── RAII handle wrapper (Issue 8) ──────────────────────────────────────

/// RAII guard for Windows `HANDLE` values obtained from `OpenProcess`,
/// `OpenProcessToken`, etc. Calls `CloseHandle` on drop.
#[cfg(windows)]
struct SafeHandle(windows::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl SafeHandle {
    fn is_invalid(&self) -> bool {
        self.0.is_invalid()
    }
}

#[cfg(windows)]
impl Drop for SafeHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe { let _ = windows::Win32::Foundation::CloseHandle(self.0); }
        }
    }
}

// ── Cross-platform PID → exe name ─────────────────────────────────────

#[cfg(windows)]
fn resolve_pid_to_exe(pid: u32) -> Option<String> {
    use windows::Win32::System::ProcessStatus::{
        K32GetModuleFileNameExW, K32GetProcessImageFileNameW,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let raw = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }.ok()?;
    let handle = SafeHandle(raw);
    if handle.is_invalid() {
        return None;
    }

    // MAX_PATH on Windows is 260 wide characters.
    const WINDOWS_MAX_PATH: usize = 260;
    let name = unsafe {
        let mut buf = vec![0u16; WINDOWS_MAX_PATH];
        let len = K32GetModuleFileNameExW(handle.0, None, &mut buf);
        let len = if len == 0 {
            K32GetProcessImageFileNameW(handle.0, &mut buf)
        } else {
            len
        };
        if len == 0 {
            return None;
        }
        String::from_utf16_lossy(&buf[..len as usize])
    };
    // handle is dropped here → CloseHandle called automatically.

    std::path::Path::new(&name)
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .or(Some(name))
}

#[cfg(target_os = "linux")]
fn resolve_pid_to_exe(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{}/comm", pid))
        .ok()
        .map(|s| s.trim().to_string())
}

#[cfg(target_os = "macos")]
fn resolve_pid_to_exe(pid: u32) -> Option<String> {
    // PROC_PIDPATHINFO_MAXSIZE = 4096
    const MACOS_PROC_PIDPATH_MAXSIZE: usize = 4096;
    let mut buf = vec![0u8; MACOS_PROC_PIDPATH_MAXSIZE];
    unsafe {
        let ret = libc::proc_pidpath(pid as i32, buf.as_mut_ptr() as *mut _, buf.len() as u32);
        if ret <= 0 {
            return None;
        }
        let path = std::ffi::CStr::from_ptr(buf.as_ptr() as *const _)
            .to_string_lossy()
            .to_string();
        std::path::Path::new(&path)
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn resolve_pid_to_exe(_pid: u32) -> Option<String> {
    None
}

// ── Cross-platform netstat2 fallback ────────────────────────────────────

mod netstat_fallback {
    use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};

    /// Blocking call — caller must wrap in `spawn_blocking`.
    pub fn lookup_port_to_pid(listen_port: u16, remote_port: u16) -> Option<u32> {
        let af = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
        let proto = ProtocolFlags::TCP;
        let sockets = netstat2::get_sockets_info(af, proto).ok()?;

        for si in sockets {
            if let ProtocolSocketInfo::Tcp(tcp) = &si.protocol_socket_info {
                // Match the CLIENT side: local port == client's source port,
                // remote port == our listen port. PID is the client process.
                // This works for same-host clients (loopback / local LAN).
                // Remote clients do not have a socket entry on the proxy host.
                if tcp.remote_port == listen_port && tcp.local_port == remote_port {
                    let pid = *si.associated_pids.first()?;
                    if pid == 0 || pid == 4 {
                        return None; // System / idle — skip
                    }
                    log::debug!(
                        "netstat2: matched local=*:{}, remote=*:{} → pid={}",
                        tcp.local_port,
                        tcp.remote_port,
                        pid,
                    );
                    return Some(pid);
                }
            }
        }
        None
    }
}

// ── Cache eviction helper (Issue 2) ─────────────────────────────────────

/// Evict stale entries from a port-keyed cache when it exceeds capacity.
///
/// Removes entries older than [`EXE_CACHE_TTL_SECS`] only when the map
/// length exceeds [`EXE_CACHE_CAPACITY`], keeping eviction overhead bounded.
fn evict_stale_entries<V>(map: &mut std::collections::HashMap<u16, (V, std::time::Instant)>) {
    if map.len() > EXE_CACHE_CAPACITY {
        let now = std::time::Instant::now();
        map.retain(|_, (_, time)| {
            now.duration_since(*time) < std::time::Duration::from_secs(EXE_CACHE_TTL_SECS)
        });
    }
}

// ── Windows implementation (ETW + netstat2 fallback) ────────────────────

#[cfg(windows)]
mod imp {
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use std::sync::Arc;

    use std::time::Instant;
    use super::{evict_stale_entries, ETW_SESSION_NAME};

    #[derive(Clone)]
    pub struct ExeResolver {
        /// PID source: populated by ETW callback (cheap, no syscalls).
        port_to_pid: Arc<Mutex<HashMap<u16, (u32, Instant)>>>,
        /// Resolved exe name cache.
        port_to_exe: Arc<Mutex<HashMap<u16, (String, Instant)>>>,
        listen_port: u16,
    }

    impl ExeResolver {
        pub fn new(listen_port: u16) -> Self {
            let port_to_pid = Arc::new(Mutex::new(HashMap::new()));
            let port_to_exe = Arc::new(Mutex::new(HashMap::new()));

            let pid_map = port_to_pid.clone();
            let exe_map = port_to_exe.clone();
            if !try_start_etw(listen_port, pid_map, exe_map) {
                log::warn!("ETW unavailable, using netstat2 fallback for exe resolution");
            }

            Self {
                port_to_pid,
                port_to_exe,
                listen_port,
            }
        }

        /// Resolve exe name for a connection's source port.
        ///
        /// Uses `spawn_blocking` for any blocking OS call (netstat2 scan,
        /// `OpenProcess`+`K32GetModuleFileNameExW`) to avoid starving the
        /// Tokio worker thread pool.
        ///
        /// Note: this method is intentionally kept separate from the non-Windows
        /// version rather than fully unified behind a trait. The Windows variant
        /// has an extra ETW PID cache branch that makes the control flow differ
        /// meaningfully; forcing both into a single generic would require a
        /// strategy trait with marginal benefit. The shared cache logic is
        /// extracted into `resolve_and_cache_pid` (Issue 4).
        pub async fn lookup(&self, remote_port: u16) -> Option<String> {
            // Fast path: already-resolved cache.
            if let Some((exe, _)) = self.port_to_exe.lock().get(&remote_port).cloned() {
                return Some(exe);
            }

            // ETW-provided PID — resolve in spawn_blocking.
            // Guard must be dropped before the await point.
            let etw_pid = self
                .port_to_pid
                .lock()
                .get(&remote_port)
                .map(|(pid, _)| *pid);
            if let Some(pid) = etw_pid {
                return self.resolve_and_cache_pid(remote_port, pid).await;
            }

            // Fallback: scan TCP connection table (blocking OS call).
            let listen_port = self.listen_port;
            let pid = tokio::task::spawn_blocking(move || {
                super::netstat_fallback::lookup_port_to_pid(listen_port, remote_port)
            })
            .await
            .ok()??;

            // Cache the PID so future lookups on this port avoid another scan.
            {
                let mut pid_map = self.port_to_pid.lock();
                pid_map.insert(remote_port, (pid, Instant::now()));
                evict_stale_entries(&mut pid_map);
            }

            self.resolve_and_cache_pid(remote_port, pid).await
        }

        /// Resolve PID → exe name and cache the result if the PID is still current.
        ///
        /// Lock ordering: always `port_to_pid` → `port_to_exe` (Issue 6).
        async fn resolve_and_cache_pid(&self, remote_port: u16, pid: u32) -> Option<String> {
            let exe = tokio::task::spawn_blocking(move || super::resolve_pid_to_exe(pid))
                .await
                .ok()??;
            // Only cache if the PID hasn't changed since we started resolving.
            let pid_map = self.port_to_pid.lock();
            if pid_map.get(&remote_port).map(|(p, _)| *p) == Some(pid) {
                let mut exe_map = self.port_to_exe.lock();
                exe_map.insert(remote_port, (exe.clone(), Instant::now()));
                evict_stale_entries(&mut exe_map);
            }
            Some(exe)
        }

        /// Evict cached entries for a port that is no longer in use.
        pub fn remove(&self, port: u16) {
            self.port_to_pid.lock().remove(&port);
            self.port_to_exe.lock().remove(&port);
        }

        pub fn cleanup(&self) {
            etw_cleanup::stop_session_if_exists(ETW_SESSION_NAME);
        }
    }

    // ── ETW trace (primary) ──────────────────────────────────────────────

    /// Provider: Microsoft-Windows-TCPIP
    /// GUID:    {7DD42A49-5329-4832-8DFD-43D979153A88}
    ///
    /// Event ID 10 (TcpConnectTcpEndpoint): fired when a local TCP connection
    /// is established. Fields used:
    ///   - `dport` (u16): destination port (== our listen port for inbound connections)
    ///   - `sport` (u16): source port of the connecting client process
    ///
    /// `process_id()` on the record gives the PID of the connecting process.
    fn try_start_etw(
        listen_port: u16,
        port_to_pid: Arc<Mutex<HashMap<u16, (u32, std::time::Instant)>>>,
        port_to_exe: Arc<Mutex<HashMap<u16, (String, std::time::Instant)>>>,
    ) -> bool {
        use std::time::Duration;

        use ferrisetw::EventRecord;
        use ferrisetw::parser::Parser;
        use ferrisetw::provider::Provider;
        use ferrisetw::schema_locator::SchemaLocator;
        use ferrisetw::trace::UserTrace;

        // Fixed session name so stale sessions from previous runs can be cleaned.
        let session_name = ETW_SESSION_NAME;

        // Best-effort cleanup: stop any previous session with this name.
        etw_cleanup::stop_session_if_exists(ETW_SESSION_NAME);

        // Kernel network providers require SeSystemProfilePrivilege, even as admin.
        if !enable_system_profile_privilege() {
            log::debug!("ETW: failed to enable SeSystemProfilePrivilege");
            return false;
        }

        let (tx, rx) = std::sync::mpsc::channel();

        let _ = std::thread::Builder::new()
            .name("etw-trace".into())
            .spawn(move || {
                log::debug!(
                    "ETW: starting trace session \"{}\" on port {}",
                    session_name,
                    listen_port
                );

                let provider = Provider::by_guid("7DD42A49-5329-4832-8DFD-43D979153A88")
                    .add_callback(
                        move |record: &EventRecord, schema_locator: &SchemaLocator| {
                            if record.event_id() != 10 {
                                return;
                            }
                            let pid = record.process_id();

                            let schema = match schema_locator.event_schema(record) {
                                Ok(s) => s,
                                Err(_) => return,
                            };
                            let parser = Parser::create(record, &schema);

                            let dport: u16 = match parser.try_parse("dport") {
                                Ok(p) => p,
                                Err(_) => return,
                            };
                            if dport != listen_port {
                                return;
                            }

                            let sport: u16 = match parser.try_parse("sport") {
                                Ok(p) => p,
                                Err(_) => return,
                            };
                            if sport == 0 {
                                return;
                            }

                            let mut pid_map = port_to_pid.lock();
                            let mut exe_map = port_to_exe.lock();
                            let now = std::time::Instant::now();
                            pid_map.insert(sport, (pid, now));
                            exe_map.remove(&sport);
                            // Lock ordering: always pid_map → exe_map (consistent with lookup()).
                            evict_stale_entries(&mut pid_map);
                            evict_stale_entries(&mut exe_map);
                            log::debug!("ETW: captured pid={}, sport={}", pid, sport);
                            drop(pid_map);
                            drop(exe_map);
                        },
                    )
                    .build();

                let trace = UserTrace::new().named(session_name.into()).enable(provider);

                // start_and_process() spawns an internal processing thread and
                // returns immediately with the trace handle.
                match trace.start_and_process() {
                    Ok(_t) => {
                        let _ = tx.send(true);
                        log::debug!("ETW: trace session started successfully");
                        // Keep _t alive so the trace runs for the program lifetime.
                        // The thread will be terminated on process exit (process::exit(0)).
                        // Sleep in a loop — a single sleep(u64::MAX) would saturate
                        // to u32::MAX ms (~49.7 days) on Windows and return early,
                        // dropping _t and silently stopping the ETW session.
                        loop {
                            std::thread::sleep(std::time::Duration::from_secs(3600));
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(false);
                        log::error!("ETW: failed to start trace session: {:?}", e);
                    }
                }
            });

        // Wait up to 2 seconds for trace startup confirmation.
        rx.recv_timeout(Duration::from_secs(2)).unwrap_or(false)
    }

    // ── SeSystemProfilePrivilege ─────────────────────────────────────────

    fn enable_system_profile_privilege() -> bool {
        use windows::Win32::Security::{
            AdjustTokenPrivileges, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
            TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        unsafe {
            let mut raw = windows::Win32::Foundation::HANDLE::default();
            if OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut raw,
            )
            .is_err()
            {
                log::debug!("ETW: OpenProcessToken failed");
                return false;
            }
            let token = super::SafeHandle(raw);

            let mut luid = std::mem::zeroed();
            if LookupPrivilegeValueW(
                None,
                windows::core::w!("SeSystemProfilePrivilege"),
                &mut luid,
            )
            .is_err()
            {
                log::debug!("ETW: LookupPrivilegeValueW failed");
                return false;
            }

            let mut tp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                ..Default::default()
            };
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            let ret = AdjustTokenPrivileges(token.0, false, Some(&tp), 0, None, None);
            // token dropped here → CloseHandle called automatically.

            if ret.is_err() {
                log::debug!("ETW: AdjustTokenPrivileges failed: {:?}", ret);
                return false;
            }
        }

        log::debug!("ETW: SeSystemProfilePrivilege enabled");
        true
    }

    // ── Stale session cleanup ────────────────────────────────────────────

    mod etw_cleanup {
        pub fn stop_session_if_exists(name: &str) {
            use windows::Win32::Foundation::WIN32_ERROR;
            use windows::Win32::System::Diagnostics::Etw::{
                CONTROLTRACE_HANDLE, ControlTraceW, EVENT_TRACE_CONTROL_STOP,
                EVENT_TRACE_PROPERTIES,
            };
            use windows::core::PCWSTR;

            let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

            let mut props: EVENT_TRACE_PROPERTIES = unsafe { std::mem::zeroed() };
            props.Wnode.BufferSize = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;

            let ret = unsafe {
                ControlTraceW(
                    CONTROLTRACE_HANDLE::default(),
                    PCWSTR::from_raw(wide.as_ptr()),
                    &mut props,
                    EVENT_TRACE_CONTROL_STOP,
                )
            };

            if ret == WIN32_ERROR(0) {
                log::debug!("ETW cleanup: stopped stale session \"{}\"", name);
            }
        }
    }
}

#[cfg(windows)]
pub use imp::ExeResolver;

// ── Non-Windows implementation (netstat2 only) ──────────────────────────

#[cfg(not(windows))]
mod imp {
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Instant;
    use super::evict_stale_entries;

    #[derive(Clone)]
    pub struct ExeResolver {
        port_to_pid: Arc<Mutex<HashMap<u16, (u32, Instant)>>>,
        port_to_exe: Arc<Mutex<HashMap<u16, (String, Instant)>>>,
        listen_port: u16,
    }

    impl ExeResolver {
        pub fn new(listen_port: u16) -> Self {
            Self {
                port_to_pid: Arc::new(Mutex::new(HashMap::new())),
                port_to_exe: Arc::new(Mutex::new(HashMap::new())),
                listen_port,
            }
        }

        pub async fn lookup(&self, remote_port: u16) -> Option<String> {
            // Fast path: already-resolved cache.
            if let Some((exe, _)) = self.port_to_exe.lock().get(&remote_port).cloned() {
                return Some(exe);
            }

            // Check if we already have a cached PID from a previous netstat lookup.
            let cached_pid = self
                .port_to_pid
                .lock()
                .get(&remote_port)
                .map(|(pid, _)| *pid);
            if let Some(pid) = cached_pid {
                return self.resolve_and_cache_pid(remote_port, pid).await;
            }

            // Fallback: scan TCP connection table (blocking OS call).
            let listen_port = self.listen_port;
            let pid = tokio::task::spawn_blocking(move || {
                super::netstat_fallback::lookup_port_to_pid(listen_port, remote_port)
            })
            .await
            .ok()??;

            // Cache the PID so future lookups on this port avoid another scan.
            {
                let mut pid_map = self.port_to_pid.lock();
                pid_map.insert(remote_port, (pid, Instant::now()));
                evict_stale_entries(&mut pid_map);
            }

            self.resolve_and_cache_pid(remote_port, pid).await
        }

        /// Resolve PID → exe name and cache the result if the PID is still current.
        ///
        /// Lock ordering: always `port_to_pid` → `port_to_exe` (Issue 6).
        async fn resolve_and_cache_pid(&self, remote_port: u16, pid: u32) -> Option<String> {
            let exe = tokio::task::spawn_blocking(move || super::resolve_pid_to_exe(pid))
                .await
                .ok()??;
            // Only cache if the PID hasn't changed since we started resolving.
            let pid_map = self.port_to_pid.lock();
            if pid_map.get(&remote_port).map(|(p, _)| *p) == Some(pid) {
                let mut exe_map = self.port_to_exe.lock();
                exe_map.insert(remote_port, (exe.clone(), Instant::now()));
                evict_stale_entries(&mut exe_map);
            }
            Some(exe)
        }

        pub fn remove(&self, port: u16) {
            self.port_to_pid.lock().remove(&port);
            self.port_to_exe.lock().remove(&port);
        }

        pub fn cleanup(&self) {}
    }
}

#[cfg(not(windows))]
pub use imp::ExeResolver;
