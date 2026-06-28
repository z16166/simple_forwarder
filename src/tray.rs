use crate::connection_tracker::ConnectionTracker;
use crate::stats::TrafficStats;
use crate::traffic_window;
use anyhow::Result;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;
use tray_icon::{
    TrayIcon, TrayIconBuilder, TrayIconEvent,
    menu::{CheckMenuItem, Menu, MenuEvent, MenuItem},
};

/// Interval between traffic activity checks (ms).
const ACTIVITY_CHECK_INTERVAL_MS: u64 = 500;
/// Minimum interval between tooltip hover updates (ms) to avoid flooding.
const HOVER_THROTTLE_INTERVAL_MS: u64 = 200;
/// Fallback timeout for graceful shutdown before forcing exit (seconds).
const FORCE_EXIT_TIMEOUT_SECS: u64 = 3;
/// Buffer size for registry path queries (wide characters).
const REGISTRY_BUFFER_SIZE: usize = 1024;

/// Application display name, used in tooltips and dialogs.
// Issue 7: All UI strings are currently hardcoded in English. To support i18n,
// consider using the `fluent` or `rust-i18n` crate and moving display strings
// to a localization table (e.g. `locales/en.toml`, `locales/zh.toml`).
pub(crate) const APP_NAME: &str = "Simple Forwarder";

#[cfg(windows)]
use windows::Win32::Storage::FileSystem::GetLongPathNameW;
#[cfg(windows)]
use windows::Win32::System::Registry::{
    HKEY_CURRENT_USER, KEY_ALL_ACCESS, REG_SZ, RegCloseKey, RegDeleteValueW, RegOpenKeyExW,
    RegQueryValueExW, RegSetValueExW,
};
#[cfg(windows)]
use windows::core::PCWSTR;

#[cfg(windows)]
const RUN_REGISTRY_PATH: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\0";
#[cfg(windows)]
const REG_APP_NAME: &str = "SimpleForwarder\0";

/// Post a WM_USER+1 message to the message loop thread to update the tray icon (Issue 24).
/// `active` = true → show active icon, false → show inactive icon.
#[cfg(windows)]
fn post_icon_update(tid_source: &Arc<AtomicU32>, active: bool) {
    let tid = tid_source.load(Ordering::Acquire);
    if tid != 0 {
        unsafe {
            use windows::Win32::UI::WindowsAndMessaging::{PostThreadMessageW, WM_USER};
            let success = PostThreadMessageW(
                tid,
                WM_USER + 1,
                windows::Win32::Foundation::WPARAM(active as usize),
                windows::Win32::Foundation::LPARAM(0),
            );
            if let Err(e) = success {
                log::error!("Failed to post icon update message to main thread: {}", e);
            }
        }
    }
}

#[cfg(not(windows))]
fn post_icon_update(_tid_source: &Arc<AtomicU32>, _active: bool) {
    // Non-Windows: icon updates are handled through the tray library's native mechanism.
}

pub struct TrayManager {
    _tray_icon: TrayIcon,
    _is_active: Arc<AtomicBool>,
    _menu: Option<Menu>,
    msg_loop_thread_id: Arc<AtomicU32>,
    icon_active: tray_icon::Icon,
    icon_inactive: tray_icon::Icon,
    #[cfg(windows)]
    hicon_active: windows::Win32::UI::WindowsAndMessaging::HICON,
    #[cfg(windows)]
    hicon_inactive: windows::Win32::UI::WindowsAndMessaging::HICON,
    autostart_item: CheckMenuItem,
    quit_id: tray_icon::menu::MenuId,
    open_dir_id: tray_icon::menu::MenuId,
    autostart_id: tray_icon::menu::MenuId,
    stats_id: tray_icon::menu::MenuId,
    traffic_id: tray_icon::menu::MenuId,
    stats: Arc<TrafficStats>,
    is_dialog_open: Arc<AtomicBool>,
    is_traffic_open: Arc<AtomicBool>,
    traffic_thread_running: Arc<AtomicBool>,
    tracker: Arc<ConnectionTracker>,
}

impl TrayManager {
    pub fn new(stats: Arc<TrafficStats>, tracker: Arc<ConnectionTracker>) -> Result<Self> {
        let is_active = Arc::new(AtomicBool::new(false));

        let quit_item = MenuItem::new("Quit", true, None);
        let quit_id = quit_item.id().clone();

        let open_dir_item = MenuItem::new("Open Program Directory", true, None);
        let open_dir_id = open_dir_item.id().clone();

        let autostart_item = CheckMenuItem::new("Run at Startup", true, false, None);
        let autostart_id = autostart_item.id().clone();

        let stats_item = MenuItem::new("Traffic Statistics...", true, None);
        let stats_id = stats_item.id().clone();

        let traffic_item = MenuItem::new("Real-time Traffic", true, None);
        let traffic_id = traffic_item.id().clone();

        #[cfg(windows)]
        {
            if let Ok(path) = Self::get_quoted_exe_path()
                && Self::check_autostart_status(&path)
            {
                autostart_item.set_checked(true);
            }
        }

        let menu = Menu::new();
        menu.append_items(&[
            &stats_item,
            &traffic_item,
            &tray_icon::menu::PredefinedMenuItem::separator(),
            &open_dir_item,
            &autostart_item,
            &tray_icon::menu::PredefinedMenuItem::separator(),
            &quit_item,
        ])?;

        let icon_active_bytes = Self::create_simple_icon(true)?;
        let icon_inactive_bytes = Self::create_simple_icon(false)?;

        let icon_active = tray_icon::Icon::from_rgba(icon_active_bytes.clone(), 32, 32)?;
        let icon_inactive = tray_icon::Icon::from_rgba(icon_inactive_bytes.clone(), 32, 32)?;

        #[cfg(windows)]
        let hicon_active = Self::create_hicon_from_rgba(&icon_active_bytes, 32, 32)?;
        #[cfg(windows)]
        let hicon_inactive = Self::create_hicon_from_rgba(&icon_inactive_bytes, 32, 32)?;

        let tray_icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu.clone()))
            .with_tooltip(&format!("{}\nMemory: Calculating...", APP_NAME))
            .with_icon(icon_inactive.clone())
            .build()?;

        let menu_clone = menu.clone();

        let is_active_clone = is_active.clone();

        // Thread ID will be set when run_message_loop() starts on the actual message loop thread.
        let msg_thread_id = Arc::new(AtomicU32::new(0));
        let thread_id_for_activity = msg_thread_id.clone();

        let quit_id_for_loop = quit_id.clone();
        let open_dir_id_for_loop = open_dir_id.clone();
        let autostart_id_for_loop = autostart_id.clone();
        let stats_id_for_loop = stats_id.clone();
        let traffic_id_for_loop = traffic_id.clone();

        let stats_clone = stats.clone();
        tokio::spawn(async move {
            let mut currently_active = false;

            log::debug!("Activity detection task started");

            loop {
                tokio::time::sleep(Duration::from_millis(ACTIVITY_CHECK_INTERVAL_MS)).await;

                let active = stats_clone.traffic_active.swap(false, Ordering::Relaxed);

                if active {
                    if !currently_active {
                        currently_active = true;
                        log::debug!("Activity detected, switching icon to active");
                        is_active_clone.store(true, Ordering::Relaxed);
                        post_icon_update(&thread_id_for_activity, true);
                    }
                } else {
                    if currently_active {
                        currently_active = false;
                        log::debug!("Inactivity detected, switching icon to inactive");
                        is_active_clone.store(false, Ordering::Relaxed);
                        post_icon_update(&thread_id_for_activity, false);
                    }
                }
            }
        });

        let tray_event_channel = TrayIconEvent::receiver();
        let tid_for_events = msg_thread_id.clone();
        std::thread::spawn(move || {
            let mut last_update = std::time::Instant::now();
            while let Ok(event) = tray_event_channel.recv() {
                match event {
                    TrayIconEvent::Enter { .. } | TrayIconEvent::Move { .. }
                        // Throttle updates to avoid flooding
                        if last_update.elapsed() > Duration::from_millis(HOVER_THROTTLE_INTERVAL_MS) => {
                            // Issue 25: tooltip updates via hover are only implemented on
                            // Windows because the Win32 message loop (PostThreadMessageW)
                            // is the only mechanism to asynchronously trigger a tooltip
                            // refresh. On non-Windows platforms the tray library handles
                            // native tooltips differently and there is no equivalent
                            // cross-platform message queue.
                            #[cfg(windows)]
                            {
                                let tid = tid_for_events.load(Ordering::Acquire);
                                if tid != 0 {
                                    unsafe {
                                        use windows::Win32::Foundation::{LPARAM, WPARAM};
                                        use windows::Win32::UI::WindowsAndMessaging::{
                                            PostThreadMessageW, WM_USER,
                                        };
                                        let _ = PostThreadMessageW(
                                            tid,
                                            WM_USER + 3,
                                            WPARAM(0),
                                            LPARAM(0),
                                        );
                                    }
                                }
                            }
                            last_update = std::time::Instant::now();
                        }
                    _ => {}
                }
            }
        });

        Ok(Self {
            _tray_icon: tray_icon,
            _is_active: is_active,
            _menu: Some(menu_clone),
            msg_loop_thread_id: msg_thread_id,
            icon_active,
            icon_inactive,
            #[cfg(windows)]
            hicon_active,
            #[cfg(windows)]
            hicon_inactive,
            autostart_item,
            quit_id: quit_id_for_loop,
            open_dir_id: open_dir_id_for_loop,
            autostart_id: autostart_id_for_loop,
            stats_id: stats_id_for_loop,
            traffic_id: traffic_id_for_loop,
            stats,
            is_dialog_open: Arc::new(AtomicBool::new(false)),
            is_traffic_open: Arc::new(AtomicBool::new(false)),
            traffic_thread_running: Arc::new(AtomicBool::new(false)),
            tracker,
        })
    }

    pub fn run_message_loop(&self) {
        #[cfg(windows)]
        {
            use windows::Win32::System::Console::GetConsoleWindow;
            use windows::Win32::UI::WindowsAndMessaging::{
                DestroyIcon, DispatchMessageW, GetMessageW, MSG, TranslateMessage, WM_USER,
            };

            unsafe {
                // Store thread ID so tokio tasks can post messages to this thread.
                let tid = windows::Win32::System::Threading::GetCurrentThreadId();
                self.msg_loop_thread_id.store(tid, Ordering::Release);

                let mut msg = MSG::default();
                log::debug!("Starting Win32 message loop (thread id={})", tid);
                let mut hwnd_console = GetConsoleWindow();
                while GetMessageW(&mut msg, None, 0, 0).as_bool() {
                    // Drain all pending menu events (non-blocking)
                    while let Ok(event) = MenuEvent::receiver().try_recv() {
                        if self.handle_menu_event(&event) {
                            // Quit requested — break out of message loop.
                            break;
                        }
                    }

                    if msg.message == WM_USER + 2 {
                        log::info!("Quit message received, exiting message loop");
                        break;
                    } else if msg.message == WM_USER + 1 {
                        self.handle_icon_update(msg.wParam.0 != 0, &mut hwnd_console);
                    } else if msg.message == WM_USER + 3 {
                        let _ = self._tray_icon.set_tooltip(Some(APP_NAME.to_string()));
                    } else {
                        let _ = TranslateMessage(&msg);
                        DispatchMessageW(&msg);
                    }
                }

                // Final cleanup of cached handles
                let _ = DestroyIcon(self.hicon_active);
                let _ = DestroyIcon(self.hicon_inactive);
            }
        }
        #[cfg(not(windows))]
        {
            loop {
                while let Ok(event) = MenuEvent::receiver().try_recv() {
                    if event.id == self.quit_id {
                        log::info!("Quit menu selected");
                        std::process::exit(0);
                    } else if event.id == self.open_dir_id {
                        // Use let-else to reduce nesting (Issue 23).
                        let Ok(exe_path) = std::env::current_exe() else {
                            continue;
                        };
                        let Some(exe_dir) = exe_path.parent() else {
                            continue;
                        };
                        if let Err(e) = open_directory(exe_dir) {
                            log::error!("Failed to open program directory: {}", e);
                        }
                    } else if event.id == self.stats_id {
                        // Issue 9: handle traffic statistics on non-Windows platforms.
                        let lock = self.is_dialog_open.clone();
                        if lock.swap(true, Ordering::SeqCst) {
                            continue;
                        }
                        let stats = self.stats.clone();
                        std::thread::spawn(move || {
                            // Non-Windows: log stats to console since there's no MessageBox.
                            let direct_in =
                                TrafficStats::format_bytes(stats.direct_rx.load(Ordering::Relaxed));
                            let direct_out =
                                TrafficStats::format_bytes(stats.direct_tx.load(Ordering::Relaxed));
                            let upstream_in = TrafficStats::format_bytes(
                                stats.upstream_rx.load(Ordering::Relaxed),
                            );
                            let upstream_out = TrafficStats::format_bytes(
                                stats.upstream_tx.load(Ordering::Relaxed),
                            );
                            log::info!(
                                "Traffic Stats — Direct: {}/{} | Proxy: {}/{}",
                                direct_in,
                                direct_out,
                                upstream_in,
                                upstream_out
                            );
                            lock.store(false, Ordering::SeqCst);
                        });
                    } else if event.id == self.traffic_id {
                        // Issue 9: handle real-time traffic window on non-Windows platforms.
                        let tracker = self.tracker.clone();
                        let want_visible = self.is_traffic_open.clone();
                        let thread_running = self.traffic_thread_running.clone();
                        traffic_window::open_traffic_window(tracker, want_visible, thread_running);
                    }
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    /// Handle a single menu event. Returns `true` if quit was requested.
    #[cfg(windows)]
    fn handle_menu_event(&self, event: &MenuEvent) -> bool {
        use windows::Win32::Foundation::{LPARAM, WPARAM};
        use windows::Win32::UI::WindowsAndMessaging::{PostThreadMessageW, WM_USER};

        if event.id == self.quit_id {
            log::info!("Quit menu selected");
            let tid = self.msg_loop_thread_id.load(Ordering::Acquire);
            if tid != 0 {
                unsafe {
                    let _ = PostThreadMessageW(tid, WM_USER + 2, WPARAM(0), LPARAM(0));
                }
                std::thread::spawn(|| {
                    std::thread::sleep(Duration::from_secs(FORCE_EXIT_TIMEOUT_SECS));
                    log::warn!("Graceful shutdown timed out, forcing exit");
                    std::process::exit(1);
                });
            } else {
                std::process::exit(0);
            }
            return true;
        }
        if event.id == self.autostart_id {
            let is_checked = self.autostart_item.is_checked();
            log::info!("Toggle Run at Startup: {}", is_checked);
            if let Ok(path) = Self::get_quoted_exe_path()
                && let Err(e) = Self::set_autostart(&path, is_checked)
            {
                log::error!("Failed to update autostart registry: {}", e);
                self.autostart_item.set_checked(!is_checked);
            }
            return false;
        }
        if event.id == self.stats_id {
            let lock = self.is_dialog_open.clone();
            if lock.swap(true, Ordering::SeqCst) {
                return false;
            }
            let stats = self.stats.clone();
            std::thread::spawn(move || {
                let mem_kb = TrayManager::get_current_memory_usage_kb();
                let mem_formatted = TrayManager::format_with_commas(mem_kb);
                let direct_in = TrafficStats::format_bytes(stats.direct_rx.load(Ordering::Relaxed));
                let direct_out =
                    TrafficStats::format_bytes(stats.direct_tx.load(Ordering::Relaxed));
                let upstream_in =
                    TrafficStats::format_bytes(stats.upstream_rx.load(Ordering::Relaxed));
                let upstream_out =
                    TrafficStats::format_bytes(stats.upstream_tx.load(Ordering::Relaxed));
                let run_time = TrayManager::format_duration(stats.start_time.elapsed());
                let admin_line = if crate::is_admin() {
                    "Privilege: Administrator\n"
                } else {
                    ""
                };
                let stats_text = format!(
                    "Listen Address: {}\n\
                     Run Time: {}\n\
                     Memory Usage: {} KB (Private Mapping)\n\
                     {}\
                     \n\
                     - Direct Traffic -\n\
                     Inbound: {}\n\
                     Outbound: {}\n\n\
                     - Proxy Traffic -\n\
                     Inbound: {}\n\
                     Outbound: {}",
                    stats.listen_addr,
                    run_time,
                    mem_formatted,
                    admin_line,
                    direct_in,
                    direct_out,
                    upstream_in,
                    upstream_out
                );
                unsafe {
                    use windows::Win32::UI::WindowsAndMessaging::{
                        MB_ICONINFORMATION, MB_OK, MessageBoxW,
                    };
                    use windows::core::HSTRING;
                    MessageBoxW(
                        None,
                        &HSTRING::from(&stats_text),
                        &HSTRING::from(&format!("{} Status", APP_NAME)),
                        MB_OK | MB_ICONINFORMATION,
                    );
                }
                lock.store(false, Ordering::SeqCst);
            });
            return false;
        }
        if event.id == self.open_dir_id {
            let Ok(exe_path) = std::env::current_exe() else {
                return false;
            };
            let Some(exe_dir) = exe_path.parent() else {
                return false;
            };
            if let Err(e) = open_directory(exe_dir) {
                log::error!("Failed to open program directory: {}", e);
            }
            return false;
        }
        if event.id == self.traffic_id {
            let tracker = self.tracker.clone();
            let want_visible = self.is_traffic_open.clone();
            let thread_running = self.traffic_thread_running.clone();
            traffic_window::open_traffic_window(tracker, want_visible, thread_running);
        }
        false
    }

    /// Handle WM_USER+1: toggle tray/taskbar icon between active and inactive.
    #[cfg(windows)]
    fn handle_icon_update(
        &self,
        active: bool,
        hwnd_console: &mut windows::Win32::Foundation::HWND,
    ) {
        use windows::Win32::Foundation::{LPARAM, WPARAM};
        use windows::Win32::System::Console::GetConsoleWindow;
        use windows::Win32::UI::WindowsAndMessaging::{
            GCLP_HICON, GCLP_HICONSM, ICON_BIG, ICON_SMALL, SendMessageW, SetClassLongPtrW,
            WM_SETICON,
        };

        log::debug!("Received UI update message: active={}", active);

        let icon = if active {
            &self.icon_active
        } else {
            &self.icon_inactive
        };
        if let Err(e) = self._tray_icon.set_icon(Some(icon.clone())) {
            log::error!("Failed to set tray icon: {}", e);
        }

        // Lazy re-check for console window if not found initially
        if hwnd_console.0.is_null() {
            *hwnd_console = unsafe { GetConsoleWindow() };
        }
        if hwnd_console.0.is_null() {
            return;
        }

        let hicon = if active {
            self.hicon_active
        } else {
            self.hicon_inactive
        };
        unsafe {
            let _ = SendMessageW(
                *hwnd_console,
                WM_SETICON,
                WPARAM(ICON_SMALL as usize),
                LPARAM(hicon.0 as isize),
            );
            let _ = SendMessageW(
                *hwnd_console,
                WM_SETICON,
                WPARAM(ICON_BIG as usize),
                LPARAM(hicon.0 as isize),
            );

            #[cfg(target_pointer_width = "64")]
            {
                let _ = SetClassLongPtrW(*hwnd_console, GCLP_HICON, hicon.0 as isize);
                let _ = SetClassLongPtrW(*hwnd_console, GCLP_HICONSM, hicon.0 as isize);
            }
            #[cfg(target_pointer_width = "32")]
            {
                use windows::Win32::UI::WindowsAndMessaging::{
                    GCL_HICON, GCL_HICONSM, SetClassLongW,
                };
                let _ = SetClassLongW(*hwnd_console, GCL_HICON, hicon.0 as i32);
                let _ = SetClassLongW(*hwnd_console, GCL_HICONSM, hicon.0 as i32);
            }
        }
    }

    #[cfg(windows)]
    fn create_hicon_from_rgba(
        rgba: &[u8],
        width: i32,
        height: i32,
    ) -> Result<windows::Win32::UI::WindowsAndMessaging::HICON> {
        use windows::Win32::Graphics::Gdi::{CreateBitmap, DeleteObject};
        use windows::Win32::UI::WindowsAndMessaging::{CreateIconIndirect, ICONINFO};

        unsafe {
            // Convert RGBA to BGRA
            let mut bgra = vec![0u8; rgba.len()];
            for i in (0..rgba.len()).step_by(4) {
                bgra[i] = rgba[i + 2]; // B
                bgra[i + 1] = rgba[i + 1]; // G
                bgra[i + 2] = rgba[i]; // R
                bgra[i + 3] = rgba[i + 3]; // A
            }

            let h_bm_color = CreateBitmap(width, height, 1, 32, Some(bgra.as_ptr() as *const _));

            // Create a monochrome AND mask (all black = opaque)
            let mask_bytes = vec![0u8; (width * height / 8) as usize];
            let h_bm_mask =
                CreateBitmap(width, height, 1, 1, Some(mask_bytes.as_ptr() as *const _));

            let icon_info = ICONINFO {
                fIcon: true.into(),
                xHotspot: 0,
                yHotspot: 0,
                hbmMask: h_bm_mask,
                hbmColor: h_bm_color,
            };

            // Issue 8: always clean up GDI bitmaps, even if CreateIconIndirect fails.
            let result = CreateIconIndirect(&icon_info);
            let _ = DeleteObject(h_bm_color);
            let _ = DeleteObject(h_bm_mask);
            let hicon = result?;

            Ok(hicon)
        }
    }

    fn create_simple_icon(active: bool) -> Result<Vec<u8>> {
        let mut rgba = vec![0u8; 32 * 32 * 4];
        let color = if active { (0, 255, 0) } else { (100, 100, 100) };

        for y in 0..32 {
            for x in 0..32 {
                let idx = (y * 32 + x) * 4;
                if (x + y) % 2 == 0 {
                    rgba[idx] = color.0;
                    rgba[idx + 1] = color.1;
                    rgba[idx + 2] = color.2;
                    rgba[idx + 3] = 255;
                } else {
                    rgba[idx + 3] = 0;
                }
            }
        }

        Ok(rgba)
    }

    #[cfg(windows)]
    fn get_current_memory_usage_kb() -> usize {
        use windows::Win32::System::ProcessStatus::{
            GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX,
        };
        use windows::Win32::System::Threading::GetCurrentProcess;

        let mut counters = PROCESS_MEMORY_COUNTERS_EX::default();
        unsafe {
            let handle = GetCurrentProcess();
            if GetProcessMemoryInfo(
                handle,
                &mut counters as *mut _ as *mut _,
                std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
            )
            .is_ok()
            {
                return counters.PrivateUsage / 1024;
            }
        }
        0
    }

    #[cfg(not(windows))]
    fn get_current_memory_usage_kb() -> usize {
        0
    }

    fn format_with_commas(n: usize) -> String {
        let s = n.to_string();
        let mut result = String::new();
        let bytes = s.as_bytes();
        let len = bytes.len();
        for (i, &b) in bytes.iter().enumerate() {
            if i > 0 && (len - i).is_multiple_of(3) {
                result.push(',');
            }
            result.push(b as char);
        }
        result
    }

    fn format_duration(duration: Duration) -> String {
        let secs = duration.as_secs();
        if secs == 0 {
            return "0 seconds".to_string();
        }

        let days = secs / 86400;
        let hours = (secs % 86400) / 3600;
        let minutes = (secs % 3600) / 60;
        let seconds = secs % 60;

        let mut parts = Vec::new();
        if days > 0 {
            parts.push(format!("{} day{}", days, if days > 1 { "s" } else { "" }));
        }
        if hours > 0 {
            parts.push(format!(
                "{} hour{}",
                hours,
                if hours > 1 { "s" } else { "" }
            ));
        }
        if minutes > 0 {
            parts.push(format!(
                "{} minute{}",
                minutes,
                if minutes > 1 { "s" } else { "" }
            ));
        }
        if seconds > 0 {
            parts.push(format!(
                "{} second{}",
                seconds,
                if seconds > 1 { "s" } else { "" }
            ));
        }

        parts.join(" ")
    }

    #[cfg(windows)]
    fn get_quoted_exe_path() -> Result<String> {
        let path = std::env::current_exe()?;
        let path_str = path.to_string_lossy().to_string();

        // Convert to long path name to ensure registry consistency
        let wide_path: Vec<u16> = path_str.encode_utf16().chain(std::iter::once(0)).collect();
        let mut buffer = [0u16; REGISTRY_BUFFER_SIZE];
        let len = unsafe { GetLongPathNameW(PCWSTR(wide_path.as_ptr()), Some(&mut buffer)) };

        let final_path = if len > 0 && (len as usize) < buffer.len() {
            String::from_utf16_lossy(&buffer[..len as usize])
        } else {
            path_str
        };

        Ok(format!("\"{}\"", final_path))
    }

    #[cfg(windows)]
    fn check_autostart_status(expected_path: &str) -> bool {
        unsafe {
            let mut hkey = windows::Win32::System::Registry::HKEY::default();
            let subkey: Vec<u16> = RUN_REGISTRY_PATH.encode_utf16().collect();

            use windows::Win32::Foundation::ERROR_SUCCESS;
            if RegOpenKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(subkey.as_ptr()),
                0,
                KEY_ALL_ACCESS,
                &mut hkey,
            ) != ERROR_SUCCESS
            {
                return false;
            }

            let value_name: Vec<u16> = REG_APP_NAME.encode_utf16().collect();
            let mut buffer = [0u16; REGISTRY_BUFFER_SIZE];
            let mut len = (buffer.len() * 2) as u32;
            let mut dw_type = windows::Win32::System::Registry::REG_VALUE_TYPE::default();

            let res = RegQueryValueExW(
                hkey,
                PCWSTR(value_name.as_ptr()),
                None,
                Some(&mut dw_type),
                Some(buffer.as_mut_ptr() as *mut _),
                Some(&mut len),
            );

            let _ = RegCloseKey(hkey);

            if res == ERROR_SUCCESS && dw_type == REG_SZ {
                let actual_path =
                    String::from_utf16_lossy(&buffer[..(len / 2).saturating_sub(1) as usize]);
                return actual_path.to_lowercase() == expected_path.to_lowercase();
            }
        }
        false
    }

    #[cfg(windows)]
    fn set_autostart(path: &str, enabled: bool) -> Result<()> {
        unsafe {
            let mut hkey = windows::Win32::System::Registry::HKEY::default();
            let subkey: Vec<u16> = RUN_REGISTRY_PATH.encode_utf16().collect();

            use windows::Win32::Foundation::ERROR_SUCCESS;
            let status = RegOpenKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(subkey.as_ptr()),
                0,
                KEY_ALL_ACCESS,
                &mut hkey,
            );
            if status != ERROR_SUCCESS {
                return Err(anyhow::anyhow!(
                    "Failed to open registry key: error code {}",
                    status.0
                ));
            }

            let value_name: Vec<u16> = REG_APP_NAME.encode_utf16().collect();

            let res = if enabled {
                let path_wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
                let data = std::slice::from_raw_parts(
                    path_wide.as_ptr() as *const u8,
                    path_wide.len() * 2,
                );
                RegSetValueExW(hkey, PCWSTR(value_name.as_ptr()), 0, REG_SZ, Some(data))
            } else {
                RegDeleteValueW(hkey, PCWSTR(value_name.as_ptr()))
            };

            let _ = RegCloseKey(hkey);
            if res != ERROR_SUCCESS {
                return Err(anyhow::anyhow!(
                    "Registry operation failed: error code {}",
                    res.0
                ));
            }
        }
        Ok(())
    }
}

fn open_directory(dir: &std::path::Path) -> std::io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer")
            .arg(dir)
            .spawn()
            .map(|_| ())
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(dir)
            .spawn()
            .map(|_| ())
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(dir)
            .spawn()
            .map(|_| ())
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Unsupported platform",
        ))
    }
}
