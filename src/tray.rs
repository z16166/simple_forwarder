use anyhow::Result;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tray_icon::{
    menu::{CheckMenuItem, Menu, MenuEvent, MenuItem},
    TrayIcon, TrayIconBuilder, TrayIconEvent,
};
use crate::stats::TrafficStats;

#[cfg(windows)]
use windows::core::PCWSTR;
#[cfg(windows)]
use windows::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY_CURRENT_USER,
    KEY_ALL_ACCESS, REG_SZ,
};
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::GetLongPathNameW;

#[cfg(windows)]
const RUN_REGISTRY_PATH: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\0";
#[cfg(windows)]
const REG_APP_NAME: &str = "SimpleForwarder\0";

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
    autostart_id: tray_icon::menu::MenuId,
    stats_id: tray_icon::menu::MenuId,
    stats: Arc<TrafficStats>,
    is_dialog_open: Arc<AtomicBool>,
}

impl TrayManager {
    pub fn new(rx: mpsc::Receiver<()>, stats: Arc<TrafficStats>) -> Result<Self> {
        let is_active = Arc::new(AtomicBool::new(false));

        let quit_item = MenuItem::new("Quit", true, None);
        let quit_id = quit_item.id().clone();

        let autostart_item = CheckMenuItem::new("Run at Startup", true, false, None);
        let autostart_id = autostart_item.id().clone();

        let stats_item = MenuItem::new("Traffic Statistics...", true, None);
        let stats_id = stats_item.id().clone();

        #[cfg(windows)]
        {
            if let Ok(path) = Self::get_quoted_exe_path() {
                if Self::check_autostart_status(&path) {
                    autostart_item.set_checked(true);
                }
            }
        }

        let menu = Menu::new();
        menu.append_items(&[
            &stats_item,
            &tray_icon::menu::PredefinedMenuItem::separator(),
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
            .with_tooltip("Simple Forwarder\nMemory: Calculating...")
            .with_icon(icon_inactive.clone())
            .build()?;

        let menu_clone = menu.clone();
        let _menu_channel = MenuEvent::receiver();

        let is_active_clone = is_active.clone();

        // Thread ID will be set when run_message_loop() starts on the actual message loop thread.
        let msg_thread_id = Arc::new(AtomicU32::new(0));
        let thread_id_for_activity = msg_thread_id.clone();
        let _thread_id_for_menu = msg_thread_id.clone();

        let mut rx = rx;
        let quit_id_for_loop = quit_id.clone();
        let autostart_id_for_loop = autostart_id.clone();
        let stats_id_for_loop = stats_id.clone();

        tokio::spawn(async move {
            let mut last_activity = std::time::Instant::now();
            let mut currently_active = false;

            log::debug!("Activity detection task started");

            loop {
                tokio::select! {
                    res = rx.recv() => {
                        if res.is_none() {
                            log::debug!("Activity channel closed");
                            break;
                        }
                        last_activity = std::time::Instant::now();
                        if !currently_active {
                            currently_active = true;
                            log::debug!("Activity detected, switching icon to active");
                            is_active_clone.store(true, Ordering::Relaxed);
                            #[cfg(windows)]
                            {
                                let tid = thread_id_for_activity.load(Ordering::Acquire);
                                if tid != 0 {
                                    unsafe {
                                        use windows::Win32::UI::WindowsAndMessaging::{PostThreadMessageW, WM_USER};
                                        let success = PostThreadMessageW(tid, WM_USER + 1, windows::Win32::Foundation::WPARAM(1), windows::Win32::Foundation::LPARAM(0));
                                        if let Err(e) = success {
                                            log::error!("Failed to post active message to main thread: {}", e);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {
                        if currently_active && last_activity.elapsed() > Duration::from_secs(1) {
                            currently_active = false;
                            log::debug!("Inactivity detected, switching icon to inactive");
                            is_active_clone.store(false, Ordering::Relaxed);
                            #[cfg(windows)]
                            {
                                let tid = thread_id_for_activity.load(Ordering::Acquire);
                                if tid != 0 {
                                    unsafe {
                                        use windows::Win32::UI::WindowsAndMessaging::{PostThreadMessageW, WM_USER};
                                        let success = PostThreadMessageW(tid, WM_USER + 1, windows::Win32::Foundation::WPARAM(0), windows::Win32::Foundation::LPARAM(0));
                                        if let Err(e) = success {
                                            log::error!("Failed to post inactive message to main thread: {}", e);
                                        }
                                    }
                                }
                            }
                        }
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
                    TrayIconEvent::Enter { .. } | TrayIconEvent::Move { .. } => {
                        // Throttle updates to at most once per 200ms to avoid flooding
                        if last_update.elapsed() > Duration::from_millis(200) {
                            #[cfg(windows)]
                            {
                                let tid = tid_for_events.load(Ordering::Acquire);
                                if tid != 0 {
                                    unsafe {
                                        use windows::Win32::UI::WindowsAndMessaging::{PostThreadMessageW, WM_USER};
                                        use windows::Win32::Foundation::{WPARAM, LPARAM};
                                        let _ = PostThreadMessageW(tid, WM_USER + 3, WPARAM(0), LPARAM(0));
                                    }
                                }
                            }
                            last_update = std::time::Instant::now();
                        }
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
            autostart_id: autostart_id_for_loop,
            stats_id: stats_id_for_loop,
            stats,
            is_dialog_open: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn run_message_loop(&self) {
        #[cfg(windows)]
        {
            use windows::Win32::UI::WindowsAndMessaging::{
                DispatchMessageW, GetMessageW, TranslateMessage, MSG, WM_USER,
                WM_SETICON, ICON_SMALL, ICON_BIG, DestroyIcon,
                MessageBoxW, MB_OK, MB_ICONINFORMATION,
            };
            use windows::Win32::System::Console::GetConsoleWindow;
            use windows::Win32::Foundation::{WPARAM, LPARAM};
            use windows::core::HSTRING;

            unsafe {
                // Store thread ID so tokio tasks can post messages to this thread.
                let tid = windows::Win32::System::Threading::GetCurrentThreadId();
                self.msg_loop_thread_id.store(tid, Ordering::Release);

                let mut msg = MSG::default();
                log::debug!("Starting Win32 message loop (thread id={})", tid);
                let mut hwnd_console = GetConsoleWindow();
                while GetMessageW(&mut msg, None, 0, 0).as_bool() {
                    // Check for menu events from the receiver (non-blocking)
                    while let Ok(event) = MenuEvent::receiver().try_recv() {
                        if event.id == self.quit_id {
                            log::info!("Quit menu selected");
                            let tid = self.msg_loop_thread_id.load(Ordering::Acquire);
                            if tid != 0 {
                                // Graceful exit from the message loop
                                use windows::Win32::UI::WindowsAndMessaging::PostThreadMessageW;
                                let _ = PostThreadMessageW(tid, WM_USER + 2, WPARAM(0), LPARAM(0));
                                // Fallback: force exit after 3 seconds if graceful shutdown stalls
                                std::thread::spawn(|| {
                                    std::thread::sleep(Duration::from_secs(3));
                                    log::warn!("Graceful shutdown timed out, forcing exit");
                                    std::process::exit(1);
                                });
                            } else {
                                std::process::exit(0);
                            }
                        } else if event.id == self.autostart_id {
                            let is_checked = self.autostart_item.is_checked();
                            log::info!("Toggle Run at Startup: {}", is_checked);
                            if let Ok(path) = Self::get_quoted_exe_path() {
                                if let Err(e) = Self::set_autostart(&path, is_checked) {
                                    log::error!("Failed to update autostart registry: {}", e);
                                    // Revert checkbox on failure
                                    self.autostart_item.set_checked(!is_checked);
                                }
                            }
                        } else if event.id == self.stats_id {
                            let lock = self.is_dialog_open.clone();
                            if lock.swap(true, Ordering::SeqCst) {
                                // Already open
                                continue;
                            }

                            let stats = self.stats.clone();
                            std::thread::spawn(move || {
                                #[cfg(windows)]
                                {
                                    let mem_kb = TrayManager::get_current_memory_usage_kb();
                                    let mem_formatted = TrayManager::format_with_commas(mem_kb);

                                    let direct_in = TrafficStats::format_bytes(stats.direct_rx.load(Ordering::Relaxed));
                                    let direct_out = TrafficStats::format_bytes(stats.direct_tx.load(Ordering::Relaxed));
                                    let upstream_in = TrafficStats::format_bytes(stats.upstream_rx.load(Ordering::Relaxed));
                                    let upstream_out = TrafficStats::format_bytes(stats.upstream_tx.load(Ordering::Relaxed));

                                    let run_time = TrayManager::format_duration(stats.start_time.elapsed());

                                    let stats_text = format!(
                                        "Run Time: {}\n\
                                         Memory Usage: {} KB (Private Mapping)\n\n\
                                         - Direct Traffic -\n\
                                         Inbound: {}\n\
                                         Outbound: {}\n\n\
                                         - Proxy Traffic -\n\
                                         Inbound: {}\n\
                                         Outbound: {}",
                                        run_time, mem_formatted, direct_in, direct_out, upstream_in, upstream_out
                                    );

                                    unsafe {
                                        MessageBoxW(
                                            None,
                                            &HSTRING::from(&stats_text),
                                            &HSTRING::from("Simple Forwarder Status"),
                                            MB_OK | MB_ICONINFORMATION,
                                        );
                                    }
                                }
                                lock.store(false, Ordering::SeqCst);
                            });
                        }
                    }

                    // WM_USER+2: graceful quit request from menu handler
                    if msg.message == WM_USER + 2 {
                        log::info!("Quit message received, exiting message loop");
                        break;
                    }

                    // WM_USER+3: tooltip update request (hover/move)
                    if msg.message == WM_USER + 3 {
                        let _ = self._tray_icon.set_tooltip(Some("Simple Forwarder".to_string()));
                        continue;
                    }

                    if msg.message == WM_USER + 1 {
                        let active = msg.wParam.0 != 0;
                        log::debug!("Received UI update message: active={}", active);

                        // Update Tray Icon using cached icons
                        let icon = if active { &self.icon_active } else { &self.icon_inactive };
                        if let Err(e) = self._tray_icon.set_icon(Some(icon.clone())) {
                            log::error!("Failed to set tray icon: {}", e);
                        }

                        // Lazy re-check for console window if not found initially
                        if hwnd_console.0.is_null() {
                            hwnd_console = GetConsoleWindow();
                        }

                        // Update Taskbar Icon (if console exists) using cached hicons
                        if !hwnd_console.0.is_null() {
                            let hicon = if active { self.hicon_active } else { self.hicon_inactive };
                            use windows::Win32::UI::WindowsAndMessaging::{SendMessageW, SetClassLongPtrW, GCLP_HICON, GCLP_HICONSM};

                            // Try both SendMessage and SetClassLongPtr for maximum compatibility
                            let _ = SendMessageW(hwnd_console, WM_SETICON, WPARAM(ICON_SMALL as usize), LPARAM(hicon.0 as isize));
                            let _ = SendMessageW(hwnd_console, WM_SETICON, WPARAM(ICON_BIG as usize), LPARAM(hicon.0 as isize));
                            
                            #[cfg(target_pointer_width = "64")]
                            {
                                let _ = SetClassLongPtrW(hwnd_console, GCLP_HICON, hicon.0 as isize);
                                let _ = SetClassLongPtrW(hwnd_console, GCLP_HICONSM, hicon.0 as isize);
                            }
                            #[cfg(target_pointer_width = "32")]
                            {
                                use windows::Win32::UI::WindowsAndMessaging::{SetClassLongW, GCL_HICON, GCL_HICONSM};
                                let _ = SetClassLongW(hwnd_console, GCL_HICON, hicon.0 as i32);
                                let _ = SetClassLongW(hwnd_console, GCL_HICONSM, hicon.0 as i32);
                            }
                        }
                        continue;
                    }
                    let _ = TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
                
                // Final cleanup of cached handles
                let _ = DestroyIcon(self.hicon_active);
                let _ = DestroyIcon(self.hicon_inactive);
            }
        }
        #[cfg(not(windows))]
        {
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }

    #[cfg(windows)]
    fn create_hicon_from_rgba(rgba: &[u8], width: i32, height: i32) -> Result<windows::Win32::UI::WindowsAndMessaging::HICON> {
        use windows::Win32::Graphics::Gdi::{CreateBitmap, DeleteObject};
        use windows::Win32::UI::WindowsAndMessaging::{CreateIconIndirect, ICONINFO};

        unsafe {
            // Convert RGBA to BGRA
            let mut bgra = vec![0u8; rgba.len()];
            for i in (0..rgba.len()).step_by(4) {
                bgra[i] = rgba[i + 2];     // B
                bgra[i + 1] = rgba[i + 1]; // G
                bgra[i + 2] = rgba[i];     // R
                bgra[i + 3] = rgba[i + 3]; // A
            }

            let h_bm_color = CreateBitmap(width, height, 1, 32, Some(bgra.as_ptr() as *const _));
            
            // Create a monochrome AND mask (all black = opaque)
            let mask_bytes = vec![0u8; (width * height / 8) as usize];
            let h_bm_mask = CreateBitmap(width, height, 1, 1, Some(mask_bytes.as_ptr() as *const _));

            let icon_info = ICONINFO {
                fIcon: true.into(),
                xHotspot: 0,
                yHotspot: 0,
                hbmMask: h_bm_mask,
                hbmColor: h_bm_color,
            };

            let hicon = CreateIconIndirect(&icon_info)?;

            let _ = DeleteObject(h_bm_color);
            let _ = DeleteObject(h_bm_mask);

            Ok(hicon)
        }
    }

    fn create_simple_icon(active: bool) -> Result<Vec<u8>> {
        let mut rgba = vec![0u8; 32 * 32 * 4];
        let color = if active {
            (0, 255, 0)
        } else {
            (100, 100, 100)
        };

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
        use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX};
        use windows::Win32::System::Threading::GetCurrentProcess;
        
        let mut counters = PROCESS_MEMORY_COUNTERS_EX::default();
        unsafe {
            let handle = GetCurrentProcess();
            if GetProcessMemoryInfo(
                handle,
                &mut counters as *mut _ as *mut _,
                std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32
            ).is_ok() {
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
            if i > 0 && (len - i) % 3 == 0 {
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
            parts.push(format!("{} hour{}", hours, if hours > 1 { "s" } else { "" }));
        }
        if minutes > 0 {
            parts.push(format!("{} minute{}", minutes, if minutes > 1 { "s" } else { "" }));
        }
        if seconds > 0 {
            parts.push(format!("{} second{}", seconds, if seconds > 1 { "s" } else { "" }));
        }

        parts.join(" ")
    }

    #[cfg(windows)]
    fn get_quoted_exe_path() -> Result<String> {
        let path = std::env::current_exe()?;
        let path_str = path.to_string_lossy().to_string();
        
        // Convert to long path name to ensure registry consistency
        let wide_path: Vec<u16> = path_str.encode_utf16().chain(std::iter::once(0)).collect();
        let mut buffer = [0u16; 1024];
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
            let subkey: Vec<u16> = RUN_REGISTRY_PATH
                .encode_utf16()
                .collect();
            
            use windows::Win32::Foundation::ERROR_SUCCESS;
            if RegOpenKeyExW(HKEY_CURRENT_USER, PCWSTR(subkey.as_ptr()), 0, KEY_ALL_ACCESS, &mut hkey) != ERROR_SUCCESS {
                return false;
            }

            let value_name: Vec<u16> = REG_APP_NAME.encode_utf16().collect();
            let mut buffer = [0u16; 1024];
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
                let actual_path = String::from_utf16_lossy(&buffer[..(len / 2).saturating_sub(1) as usize]);
                return actual_path.to_lowercase() == expected_path.to_lowercase();
            }
        }
        false
    }

    #[cfg(windows)]
    fn set_autostart(path: &str, enabled: bool) -> Result<()> {
        unsafe {
            let mut hkey = windows::Win32::System::Registry::HKEY::default();
            let subkey: Vec<u16> = RUN_REGISTRY_PATH
                .encode_utf16()
                .collect();
            
            use windows::Win32::Foundation::ERROR_SUCCESS;
            let status = RegOpenKeyExW(HKEY_CURRENT_USER, PCWSTR(subkey.as_ptr()), 0, KEY_ALL_ACCESS, &mut hkey);
            if status != ERROR_SUCCESS {
                return Err(anyhow::anyhow!("Failed to open registry key: error code {}", status.0));
            }

            let value_name: Vec<u16> = REG_APP_NAME.encode_utf16().collect();
            
            let res = if enabled {
                let path_wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
                let data = std::slice::from_raw_parts(path_wide.as_ptr() as *const u8, path_wide.len() * 2);
                RegSetValueExW(
                    hkey,
                    PCWSTR(value_name.as_ptr()),
                    0,
                    REG_SZ,
                    Some(data),
                )
            } else {
                RegDeleteValueW(hkey, PCWSTR(value_name.as_ptr()))
            };

            let _ = RegCloseKey(hkey);
            if res != ERROR_SUCCESS {
                return Err(anyhow::anyhow!("Registry operation failed: error code {}", res.0));
            }
        }
        Ok(())
    }
}
