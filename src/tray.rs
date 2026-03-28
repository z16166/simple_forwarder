use anyhow::Result;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem},
    TrayIcon, TrayIconBuilder, TrayIconEvent,
};

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
}

impl TrayManager {
    pub fn new(rx: mpsc::Receiver<()>) -> Result<Self> {
        let is_active = Arc::new(AtomicBool::new(false));

        let quit_item = MenuItem::new("Quit", true, None);
        let quit_id = quit_item.id().clone();
        let menu = Menu::new();
        menu.append(&quit_item)?;

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
        let menu_channel = MenuEvent::receiver();

        let is_active_clone = is_active.clone();

        // Thread ID will be set when run_message_loop() starts on the actual message loop thread.
        let msg_thread_id = Arc::new(AtomicU32::new(0));
        let thread_id_for_activity = msg_thread_id.clone();
        let thread_id_for_menu = msg_thread_id.clone();

        tokio::spawn(async move {
            let mut last_activity = std::time::Instant::now();
            let mut rx = rx;
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

        // Use std::thread (not tokio::spawn) because menu_channel.recv() is a
        // blocking synchronous call that would monopolize a tokio worker thread.
        std::thread::spawn(move || {
            while let Ok(event) = menu_channel.recv() {
                if event.id == quit_id {
                    log::info!("Quit menu selected");
                    #[cfg(windows)]
                    {
                        let tid = thread_id_for_menu.load(Ordering::Acquire);
                        if tid != 0 {
                            unsafe {
                                use windows::Win32::UI::WindowsAndMessaging::{PostThreadMessageW, WM_USER};
                                use windows::Win32::Foundation::{WPARAM, LPARAM};
                                // Try graceful shutdown: post quit message to the message loop
                                match PostThreadMessageW(tid, WM_USER + 2, WPARAM(0), LPARAM(0)) {
                                    Ok(_) => log::info!("Posted quit message to message loop thread (tid={})", tid),
                                    Err(e) => {
                                        log::error!("PostThreadMessageW failed: {}, forcing exit", e);
                                        std::process::exit(1);
                                    }
                                }
                            }
                            // Fallback: force exit after 3 seconds if graceful shutdown stalls
                            std::thread::spawn(|| {
                                std::thread::sleep(Duration::from_secs(3));
                                log::warn!("Graceful shutdown timed out, forcing exit");
                                std::process::exit(1);
                            });
                        } else {
                            // Message loop hasn't started yet — force exit immediately
                            log::warn!("Message loop not started, forcing exit");
                            std::process::exit(0);
                        }
                    }
                    #[cfg(not(windows))]
                    {
                        std::process::exit(0);
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
        })
    }

    pub fn run_message_loop(&self) {
        #[cfg(windows)]
        {
            use windows::Win32::UI::WindowsAndMessaging::{
                DispatchMessageW, GetMessageW, TranslateMessage, MSG, WM_USER,
                WM_SETICON, ICON_SMALL, ICON_BIG, DestroyIcon, HICON,
            };
            use windows::Win32::System::Console::GetConsoleWindow;
            use windows::Win32::Foundation::{WPARAM, LPARAM};

            unsafe {
                // Store thread ID so tokio tasks can post messages to this thread.
                let tid = windows::Win32::System::Threading::GetCurrentThreadId();
                self.msg_loop_thread_id.store(tid, Ordering::Release);

                let mut msg = MSG::default();
                log::debug!("Starting Win32 message loop (thread id={})", tid);
                let mut hwnd_console = GetConsoleWindow();
                while GetMessageW(&mut msg, None, 0, 0).as_bool() {
                    // WM_USER+2: graceful quit request from menu handler
                    if msg.message == WM_USER + 2 {
                        log::info!("Quit message received, exiting message loop");
                        break;
                    }

                    // WM_USER+3: tooltip update request (hover/move)
                    if msg.message == WM_USER + 3 {
                        let mem_kb = Self::get_current_memory_usage_kb();
                        let mem_formatted = Self::format_with_commas(mem_kb);
                        let tooltip = format!("Simple Forwarder\nMemory: {} (KB)", mem_formatted);
                        let _ = self._tray_icon.set_tooltip(Some(tooltip));
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
        use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
        use windows::Win32::System::Threading::GetCurrentProcess;
        
        let mut counters = PROCESS_MEMORY_COUNTERS::default();
        unsafe {
            let handle = GetCurrentProcess();
            if GetProcessMemoryInfo(handle, &mut counters, std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32).is_ok() {
                return counters.WorkingSetSize / 1024;
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
}
