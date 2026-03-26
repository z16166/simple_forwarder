use anyhow::Result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem},
    TrayIcon, TrayIconBuilder,
};

pub struct TrayManager {
    _tray_icon: TrayIcon,
    _is_active: Arc<AtomicBool>,
    _menu: Option<Menu>,
}

impl TrayManager {
    pub fn new(rx: mpsc::Receiver<()>) -> Result<Self> {
        let is_active = Arc::new(AtomicBool::new(false));

        let quit_item = MenuItem::new("Quit", true, None);
        let quit_id = quit_item.id().clone();
        let menu = Menu::new();
        menu.append(&quit_item)?;

        let icon_bytes = Self::create_simple_icon(false)?;

        let tray_icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu.clone()))
            .with_tooltip("Simple Forwarder")
            .with_icon(tray_icon::Icon::from_rgba(icon_bytes, 32, 32)?)
            .build()?;

        let menu_clone = menu.clone();
        let menu_channel = MenuEvent::receiver();

        let is_active_clone = is_active.clone();
        
        #[cfg(windows)]
        let main_thread_id = unsafe { windows::Win32::System::Threading::GetCurrentThreadId() };

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
                            unsafe {
                                use windows::Win32::UI::WindowsAndMessaging::{PostThreadMessageW, WM_USER};
                                let success = PostThreadMessageW(main_thread_id, WM_USER + 1, windows::Win32::Foundation::WPARAM(1), windows::Win32::Foundation::LPARAM(0));
                                if let Err(e) = success {
                                    log::error!("Failed to post active message to main thread: {}", e);
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
                            unsafe {
                                use windows::Win32::UI::WindowsAndMessaging::{PostThreadMessageW, WM_USER};
                                let success = PostThreadMessageW(main_thread_id, WM_USER + 1, windows::Win32::Foundation::WPARAM(0), windows::Win32::Foundation::LPARAM(0));
                                if let Err(e) = success {
                                    log::error!("Failed to post inactive message to main thread: {}", e);
                                }
                            }
                        }
                    }
                }
            }
        });

        tokio::spawn(async move {
            while let Ok(event) = menu_channel.recv() {
                if event.id == quit_id {
                    log::info!("Quit menu selected");
                    std::process::exit(0);
                }
            }
        });

        Ok(Self {
            _tray_icon: tray_icon,
            _is_active: is_active,
            _menu: Some(menu_clone),
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
                let mut msg = MSG::default();
                log::debug!("Starting Win32 message loop");
                let mut hwnd_console = GetConsoleWindow();
                let mut last_hicon: Option<HICON> = None;

                while GetMessageW(&mut msg, None, 0, 0).as_bool() {
                    if msg.message == WM_USER + 1 {
                        let active = msg.wParam.0 != 0;
                        log::debug!("Received UI update message: active={}", active);

                        // Lazy re-check for console window if not found initially
                        if hwnd_console.0.is_null() {
                            hwnd_console = GetConsoleWindow();
                        }

                        if let Ok(icon_bytes) = Self::create_simple_icon(active) {
                            // Update Tray Icon
                            if let Ok(icon) = tray_icon::Icon::from_rgba(icon_bytes.clone(), 32, 32) {
                                if let Err(e) = self._tray_icon.set_icon(Some(icon)) {
                                    log::error!("Failed to set tray icon: {}", e);
                                }
                            }

                            // Update Taskbar Icon (if console exists)
                            if !hwnd_console.0.is_null() {
                                if let Ok(hicon) = Self::create_hicon_from_rgba(&icon_bytes, 32, 32) {
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
                                    
                                    // Cleanup previous icon to prevent leaks
                                    if let Some(old_hicon) = last_hicon {
                                        let _ = DestroyIcon(old_hicon);
                                    }
                                    last_hicon = Some(hicon);
                                }
                            }
                        }
                        continue;
                    }
                    let _ = TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
                
                // Final cleanup
                if let Some(old_hicon) = last_hicon {
                    let _ = DestroyIcon(old_hicon);
                }
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
}
