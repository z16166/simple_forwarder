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
            .with_icon(tray_icon::Icon::from_rgba(icon_bytes, 16, 16)?)
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

            loop {
                tokio::select! {
                    _ = rx.recv() => {
                        last_activity = std::time::Instant::now();
                        if !currently_active {
                            currently_active = true;
                            is_active_clone.store(true, Ordering::Relaxed);
                            #[cfg(windows)]
                            unsafe {
                                use windows::Win32::UI::WindowsAndMessaging::{PostThreadMessageW, WM_USER};
                                let _ = PostThreadMessageW(main_thread_id, WM_USER + 1, windows::Win32::Foundation::WPARAM(1), windows::Win32::Foundation::LPARAM(0));
                            }
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {
                        if currently_active && last_activity.elapsed() > Duration::from_secs(1) {
                            currently_active = false;
                            is_active_clone.store(false, Ordering::Relaxed);
                            #[cfg(windows)]
                            unsafe {
                                use windows::Win32::UI::WindowsAndMessaging::{PostThreadMessageW, WM_USER};
                                let _ = PostThreadMessageW(main_thread_id, WM_USER + 1, windows::Win32::Foundation::WPARAM(0), windows::Win32::Foundation::LPARAM(0));
                            }
                        }
                    }
                }
            }
        });

        tokio::spawn(async move {
            while let Ok(event) = menu_channel.recv() {
                if event.id == quit_id {
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
            };
            unsafe {
                let mut msg = MSG::default();
                while GetMessageW(&mut msg, None, 0, 0).as_bool() {
                    if msg.message == WM_USER + 1 {
                        let active = msg.wParam.0 != 0;
                        if let Ok(icon_bytes) = Self::create_simple_icon(active) {
                            if let Ok(icon) = tray_icon::Icon::from_rgba(icon_bytes, 16, 16) {
                                let _ = self._tray_icon.set_icon(Some(icon));
                            }
                        }
                        continue;
                    }
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
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

    fn create_simple_icon(active: bool) -> Result<Vec<u8>> {
        let mut rgba = vec![0u8; 16 * 16 * 4];
        let color = if active {
            (0, 255, 0)
        } else {
            (100, 100, 100)
        };

        for y in 0..16 {
            for x in 0..16 {
                let idx = (y * 16 + x) * 4;
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
