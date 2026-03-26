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
}

impl TrayManager {
    pub fn new(rx: mpsc::Receiver<()>) -> Result<Self> {
        let is_active = Arc::new(AtomicBool::new(false));

        let quit_item = MenuItem::new("退出", true, None);
        let quit_id = quit_item.id().clone();
        let menu = Menu::new();
        menu.append(&quit_item)?;

        let icon_bytes = Self::create_simple_icon(false)?;

        let tray_icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("Simple Forwarder")
            .with_icon(tray_icon::Icon::from_rgba(icon_bytes, 16, 16)?)
            .build()?;

        let menu_channel = MenuEvent::receiver();

        let is_active_clone = is_active.clone();
        tokio::spawn(async move {
            let mut last_activity = std::time::Instant::now();
            let mut rx = rx;

            loop {
                tokio::select! {
                    _ = rx.recv() => {
                        is_active_clone.store(true, Ordering::Relaxed);
                        last_activity = std::time::Instant::now();
                    }
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {
                        if last_activity.elapsed() > Duration::from_secs(2) {
                            is_active_clone.store(false, Ordering::Relaxed);
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
        })
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
