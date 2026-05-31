use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use libui::controls::{
    Table, TableDataSource, TableModel, TableParameters, TableValue, TableValueType, Window,
    WindowType,
};
use libui::UI;

use crate::connection_tracker::ConnectionTracker;

#[cfg(windows)]
unsafe extern "system" {
    fn LockWindowUpdate(hWndLock: *mut std::ffi::c_void);
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

struct TrafficDataSource {
    connections: Vec<crate::connection_tracker::ConnectionInfo>,
}

impl TableDataSource for TrafficDataSource {
    fn num_columns(&mut self) -> i32 {
        8
    }

    fn num_rows(&mut self) -> i32 {
        self.connections.len() as i32
    }

    fn column_type(&mut self, _column: i32) -> TableValueType {
        TableValueType::String
    }

    fn cell(&mut self, column: i32, row: i32) -> TableValue {
        let conn = &self.connections[row as usize];
        match column {
            0 => TableValue::String(conn.source_ip.clone()),
            1 => TableValue::String(conn.outbound_target.clone()),
            2 => TableValue::String(conn.proxy_protocol.clone()),
            3 => TableValue::String(conn.proxy.clone()),
            4 => TableValue::String(conn.start_time.clone()),
            5 => TableValue::String(conn.status.clone()),
            6 => TableValue::String(format_bytes(conn.bytes_sent)),
            7 => TableValue::String(format_bytes(conn.bytes_received)),
            _ => TableValue::String(String::new()),
        }
    }

    fn set_cell(&mut self, _column: i32, _row: i32, _value: TableValue) {}
}

pub fn open_traffic_window(tracker: Arc<ConnectionTracker>) {
    std::thread::spawn(move || {
        if let Err(e) = run_traffic_window(tracker) {
            log::error!("Traffic window error: {}", e);
        }
    });
}

fn run_traffic_window(tracker: Arc<ConnectionTracker>) -> Result<(), libui::UIError> {
    let ui = UI::init()?;

    let initial_snapshot = tracker.snapshot();
    let data_source = Rc::new(RefCell::new(TrafficDataSource {
        connections: initial_snapshot,
    }));
    let model = Rc::new(RefCell::new(TableModel::new(data_source.clone())));
    let params = TableParameters::new(model.clone());
    let mut table = Table::new(params);
    table.set_header_visible(true);

    let columns = [
        "Source",
        "Outbound Target",
        "Proxy Protocol",
        "Proxy",
        "Start Time",
        "Status",
        "Bytes Sent",
        "Bytes Received",
    ];
    for (i, title) in columns.iter().enumerate() {
        table.append_text_column(title, i as i32, Table::COLUMN_READONLY);
    }

    #[cfg(windows)]
    let table_hwnd = {
        use libui::controls::Control;
        let control: Control = table.clone().into();
        get_control_hwnd(&control).0
    };

    let mut window = Window::new(&ui, "Real-time Traffic", 1100, 500, WindowType::NoMenubar);
    window.set_margined(true);
    window.set_child(table);

    let ds = data_source.clone();
    let mdl = model.clone();
    let trk = tracker.clone();

    #[cfg(windows)]
    let mut prev_width: i32 = 0;
    #[cfg(windows)]
    let mut prev_height: i32 = 0;

    let mut event_loop = ui.event_loop();
    event_loop.on_tick(move || {
        #[cfg(windows)]
        {
            use windows::Win32::Foundation::HWND;
            use windows::Win32::UI::WindowsAndMessaging::GetWindowRect;
            let mut rect = windows::Win32::Foundation::RECT::default();
            if unsafe { GetWindowRect(HWND(table_hwnd), &mut rect) }.is_ok() {
                let w = rect.right - rect.left;
                let h = rect.bottom - rect.top;
                let is_first = prev_width == 0;
                let resizing = !is_first && (w != prev_width || h != prev_height);
                prev_width = w;
                prev_height = h;

                if resizing {
                    // Silently swap data during window resize — don't lock
                    // or notify, let the resize animation paint freely.
                    let snapshot = trk.snapshot();
                    ds.borrow_mut().connections = snapshot;
                    return;
                }
            }

            unsafe { LockWindowUpdate(table_hwnd); }
        }

        let snapshot = trk.snapshot();
        let mut ds_mut = ds.borrow_mut();
        let old_connections = std::mem::take(&mut ds_mut.connections);
        let old_len = old_connections.len();
        ds_mut.connections = snapshot;
        let new_len = ds_mut.connections.len();

        let model = mdl.borrow();

        let min_len = old_len.min(new_len);
        for i in 0..min_len {
            if old_connections[i] != ds_mut.connections[i] {
                model.notify_row_changed(i as i32);
            }
        }
        if new_len > old_len {
            for i in old_len..new_len {
                model.notify_row_inserted(i as i32);
            }
        } else if old_len > new_len {
            for i in (new_len..old_len).rev() {
                model.notify_row_deleted(i as i32);
            }
        }

        #[cfg(windows)]
        unsafe { LockWindowUpdate(std::ptr::null_mut()); }
    });

    #[cfg(windows)]
    set_window_icon(&window);

    window.show();
    event_loop.run_delay(1000);

    Ok(())
}

#[cfg(windows)]
fn get_control_hwnd(control: &libui::controls::Control) -> windows::Win32::Foundation::HWND {
    use std::ffi::c_void;
    use windows::Win32::Foundation::HWND;

    let hwnd_raw = unsafe { libui_ffi::uiControlHandle(control.as_ui_control()) };
    HWND(hwnd_raw as *mut c_void)
}

#[cfg(windows)]
fn set_window_icon(window: &Window) {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LPARAM, WPARAM};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::WindowsAndMessaging::{
        LoadIconW, SendMessageW, ICON_BIG, ICON_SMALL, WM_SETICON,
    };

    let hinstance = match unsafe { GetModuleHandleW(None) } {
        Ok(h) => h,
        Err(_) => return,
    };

    // Resource ID 1 is the main icon embedded by winres
    let hicon = match unsafe { LoadIconW(hinstance, PCWSTR(1_usize as *const u16)) } {
        Ok(h) => h,
        Err(_) => return,
    };
    if hicon.is_invalid() {
        return;
    }

    let hwnd = get_control_hwnd(&window.clone().into());

    unsafe {
        SendMessageW(hwnd, WM_SETICON, WPARAM(ICON_SMALL as usize), LPARAM(hicon.0 as isize));
        SendMessageW(hwnd, WM_SETICON, WPARAM(ICON_BIG as usize), LPARAM(hicon.0 as isize));
    }
}
