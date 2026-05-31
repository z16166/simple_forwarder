use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use libui::UI;
use libui::controls::{
    Table, TableDataSource, TableModel, TableParameters, TableValue, TableValueType, Window,
    WindowType,
};

use crate::connection_tracker::ConnectionTracker;
use crate::stats::TrafficStats;

#[cfg(windows)]
unsafe extern "system" {
    fn LockWindowUpdate(hWndLock: *mut std::ffi::c_void);
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
        let Some(conn) = self.connections.get(row as usize) else {
            return TableValue::String(String::new());
        };
        match column {
            0 => TableValue::String(conn.source_ip.clone()),
            1 => TableValue::String(conn.outbound_target.clone()),
            2 => TableValue::String(conn.proxy_protocol.clone()),
            3 => TableValue::String(conn.proxy.clone()),
            4 => TableValue::String(conn.start_time.clone()),
            5 => TableValue::String(conn.status.clone()),
            6 => TableValue::String(TrafficStats::format_bytes(conn.bytes_sent)),
            7 => TableValue::String(TrafficStats::format_bytes(conn.bytes_received)),
            _ => TableValue::String(String::new()),
        }
    }

    fn set_cell(&mut self, _column: i32, _row: i32, _value: TableValue) {}
}

/// Open (or show) the real-time traffic window.
///
/// `want_visible` signals the UI thread whether the window should be shown.
/// `thread_running` tracks whether the UI thread has already been spawned
/// (`UI::init()` is single-use per process).
pub fn open_traffic_window(
    tracker: Arc<ConnectionTracker>,
    want_visible: Arc<AtomicBool>,
    thread_running: Arc<AtomicBool>,
) {
    // Tell the existing window to show itself (if already running)
    want_visible.store(true, Ordering::SeqCst);

    if thread_running.swap(true, Ordering::SeqCst) {
        return; // UI thread already alive
    }

    std::thread::spawn(move || {
        if let Err(e) = run_traffic_window(tracker, want_visible) {
            log::error!("Traffic window error: {}", e);
        }
    });
}

fn run_traffic_window(
    tracker: Arc<ConnectionTracker>,
    want_visible: Arc<AtomicBool>,
) -> Result<(), libui::UIError> {
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
    table.set_column_width(0, 200); // Source
    table.set_column_width(1, 260); // Outbound Target
    table.set_column_width(3, 220); // Proxy
    table.set_column_width(4, 180); // Start Time

    #[cfg(windows)]
    let table_hwnd = {
        use libui::controls::Control;
        let control: Control = table.clone().into();
        get_control_hwnd(&control).0
    };

    let mut window = Window::new(&ui, "Real-time Traffic", 1100, 500, WindowType::NoMenubar);
    window.set_margined(true);
    window.set_child(table);

    #[cfg(windows)]
    set_window_icon(&window);

    #[cfg(windows)]
    center_window(&window, 1100, 500);

    // Wrap in Rc<RefCell<>> so both on_closing and on_tick can access the window.
    let window_rc = Rc::new(RefCell::new(window));
    let window_for_close = window_rc.clone();
    let window_for_tick = window_rc.clone();
    let visible_for_close = want_visible.clone();

    window_for_close.borrow_mut().on_closing(&ui, move |w| {
        visible_for_close.store(false, Ordering::SeqCst);
        w.hide();
    });

    let ds = data_source.clone();
    let mdl = model.clone();
    let trk = tracker.clone();

    #[cfg(windows)]
    let mut prev_width: i32 = 0;
    #[cfg(windows)]
    let mut prev_height: i32 = 0;

    let mut event_loop = ui.event_loop();
    event_loop.on_tick(move || {
        let mut w = window_for_tick.borrow_mut();

        if !want_visible.load(Ordering::SeqCst) {
            w.hide();
            return; // Window hidden — skip update
        }
        w.show();

        #[cfg(windows)]
        {
            use windows::Win32::Foundation::HWND;
            use windows::Win32::UI::WindowsAndMessaging::{GetClientRect, IsWindow};

            let hwnd = HWND(table_hwnd);
            if unsafe { IsWindow(hwnd) }.as_bool() {
                let mut rect = windows::Win32::Foundation::RECT::default();
                if unsafe { GetClientRect(hwnd, &mut rect) }.is_ok() {
                    let width = rect.right - rect.left;
                    let height = rect.bottom - rect.top;
                    let is_first = prev_width == 0;
                    let resizing = !is_first && (width != prev_width || height != prev_height);
                    prev_width = width;
                    prev_height = height;

                    if resizing {
                        let snapshot = trk.snapshot();
                        ds.borrow_mut().connections = snapshot;
                        return;
                    }
                }

                unsafe {
                    LockWindowUpdate(table_hwnd);
                }
            }
        }

        drop(w); // Release window borrow before model operations

        let snapshot = trk.snapshot();
        let mut ds_mut = ds.borrow_mut();
        let old_connections = std::mem::take(&mut ds_mut.connections);
        ds_mut.connections = snapshot;

        let model = mdl.borrow();

        // ID-based diff: match rows by connection id so that mid-vector
        // removals (pruning, eviction) don't cause index misalignment.
        //
        // Index-space model (3 steps, executed in order):
        //
        //   Step 1 — deletions use OLD snapshot indices. Notifying high-to-low
        //   ensures each deletion doesn't shift indices of the remaining
        //   not-yet-deleted rows.
        //
        //   After step 1, the model has the same set of rows (and same order)
        //   as the new data source. The surviving rows are at identical
        //   positions in both the post-deletion model and the data source.
        //
        //   Step 2 — changed rows use NEW data-source indices, which now
        //   match the model's post-deletion state.
        //
        //   Step 3 — insertions also use NEW data-source indices. Inserting
        //   low-to-high is correct because step 1 already removed all stale
        //   rows; the model's row count is exactly new_len - insert_count.
        let old_idx_by_id: HashMap<u64, usize> = old_connections
            .iter()
            .enumerate()
            .map(|(i, c)| (c.id, i))
            .collect();
        let new_ids: HashSet<u64> = ds_mut.connections.iter().map(|c| c.id).collect();

        // 1. Delete rows no longer in the new snapshot (old indices, high→low)
        let mut del_indices: Vec<usize> = (0..old_connections.len())
            .filter(|i| !new_ids.contains(&old_connections[*i].id))
            .collect();
        del_indices.sort_unstable_by(|a, b| b.cmp(a));
        for idx in &del_indices {
            model.notify_row_deleted(*idx as i32);
        }

        // 2. Notify changed rows (new indices — model now == data source)
        for (new_idx, conn) in ds_mut.connections.iter().enumerate() {
            if let Some(&old_idx) = old_idx_by_id.get(&conn.id) {
                if old_connections[old_idx] != *conn {
                    model.notify_row_changed(new_idx as i32);
                }
            }
        }

        // 3. Insert genuinely new rows (new indices, low→high)
        for (new_idx, conn) in ds_mut.connections.iter().enumerate() {
            if !old_idx_by_id.contains_key(&conn.id) {
                model.notify_row_inserted(new_idx as i32);
            }
        }

        #[cfg(windows)]
        unsafe {
            LockWindowUpdate(std::ptr::null_mut());
        }
    });

    window_rc.borrow_mut().show();
    event_loop.run_delay(1000);

    // run_delay only returns if all windows are destroyed (which we prevent
    // via on_closing). If it ever does, reset the thread_running flag so a
    // fresh thread can be spawned.
    #[cfg(windows)]
    unsafe {
        LockWindowUpdate(std::ptr::null_mut());
    }

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
    use windows::Win32::Foundation::{LPARAM, WPARAM};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::WindowsAndMessaging::{
        ICON_BIG, ICON_SMALL, LoadIconW, SendMessageW, WM_SETICON,
    };
    use windows::core::PCWSTR;

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
        SendMessageW(
            hwnd,
            WM_SETICON,
            WPARAM(ICON_SMALL as usize),
            LPARAM(hicon.0 as isize),
        );
        SendMessageW(
            hwnd,
            WM_SETICON,
            WPARAM(ICON_BIG as usize),
            LPARAM(hicon.0 as isize),
        );
    }
}

#[cfg(windows)]
fn center_window(window: &Window, width: i32, height: i32) {
    use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SetWindowPos, SM_CXSCREEN, SM_CYSCREEN, SWP_NOSIZE};

    let hwnd = get_control_hwnd(&window.clone().into());
    let screen_w = unsafe { GetSystemMetrics(SM_CXSCREEN) };
    let screen_h = unsafe { GetSystemMetrics(SM_CYSCREEN) };
    let x = (screen_w - width) / 2;
    let y = (screen_h - height) / 2;
    unsafe {
        let _ = SetWindowPos(hwnd, None, x, y, 0, 0, SWP_NOSIZE);
    }
}
