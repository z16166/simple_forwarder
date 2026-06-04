use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64},
};

pub struct TrafficStats {
    pub listen_addr: String,
    pub upstream_rx: AtomicU64,
    pub upstream_tx: AtomicU64,
    pub direct_rx: AtomicU64,
    pub direct_tx: AtomicU64,
    pub start_time: std::time::Instant,
    pub traffic_active: AtomicBool,
}

impl TrafficStats {
    pub fn new(listen_addr: String) -> Arc<Self> {
        Arc::new(Self {
            listen_addr,
            upstream_rx: AtomicU64::new(0),
            upstream_tx: AtomicU64::new(0),
            direct_rx: AtomicU64::new(0),
            direct_tx: AtomicU64::new(0),
            start_time: std::time::Instant::now(),
            traffic_active: AtomicBool::new(false),
        })
    }

    pub fn format_bytes(bytes: u64) -> String {
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;
        const GB: u64 = MB * 1024;
        const TB: u64 = GB * 1024;

        if bytes >= TB {
            format!("{:.2} TB", bytes as f64 / TB as f64)
        } else if bytes >= GB {
            format!("{:.2} GB", bytes as f64 / GB as f64)
        } else if bytes >= MB {
            format!("{:.2} MB", bytes as f64 / MB as f64)
        } else if bytes >= KB {
            format!("{:.2} KB", bytes as f64 / KB as f64)
        } else {
            format!("{} B", bytes)
        }
    }
}
