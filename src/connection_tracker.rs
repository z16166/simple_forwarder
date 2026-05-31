use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_CONNECTIONS: usize = 5000;
const CLOSED_RETENTION: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
pub struct ConnectionInfo {
    pub id: u64,
    pub source_ip: String,
    pub outbound_target: String,
    pub proxy_protocol: String,
    pub proxy: String,
    pub start_time: String,
    pub status: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    closed_at: Option<Instant>,
}

pub struct ConnectionTracker {
    connections: Mutex<Vec<ConnectionInfo>>,
    next_id: AtomicU64,
}

impl ConnectionTracker {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            connections: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(1),
        })
    }

    pub fn register(
        &self,
        source_ip: String,
        outbound_target: String,
        proxy_protocol: String,
    ) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let info = ConnectionInfo {
            id,
            source_ip,
            outbound_target,
            proxy_protocol,
            proxy: String::from("connecting..."),
            start_time: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            status: String::from("connecting"),
            bytes_sent: 0,
            bytes_received: 0,
            closed_at: None,
        };
        let mut connections = self.connections.lock().unwrap();
        connections.push(info);
        if connections.len() > MAX_CONNECTIONS {
            connections.remove(0);
        }
        id
    }

    fn find(connections: &mut [ConnectionInfo], id: u64) -> Option<&mut ConnectionInfo> {
        connections.iter_mut().find(|c| c.id == id)
    }

    pub fn set_proxy(&self, id: u64, proxy: String) {
        let mut connections = self.connections.lock().unwrap();
        if let Some(conn) = Self::find(&mut connections, id) {
            conn.proxy = proxy;
        }
    }

    pub fn set_connected(&self, id: u64) {
        let mut connections = self.connections.lock().unwrap();
        if let Some(conn) = Self::find(&mut connections, id) {
            conn.status = String::from("connected");
        }
    }

    pub fn set_closed(&self, id: u64) {
        let mut connections = self.connections.lock().unwrap();
        if let Some(conn) = Self::find(&mut connections, id) {
            conn.status = String::from("closed");
            conn.closed_at = Some(Instant::now());
        }
    }

    pub fn set_error(&self, id: u64, err: &str) {
        let mut connections = self.connections.lock().unwrap();
        if let Some(conn) = Self::find(&mut connections, id) {
            conn.status = format!("error: {}", err);
            conn.closed_at = Some(Instant::now());
        }
    }

    pub fn add_bytes_sent(&self, id: u64, n: u64) {
        let mut connections = self.connections.lock().unwrap();
        if let Some(conn) = Self::find(&mut connections, id) {
            conn.bytes_sent += n;
        }
    }

    pub fn add_bytes_received(&self, id: u64, n: u64) {
        let mut connections = self.connections.lock().unwrap();
        if let Some(conn) = Self::find(&mut connections, id) {
            conn.bytes_received += n;
        }
    }

    pub fn snapshot(&self) -> Vec<ConnectionInfo> {
        let mut connections = self.connections.lock().unwrap();
        connections.retain(|c| c.closed_at.map_or(true, |t| t.elapsed() < CLOSED_RETENTION));
        connections.clone()
    }
}

// PartialEq for display-relevant fields only (skips id and closed_at).
impl PartialEq for ConnectionInfo {
    fn eq(&self, other: &Self) -> bool {
        self.source_ip == other.source_ip
            && self.outbound_target == other.outbound_target
            && self.proxy_protocol == other.proxy_protocol
            && self.proxy == other.proxy
            && self.start_time == other.start_time
            && self.status == other.status
            && self.bytes_sent == other.bytes_sent
            && self.bytes_received == other.bytes_received
    }
}
