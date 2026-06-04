use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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
    pub bytes_sent: Arc<AtomicU64>,
    pub bytes_received: Arc<AtomicU64>,
    pub exe_name: String,
    closed_at: Option<Instant>,
}

struct TrackerState {
    connections: HashMap<u64, ConnectionInfo>,
    order: VecDeque<u64>,
}

pub struct ConnectionTracker {
    state: Mutex<TrackerState>,
    next_id: AtomicU64,
}

impl ConnectionTracker {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(TrackerState {
                connections: HashMap::new(),
                order: VecDeque::new(),
            }),
            next_id: AtomicU64::new(1),
        })
    }

    pub fn register(
        &self,
        source_ip: String,
        outbound_target: String,
        proxy_protocol: String,
    ) -> (u64, Arc<AtomicU64>, Arc<AtomicU64>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let bytes_sent = Arc::new(AtomicU64::new(0));
        let bytes_received = Arc::new(AtomicU64::new(0));
        let info = ConnectionInfo {
            id,
            source_ip,
            outbound_target,
            proxy_protocol,
            proxy: String::from("connecting..."),
            start_time: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            status: String::from("connecting"),
            bytes_sent: bytes_sent.clone(),
            bytes_received: bytes_received.clone(),
            exe_name: String::new(),
            closed_at: None,
        };
        let mut state = self.state.lock();
        state.connections.insert(id, info);
        state.order.push_back(id);
        while state.order.len() > MAX_CONNECTIONS {
            if let Some(oldest_id) = state.order.pop_front()
                && let Some(evicted) = state.connections.remove(&oldest_id)
            {
                log::warn!(
                    "Connection tracker full ({}), evicted oldest connection id={} addr={}",
                    MAX_CONNECTIONS,
                    evicted.id,
                    evicted.source_ip,
                );
            }
        }
        (id, bytes_sent, bytes_received)
    }

    pub fn set_exe_name(&self, id: u64, exe_name: String) {
        let mut state = self.state.lock();
        if let Some(conn) = state.connections.get_mut(&id) {
            conn.exe_name = exe_name;
        }
    }

    pub fn set_proxy(&self, id: u64, proxy: String) {
        let mut state = self.state.lock();
        if let Some(conn) = state.connections.get_mut(&id) {
            conn.proxy = proxy;
        }
    }

    pub fn set_outbound_target(&self, id: u64, target: String) {
        let mut state = self.state.lock();
        if let Some(conn) = state.connections.get_mut(&id) {
            conn.outbound_target = target;
        }
    }

    pub fn set_proxy_protocol(&self, id: u64, protocol: String) {
        let mut state = self.state.lock();
        if let Some(conn) = state.connections.get_mut(&id) {
            conn.proxy_protocol = protocol;
        }
    }

    pub fn set_connected(&self, id: u64) {
        let mut state = self.state.lock();
        if let Some(conn) = state.connections.get_mut(&id) {
            conn.status = String::from("connected");
        }
    }

    pub fn set_closed(&self, id: u64) {
        let mut state = self.state.lock();
        if let Some(conn) = state.connections.get_mut(&id) {
            conn.status = String::from("closed");
            conn.closed_at = Some(Instant::now());
        }
    }

    pub fn set_error(&self, id: u64, err: &str) {
        let mut state = self.state.lock();
        if let Some(conn) = state.connections.get_mut(&id) {
            conn.status = format!("error: {}", err);
            conn.closed_at = Some(Instant::now());
        }
    }

    pub fn snapshot(&self) -> Vec<ConnectionInfo> {
        let mut guard = self.state.lock();
        let state = &mut *guard;
        state
            .connections
            .retain(|_, c| c.closed_at.is_none_or(|t| t.elapsed() < CLOSED_RETENTION));
        let active_connections = &state.connections;
        state.order.retain(|id| active_connections.contains_key(id));

        let mut list = Vec::with_capacity(state.connections.len());
        for id in &state.order {
            if let Some(conn) = state.connections.get(id) {
                list.push(conn.clone());
            }
        }
        list
    }
}

// PartialEq for display-relevant fields (includes id, bytes loaded via load).
impl PartialEq for ConnectionInfo {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.source_ip == other.source_ip
            && self.outbound_target == other.outbound_target
            && self.proxy_protocol == other.proxy_protocol
            && self.proxy == other.proxy
            && self.start_time == other.start_time
            && self.status == other.status
            && self.bytes_sent.load(Ordering::Relaxed) == other.bytes_sent.load(Ordering::Relaxed)
            && self.bytes_received.load(Ordering::Relaxed)
                == other.bytes_received.load(Ordering::Relaxed)
            && self.exe_name == other.exe_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracker_lifecycle() {
        let tracker = ConnectionTracker::new();

        // 1. Register a connection
        let (id, sent_ctr, recv_ctr) = tracker.register(
            "127.0.0.1:12345".to_string(),
            "google.com:443".to_string(),
            "HTTPS".to_string(),
        );
        assert_eq!(id, 1);

        // 2. Initial state
        {
            let snap = tracker.snapshot();
            assert_eq!(snap.len(), 1);
            assert_eq!(snap[0].id, 1);
            assert_eq!(snap[0].source_ip, "127.0.0.1:12345");
            assert_eq!(snap[0].status, "connecting");
            assert_eq!(snap[0].bytes_sent.load(Ordering::Relaxed), 0);
            assert_eq!(snap[0].bytes_received.load(Ordering::Relaxed), 0);
        }

        // 3. Update properties and counters
        tracker.set_connected(id);
        tracker.set_exe_name(id, "chrome.exe".to_string());
        sent_ctr.fetch_add(1024, Ordering::Relaxed);
        recv_ctr.fetch_add(2048, Ordering::Relaxed);

        {
            let snap = tracker.snapshot();
            assert_eq!(snap.len(), 1);
            assert_eq!(snap[0].status, "connected");
            assert_eq!(snap[0].exe_name, "chrome.exe");
            assert_eq!(snap[0].bytes_sent.load(Ordering::Relaxed), 1024);
            assert_eq!(snap[0].bytes_received.load(Ordering::Relaxed), 2048);
        }

        // 4. Close connection
        tracker.set_closed(id);
        {
            let snap = tracker.snapshot();
            assert_eq!(snap.len(), 1);
            assert_eq!(snap[0].status, "closed");
        }
    }
}
