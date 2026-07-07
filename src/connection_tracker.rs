use parking_lot::RwLock;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const MAX_CONNECTIONS: usize = 5000;
const CLOSED_RETENTION: Duration = Duration::from_secs(5);

// ── Connection status enum (Issue 14) ──────────────────────────────────

/// Discrete connection status, replacing raw string literals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnStatus {
    Connecting,
    Connected,
    Closed,
    Error(String),
}

impl fmt::Display for ConnStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnStatus::Connecting => f.write_str("connecting"),
            ConnStatus::Connected => f.write_str("connected"),
            ConnStatus::Closed => f.write_str("closed"),
            ConnStatus::Error(msg) => write!(f, "error: {}", msg),
        }
    }
}

// ── Protocol enum (Issue 14) ───────────────────────────────────────────

/// Proxy protocol type, replacing raw string literals.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)] // Direct variant reserved for future use
pub enum Protocol {
    Socks4,
    Socks4a,
    Socks5,
    Socks5h,
    Http,
    Direct,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Socks4 => f.write_str("SOCKS4"),
            Protocol::Socks4a => f.write_str("SOCKS4a"),
            Protocol::Socks5 => f.write_str("SOCKS5"),
            Protocol::Socks5h => f.write_str("SOCKS5h"),
            Protocol::Http => f.write_str("HTTP"),
            Protocol::Direct => f.write_str("Direct"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ConnectionInfo {
    pub id: u64,
    pub source_ip: Arc<str>,
    pub outbound_target: Arc<str>,
    pub proxy_protocol: Arc<str>,
    pub proxy: Arc<str>,
    pub start_time: Arc<str>,
    pub status: ConnStatus,
    pub bytes_sent: Arc<AtomicU64>,
    pub bytes_received: Arc<AtomicU64>,
    pub exe_name: Arc<str>,
    closed_at: Option<Instant>,
}

struct TrackerState {
    connections: HashMap<u64, Arc<ConnectionInfo>>,
    order: VecDeque<u64>,
}

pub struct ConnectionTracker {
    state: RwLock<TrackerState>,
    next_id: AtomicU64,
    /// Counter for periodic cleanup in snapshot() (Issue 16).
    snapshot_count: AtomicU64,
}

impl ConnectionTracker {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: RwLock::new(TrackerState {
                connections: HashMap::new(),
                order: VecDeque::new(),
            }),
            next_id: AtomicU64::new(1),
            snapshot_count: AtomicU64::new(0),
        })
    }

    /// Copy-on-write update of a single connection. Clones the inner value,
    /// applies `f`, then swaps in a fresh `Arc`. Readers holding the old
    /// `Arc` keep seeing a consistent snapshot. The atomic counters
    /// (`bytes_sent`/`bytes_received`) are shared via their own `Arc`s and
    /// therefore keep updating live regardless of which `Arc<ConnectionInfo>`
    /// a reader holds.
    fn modify<F: FnOnce(&mut ConnectionInfo)>(&self, id: u64, f: F) {
        let mut state = self.state.write();
        if let Some(arc_conn) = state.connections.get_mut(&id) {
            let mut new_conn = (**arc_conn).clone();
            f(&mut new_conn);
            *arc_conn = Arc::new(new_conn);
        }
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
            source_ip: Arc::from(source_ip),
            outbound_target: Arc::from(outbound_target),
            proxy_protocol: Arc::from(proxy_protocol),
            proxy: Arc::from("connecting..."),
            start_time: Arc::from(chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()),
            status: ConnStatus::Connecting,
            bytes_sent: bytes_sent.clone(),
            bytes_received: bytes_received.clone(),
            exe_name: Arc::from(""),
            closed_at: None,
        };
        let mut state = self.state.write();
        state.connections.insert(id, Arc::new(info));
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
        self.modify(id, |c| c.exe_name = Arc::from(exe_name));
    }

    pub fn set_proxy(&self, id: u64, proxy: String) {
        self.modify(id, |c| c.proxy = Arc::from(proxy));
    }

    pub fn set_outbound_target(&self, id: u64, target: String) {
        self.modify(id, |c| c.outbound_target = Arc::from(target));
    }

    pub fn set_proxy_protocol(&self, id: u64, protocol: String) {
        self.modify(id, |c| c.proxy_protocol = Arc::from(protocol));
    }

    pub fn set_connected(&self, id: u64) {
        self.modify(id, |c| c.status = ConnStatus::Connected);
    }

    pub fn set_closed(&self, id: u64) {
        self.modify(id, |c| {
            c.status = ConnStatus::Closed;
            c.closed_at = Some(Instant::now());
        });
    }

    pub fn set_error(&self, id: u64, err: &str) {
        self.modify(id, |c| {
            c.status = ConnStatus::Error(err.to_string());
            c.closed_at = Some(Instant::now());
        });
    }

    pub fn snapshot(&self) -> Vec<Arc<ConnectionInfo>> {
        // snapshot() is called once per second by the traffic window.
        // Run cleanup every 5 snapshots to reduce overhead (Issue 16).
        // The cleanup tick needs a write lock; the other 4/5 take a cheap
        // read lock so concurrent readers (and writers via `modify`/`register`)
        // are not blocked (Issue 17).
        let count = self.snapshot_count.fetch_add(1, Ordering::Relaxed);
        if count.is_multiple_of(5) {
            let mut state = self.state.write();
            state
                .connections
                .retain(|_, c| c.closed_at.is_none_or(|t| t.elapsed() < CLOSED_RETENTION));
            // Collect surviving ids first to avoid borrowing `state` inside
            // the `retain` closure on `state.order`.
            let live: HashSet<u64> = state.connections.keys().copied().collect();
            state.order.retain(|id| live.contains(id));
            state
                .order
                .iter()
                .filter_map(|id| state.connections.get(id).cloned())
                .collect()
        } else {
            let state = self.state.read();
            state
                .order
                .iter()
                .filter_map(|id| state.connections.get(id).cloned())
                .collect()
        }
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

// Eq is safe to implement since all fields support equality.
impl Eq for ConnectionInfo {}

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
            assert_eq!(&*snap[0].source_ip, "127.0.0.1:12345");
            assert_eq!(snap[0].status, ConnStatus::Connecting);
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
            assert_eq!(snap[0].status, ConnStatus::Connected);
            assert_eq!(&*snap[0].exe_name, "chrome.exe");
            assert_eq!(snap[0].bytes_sent.load(Ordering::Relaxed), 1024);
            assert_eq!(snap[0].bytes_received.load(Ordering::Relaxed), 2048);
        }

        // 4. Close connection
        tracker.set_closed(id);
        {
            let snap = tracker.snapshot();
            assert_eq!(snap.len(), 1);
            assert_eq!(snap[0].status, ConnStatus::Closed);
        }
    }
}
