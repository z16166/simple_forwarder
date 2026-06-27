use anyhow::{Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::Ordering;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{Duration, timeout};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// Timeout for write operations. Prevents indefinite blocking when a peer
/// stops reading while the other side is still sending (TCP send buffer full).
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONNECTIONS: usize = 1024;

/// Initial capacity for HTTP header read buffer.
const HTTP_HEADER_INITIAL_BUF_SIZE: usize = 4096;
/// Maximum allowed length of HTTP headers (bytes).
const HTTP_HEADER_MAX_LEN: usize = 16384;
/// Buffer size for bidirectional relay copy.
const RELAY_BUF_SIZE: usize = 8192;
/// Maximum length of SOCKS4 handshake data (User ID + Domain).
const SOCKS4_HANDSHAKE_MAX_LEN: usize = 1024;
/// Linger timeout: how long to wait for the peer to finish after one side closes.
const LINGER_TIMEOUT_SECS: u64 = 15;
/// Default port for HTTPS (used when CONNECT URI has no port).
const HTTPS_DEFAULT_PORT: u16 = 443;
/// Default port for HTTP (used when regular HTTP URI has no port).
const HTTP_DEFAULT_PORT: u16 = 80;

use crate::connection_tracker::{ConnectionTracker, Protocol};
use crate::etw_resolver::ExeResolver;
use crate::matcher::RuleMatcher;
use crate::proxy_client::{CONNECT_TIMEOUT, ProxyClient, ProxyConfig};
use crate::stats::TrafficStats;
use arc_swap::ArcSwap;
use std::sync::Arc;

pub struct ProxyServer {
    listener: TcpListener,
    rules: Arc<ArcSwap<Vec<(RuleMatcher, ProxyConfig)>>>,
    semaphore: Arc<Semaphore>,
    stats: Arc<TrafficStats>,
    tracker: Arc<ConnectionTracker>,
    exe_resolver: ExeResolver,
}

impl ProxyServer {
    pub async fn new(
        listen_addr: SocketAddr,
        rules: Arc<ArcSwap<Vec<(RuleMatcher, ProxyConfig)>>>,
        stats: Arc<TrafficStats>,
        tracker: Arc<ConnectionTracker>,
        exe_resolver: ExeResolver,
    ) -> Result<Self> {
        let listener = TcpListener::bind(listen_addr)
            .await
            .with_context(|| format!("Failed to bind to {}", listen_addr))?;
        // TCP_NODELAY is set per-accepted connection in handle_connection below.
        log::info!("Proxy server listening on {}", listen_addr);
        Ok(Self {
            listener,
            rules,
            semaphore: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            stats,
            tracker,
            exe_resolver,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        loop {
            match self.listener.accept().await {
                Ok((stream, peer_addr)) => {
                    log::debug!("Accepted connection from {}", peer_addr);
                    // TCP_NODELAY: disable Nagle's algorithm for lower latency
                    // on interactive proxy traffic (HTTP, SSH, etc.) (Issue 18).
                    let _ = stream.set_nodelay(true);
                    self.stats.traffic_active.store(true, Ordering::Relaxed);

                    let rules = self.rules.clone();
                    let stats = self.stats.clone();
                    let tracker = self.tracker.clone();
                    let exe_resolver = self.exe_resolver.clone();
                    let permit = match self.semaphore.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            log::warn!(
                                "Max connections ({}) reached, rejecting {}",
                                MAX_CONNECTIONS,
                                peer_addr
                            );
                            drop(stream);
                            continue;
                        }
                    };

                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(e) = handle_connection(
                            stream,
                            peer_addr,
                            rules,
                            stats,
                            tracker,
                            exe_resolver,
                        )
                        .await
                        {
                            log::error!("Error handling connection from {}: {}", peer_addr, e);
                        }
                    });
                }
                Err(e) => {
                    log::error!("Error accepting connection: {}", e);
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct HandshakeResult {
    pub client_stream: TcpStream,
    pub target_stream: TcpStream,
    pub host: String,
    pub port: u16,
    pub proxy_desc: String,
    pub is_direct: bool,
    pub protocol: Protocol,
    pub leftover: Bytes,
}

async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    rules: Arc<ArcSwap<Vec<(RuleMatcher, ProxyConfig)>>>,
    stats: Arc<TrafficStats>,
    tracker: Arc<ConnectionTracker>,
    exe_resolver: ExeResolver,
) -> Result<()> {
    // Register at accept time so failed handshakes appear in the table.
    let (conn_id, bytes_sent_counter, bytes_received_counter) = tracker.register(
        peer_addr.to_string(),
        String::from("resolving..."),
        String::from("detecting..."),
    );

    // Resolve exe name in background — lookup uses spawn_blocking internally
    // to avoid starving the Tokio worker pool with blocking OS calls.
    let exe_for_lookup = exe_resolver.clone();
    let exe_tracker = tracker.clone();
    let conn_peer = peer_addr;
    tokio::spawn(async move {
        let sport = conn_peer.port();
        log::debug!("exe lookup: conn_id={}, sport={}", conn_id, sport);
        if let Some(exe) = exe_for_lookup.lookup(sport).await {
            log::debug!(
                "exe lookup: conn_id={}, sport={}, exe={}",
                conn_id,
                sport,
                exe
            );
            exe_tracker.set_exe_name(conn_id, exe);
            return;
        }
        // Quick retry: ETW event may arrive between the first lookup and now.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if let Some(exe) = exe_for_lookup.lookup(sport).await {
            log::debug!(
                "exe lookup (retry): conn_id={}, sport={}, exe={}",
                conn_id,
                sport,
                exe
            );
            exe_tracker.set_exe_name(conn_id, exe);
        } else {
            log::debug!(
                "exe lookup: conn_id={}, sport={}, not found",
                conn_id,
                sport
            );
        }
    });

    let rules_guard = rules.load();
    let res = timeout(HANDSHAKE_TIMEOUT, async {
        let mut first_byte = [0u8; 1];
        stream.read_exact(&mut first_byte).await?;

        let fb = first_byte[0];
        if fb == 0x05 {
            handle_socks5(fb, stream, peer_addr, &rules_guard).await
        } else if fb == 0x04 {
            handle_socks4(fb, stream, peer_addr, &rules_guard).await
        } else {
            handle_http(fb, stream, peer_addr, &rules_guard).await
        }
    })
    .await;

    match res {
        Ok(Ok(hr)) => {
            tracker.set_proxy_protocol(conn_id, hr.protocol.to_string());
            tracker.set_outbound_target(conn_id, format!("{}:{}", hr.host, hr.port));
            tracker.set_proxy(conn_id, hr.proxy_desc.clone());
            tracker.set_connected(conn_id);

            let result = relay_data(
                hr.client_stream,
                hr.target_stream,
                RelayContext {
                    host: hr.host,
                    port: hr.port,
                    peer_addr,
                    stats,
                    is_direct: hr.is_direct,
                    conn_id,
                    tracker,
                    leftover: hr.leftover,
                    bytes_sent: bytes_sent_counter,
                    bytes_received: bytes_received_counter,
                },
            )
            .await;
            exe_resolver.remove(peer_addr.port());
            result
        }
        Ok(Err(e)) => {
            tracker.set_error(conn_id, &e.to_string());
            exe_resolver.remove(peer_addr.port());
            Err(e)
        }
        Err(_) => {
            log::warn!("Handshake with {} timed out", peer_addr);
            tracker.set_error(conn_id, "Handshake timed out");
            exe_resolver.remove(peer_addr.port());
            Err(anyhow::anyhow!("Handshake timed out"))
        }
    }
}

async fn handle_socks4(
    _first_byte: u8,
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    rules: &[(RuleMatcher, ProxyConfig)],
) -> Result<HandshakeResult> {
    // SOCKS4 header: CMD (1), DSTPORT (2), DSTIP (4)
    let mut header = [0u8; 7];
    stream.read_exact(&mut header).await?;

    let cmd = header[0];
    if cmd != 0x01 {
        send_socks4_reply(&mut stream, 0x5B).await?;
        return Err(anyhow::anyhow!("Unsupported SOCKS4 command: {}", cmd));
    }

    let port = u16::from_be_bytes([header[1], header[2]]);
    let ip_bytes = [header[3], header[4], header[5], header[6]];
    // SOCKS4a detection: IP 0.0.0.x (x != 0) signals that the real destination
    // hostname follows the User ID as a null-terminated string. This is the
    // SOCKS4a protocol extension (RFC 1929 analogue for SOCKS4).
    let is_socks4a = ip_bytes[0] == 0 && ip_bytes[1] == 0 && ip_bytes[2] == 0 && ip_bytes[3] != 0;

    // Read User ID and Domain Name in chunks to avoid byte-by-byte read syscalls
    let mut buf = BytesMut::with_capacity(512);
    let mut temp = [0u8; 256];
    let mut user_id_end = None;
    let mut domain_end = None;

    loop {
        if user_id_end.is_none()
            && let Some(pos) = buf.iter().position(|&b| b == 0)
        {
            user_id_end = Some(pos);
        }
        if let Some(u_end) = user_id_end
            && is_socks4a
            && domain_end.is_none()
            && let Some(pos) = buf[u_end + 1..].iter().position(|&b| b == 0)
        {
            domain_end = Some(u_end + 1 + pos);
        }

        if user_id_end.is_some() && (!is_socks4a || domain_end.is_some()) {
            break;
        }

        if buf.len() > SOCKS4_HANDSHAKE_MAX_LEN {
            return Err(anyhow::anyhow!("SOCKS4 handshake data too long"));
        }

        let n = stream.read(&mut temp).await?;
        if n == 0 {
            return Err(anyhow::anyhow!("Connection closed during SOCKS4 handshake"));
        }
        buf.put_slice(&temp[..n]);
    }

    let Some(u_end) = user_id_end else {
        return Err(anyhow::anyhow!("SOCKS4: missing User ID terminator"));
    };
    // Issue 26: validate individual field lengths.
    if u_end > 255 {
        return Err(anyhow::anyhow!("SOCKS4: User ID too long ({} bytes)", u_end));
    }
    let _user_id = buf.split_to(u_end + 1).freeze();

    let host = if is_socks4a {
        let Some(d_end) = domain_end else {
            return Err(anyhow::anyhow!("SOCKS4a: missing domain name terminator"));
        };
        let domain_len = d_end - (u_end + 1);
        // DNS name limit is 253 characters (RFC 1035).
        if domain_len > 253 {
            return Err(anyhow::anyhow!("SOCKS4a: domain name too long ({} bytes)", domain_len));
        }
        let domain = buf.split_to(domain_len + 1).freeze();
        String::from_utf8_lossy(&domain[..domain_len]).to_string()
    } else {
        Ipv4Addr::from(ip_bytes).to_string()
    };

    let leftover = buf.freeze();

    let ip = if is_socks4a {
        None
    } else {
        Some(IpAddr::V4(Ipv4Addr::from(ip_bytes)))
    };

    log::debug!(
        "SOCKS4{} request from {}: {}:{}",
        if is_socks4a { "a" } else { "" },
        peer_addr,
        host,
        port
    );

    let (target_stream, proxy_desc, is_direct) =
        match connect_to_target(&host, port, is_socks4a, ip, rules, &mut stream, false).await {
            Ok(res) => res,
            Err(e) => {
                let _ = send_socks4_reply(&mut stream, 0x5B).await;
                return Err(e);
            }
        };

    send_socks4_reply(&mut stream, 0x5A).await?;

    let proto = if is_socks4a { Protocol::Socks4a } else { Protocol::Socks4 };
    Ok(HandshakeResult {
        client_stream: stream,
        target_stream,
        host,
        port,
        proxy_desc,
        is_direct,
        protocol: proto,
        leftover,
    })
}

async fn send_socks4_reply(stream: &mut TcpStream, status: u8) -> Result<()> {
    let mut reply = [0u8; 8];
    reply[1] = status;
    stream.write_all(&reply).await?;
    Ok(())
}

async fn handle_socks5(
    _first_byte: u8,
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    rules: &[(RuleMatcher, ProxyConfig)],
) -> Result<HandshakeResult> {
    let mut second_byte = [0u8; 1];
    stream.read_exact(&mut second_byte).await?;
    let nmethods = second_byte[0] as usize;

    if nmethods == 0 || nmethods > 255 {
        return Err(anyhow::anyhow!("SOCKS5 nmethods must be between 1 and 255"));
    }

    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    let selected_method = if methods.contains(&0x00) { 0x00 } else { 0xFF };

    let mut response = [0u8; 2];
    response[0] = 0x05;
    response[1] = selected_method;

    stream.write_all(&response).await?;

    if selected_method == 0xFF {
        return Err(anyhow::anyhow!("No acceptable authentication method"));
    }

    let mut request_header = [0u8; 4];
    stream.read_exact(&mut request_header).await?;

    if request_header[0] != 0x05 {
        return Err(anyhow::anyhow!("Invalid SOCKS5 version in request"));
    }

    let cmd = request_header[1];
    if cmd != 0x01 {
        send_error_reply(&mut stream, 0x07).await?;
        return Err(anyhow::anyhow!("Unsupported SOCKS5 command: {}", cmd));
    }

    let atyp = request_header[3];
    let (host, port, resolve_hostname, ip) = match atyp {
        0x01 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            let addr = Ipv4Addr::from(addr);
            let port = u16::from_be_bytes(port_buf);
            (addr.to_string(), port, false, Some(IpAddr::V4(addr)))
        }
        0x03 => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let len = len_buf[0] as usize;
            if len == 0 || len > 253 {
                send_error_reply(&mut stream, 0x08).await?;
                return Err(anyhow::anyhow!(
                    "SOCKS5 domain name length must be between 1 and 253"
                ));
            }
            let mut host_buf = vec![0u8; len];
            stream.read_exact(&mut host_buf).await?;
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            let host = String::from_utf8_lossy(&host_buf).to_string();
            let port = u16::from_be_bytes(port_buf);
            (host, port, true, None)
        }
        0x04 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            let addr = Ipv6Addr::from(addr);
            let port = u16::from_be_bytes(port_buf);
            (addr.to_string(), port, false, Some(IpAddr::V6(addr)))
        }
        _ => {
            send_error_reply(&mut stream, 0x08).await?;
            return Err(anyhow::anyhow!("Unsupported SOCKS5 address type: {}", atyp));
        }
    };

    log::debug!("SOCKS5 request from {}: {}:{}", peer_addr, host, port);

    let (target_stream, proxy_desc, is_direct) =
        connect_to_target(&host, port, resolve_hostname, ip, rules, &mut stream, true).await?;

    send_success_reply(&mut stream).await?;

    let proto = if resolve_hostname { Protocol::Socks5h } else { Protocol::Socks5 };
    Ok(HandshakeResult {
        client_stream: stream,
        target_stream,
        host,
        port,
        proxy_desc,
        is_direct,
        protocol: proto,
        leftover: Bytes::new(),
    })
}

async fn read_http_headers(stream: &mut TcpStream, first_byte: u8) -> Result<(Vec<u8>, Bytes)> {
    let mut buf = BytesMut::with_capacity(HTTP_HEADER_INITIAL_BUF_SIZE);
    buf.put_u8(first_byte);
    let mut temp = [0u8; 1024];
    let mut start_pos = 0;
    loop {
        if let Some(pos) = crate::util::find_header_separator(&buf, start_pos) {
            if pos > HTTP_HEADER_MAX_LEN {
                return Err(anyhow::anyhow!("HTTP headers too long"));
            }
            let headers = buf.split_to(pos).freeze();
            return Ok((headers.to_vec(), buf.freeze()));
        }
        if buf.len() > HTTP_HEADER_MAX_LEN {
            return Err(anyhow::anyhow!("HTTP headers too long"));
        }
        start_pos = buf.len();
        let n = stream.read(&mut temp).await?;
        if n == 0 {
            return Err(anyhow::anyhow!(
                "Connection closed while reading HTTP headers"
            ));
        }
        buf.put_slice(&temp[..n]);
    }
}

fn filter_hop_by_hop_headers(headers: &[u8]) -> Vec<u8> {
    // Hop-by-hop headers to strip (lowercase). Kept as byte slices for
    // direct ASCII case-insensitive comparison without String allocation (Issue 21).
    const HOP_BY_HOP: [&[u8]; 9] = [
        b"connection",
        b"keep-alive",
        b"proxy-authenticate",
        b"proxy-authorization",
        b"proxy-connection",
        b"te",
        b"trailers",
        b"transfer-encoding",
        b"upgrade",
    ];

    let mut filtered = Vec::with_capacity(headers.len());
    let mut pos = 0;
    while pos < headers.len() {
        // Find end of line (\r\n or \n).
        let line_end = headers[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|i| pos + i)
            .unwrap_or(headers.len());
        let line = &headers[pos..line_end];
        // Advance past the newline character(s).
        pos = line_end + 1;

        // Strip trailing \r — line_end points at \n, so \r\n lines still
        // carry the \r in the slice. Without this we'd emit \r\r\n.
        let line = line.strip_suffix(b"\r").unwrap_or(line);

        // Skip empty lines (end-of-headers marker is handled by caller).
        if line.is_empty() {
            continue;
        }

        // Check if this line starts with a hop-by-hop header name followed by ':'.
        let is_hop = HOP_BY_HOP.iter().any(|&name| {
            if line.len() > name.len() && line[name.len()] == b':' {
                line[..name.len()].eq_ignore_ascii_case(name)
            } else {
                false
            }
        });

        if !is_hop {
            filtered.extend_from_slice(line);
            filtered.extend_from_slice(b"\r\n");
        }
    }
    filtered.extend_from_slice(b"\r\n");
    filtered
}

async fn handle_http(
    first_byte: u8,
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    rules: &[(RuleMatcher, ProxyConfig)],
) -> Result<HandshakeResult> {
    let (header_bytes, leftover) = read_http_headers(&mut stream, first_byte).await?;

    let first_newline_pos = header_bytes
        .iter()
        .position(|&b| b == b'\n')
        .ok_or_else(|| anyhow::anyhow!("Invalid HTTP request headers"))?;
    let request_line = &header_bytes[..=first_newline_pos];
    let headers = &header_bytes[first_newline_pos + 1..];

    let request_line_str = String::from_utf8_lossy(request_line).trim().to_string();
    log::debug!("HTTP request line: {}", request_line_str);

    let parts: Vec<&str> = request_line_str.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(anyhow::anyhow!(
            "Invalid HTTP request line: {}",
            request_line_str
        ));
    }

    let method = parts[0];
    let uri = parts[1];

    let (host, port, is_connect) = if method.to_uppercase() == "CONNECT" {
        if uri.starts_with('[') {
            // IPv6: [::1]:443
            let end_bracket = uri
                .find(']')
                .ok_or_else(|| anyhow::anyhow!("Invalid IPv6 CONNECT URI: {}", uri))?;
            let host = uri[1..end_bracket].to_string();
            let port = if uri.len() > end_bracket + 2 && uri.as_bytes()[end_bracket + 1] == b':' {
                uri[end_bracket + 2..].parse().unwrap_or(HTTPS_DEFAULT_PORT)
            } else {
                HTTPS_DEFAULT_PORT
            };
            (host, port, true)
        } else {
            // IPv4 or domain: host:port
            let (host, port) = match uri.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), p.parse().unwrap_or(HTTPS_DEFAULT_PORT)),
                None => (uri.to_string(), HTTPS_DEFAULT_PORT),
            };
            (host, port, true)
        }
    } else {
        let uri_parsed = uri
            .parse::<http::Uri>()
            .map_err(|_| anyhow::anyhow!("Failed to parse URI: {}", uri))?;
        let host = uri_parsed
            .host()
            .ok_or_else(|| anyhow::anyhow!("Missing host in HTTP URI"))?
            .to_string();
        let port = uri_parsed.port_u16().unwrap_or(HTTP_DEFAULT_PORT);
        (host, port, false)
    };

    log::debug!(
        "HTTP {} request from {}: {}:{}",
        method,
        peer_addr,
        host,
        port
    );

    let (mut target_stream, proxy_desc, is_direct) =
        match connect_to_target(&host, port, true, None, rules, &mut stream, false).await {
            Ok(res) => res,
            Err(e) => {
                let _ = stream
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
                return Err(e);
            }
        };

    if is_connect {
        // CONNECT request: send the success response back to the client.
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
    } else {
        // Regular GET/POST request: rewrite the request line to origin-form and forward.
        let rewritten_line: Vec<u8> = if uri.starts_with("http://") || uri.starts_with("https://") {
            let origin = if let Ok(parsed) = uri.parse::<http::Uri>() {
                let path = parsed.path();
                let path = if path.is_empty() { "/" } else { path };
                match parsed.query() {
                    Some(q) => format!("{path}?{q}"),
                    None => path.to_string(),
                }
            } else {
                let after_scheme = &uri[uri.find("://").map(|i| i + 3).unwrap_or(0)..];
                let path_start = after_scheme.find('/').unwrap_or(after_scheme.len());
                let path = &after_scheme[path_start..];
                if path.is_empty() {
                    "/".to_string()
                } else {
                    path.to_string()
                }
            };
            let version = if parts.len() >= 3 {
                parts[2]
            } else {
                "HTTP/1.1"
            };
            format!("{method} {origin} {version}\r\n").into_bytes()
        } else {
            request_line.to_vec()
        };

        log::debug!(
            "Forwarding request line (origin-form): {}",
            String::from_utf8_lossy(&rewritten_line).trim()
        );
        target_stream.write_all(&rewritten_line).await?;

        // Filter hop-by-hop headers
        let filtered_headers = filter_hop_by_hop_headers(headers);
        target_stream.write_all(&filtered_headers).await?;
    }

    Ok(HandshakeResult {
        client_stream: stream,
        target_stream,
        host,
        port,
        proxy_desc,
        is_direct,
        protocol: Protocol::Http,
        leftover,
    })
}

async fn connect_to_target(
    host: &str,
    port: u16,
    resolve_hostname: bool,
    ip: Option<IpAddr>,
    rules: &[(RuleMatcher, ProxyConfig)],
    client_stream: &mut TcpStream,
    is_socks: bool,
) -> Result<(TcpStream, String, bool)> {
    for (matcher, proxy_config) in rules {
        if matcher.matches(host, ip) {
            log::debug!(
                "Matched rule, forwarding {} to proxy: {}",
                host,
                proxy_config.addr
            );
            let proxy_url = format!("{}://{}", proxy_config.proxy_type, proxy_config.addr);
            let client = ProxyClient::new(proxy_config.clone());
            match client.connect(host, port, resolve_hostname).await {
                Ok(s) => return Ok((s, proxy_url, false)),
                Err(e) => {
                    log::error!("Failed to connect to proxy {}: {}", proxy_config.addr, e);
                    if is_socks {
                        let _ = send_error_reply(client_stream, 0x01).await;
                    }
                    return Err(e);
                }
            }
        }
    }

    log::debug!("No rule matched, connecting directly to {}:{}", host, port);
    match timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => {
            let _ = s.set_nodelay(true);
            Ok((s, "direct".to_string(), true))
        }
        Ok(Err(e)) => {
            log::error!("Failed to connect directly to {}:{}: {}", host, port, e);
            if is_socks {
                let err_code = if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    0x05
                } else {
                    0x04
                };
                let _ = send_error_reply(client_stream, err_code).await;
            }
            Err(e.into())
        }
        Err(_) => {
            log::error!("Connection to {}:{} timed out", host, port);
            if is_socks {
                let _ = send_error_reply(client_stream, 0x06).await;
            }
            Err(anyhow::anyhow!("Connection timed out"))
        }
    }
}

/// Context for bidirectional data relay, grouping related parameters (Issue 20).
struct RelayContext {
    host: String,
    port: u16,
    peer_addr: SocketAddr,
    stats: Arc<TrafficStats>,
    is_direct: bool,
    conn_id: u64,
    tracker: Arc<ConnectionTracker>,
    leftover: Bytes,
    bytes_sent: Arc<std::sync::atomic::AtomicU64>,
    bytes_received: Arc<std::sync::atomic::AtomicU64>,
}

async fn relay_data(
    stream: TcpStream,
    target_stream: TcpStream,
    ctx: RelayContext,
) -> Result<()> {
    let (mut client_reader, mut client_writer) = stream.into_split();
    let (mut target_reader, mut target_writer) = target_stream.into_split();

    let client_to_target = async {
        if !ctx.leftover.is_empty() {
            timeout(WRITE_TIMEOUT, target_writer.write_all(&ctx.leftover))
                .await
                .map_err(|_| anyhow::anyhow!("Target leftover write timeout ({}s)", WRITE_TIMEOUT.as_secs()))??;
            if ctx.is_direct {
                ctx.stats
                    .direct_tx
                    .fetch_add(ctx.leftover.len() as u64, Ordering::Relaxed);
            } else {
                ctx.stats
                    .upstream_tx
                    .fetch_add(ctx.leftover.len() as u64, Ordering::Relaxed);
            }
            ctx.bytes_sent.fetch_add(ctx.leftover.len() as u64, Ordering::Relaxed);
            ctx.stats.traffic_active.store(true, Ordering::Relaxed);
        }
        let mut buf = [0u8; RELAY_BUF_SIZE];
        loop {
            match timeout(IDLE_TIMEOUT, client_reader.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    timeout(WRITE_TIMEOUT, target_writer.write_all(&buf[..n]))
                        .await
                        .map_err(|_| anyhow::anyhow!("Target write timeout ({}s)", WRITE_TIMEOUT.as_secs()))??;
                    if ctx.is_direct {
                        ctx.stats.direct_tx.fetch_add(n as u64, Ordering::Relaxed);
                    } else {
                        ctx.stats.upstream_tx.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    ctx.bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
                    ctx.stats.traffic_active.store(true, Ordering::Relaxed);
                }
                Ok(Err(e)) => return Err::<(), anyhow::Error>(e.into()),
                Err(_) => return Err(anyhow::anyhow!("Client connection idle timeout")),
            }
        }
        let _ = timeout(WRITE_TIMEOUT, target_writer.shutdown()).await;
        Ok(())
    };

    let target_to_client = async {
        let mut buf = [0u8; RELAY_BUF_SIZE];
        loop {
            match timeout(IDLE_TIMEOUT, target_reader.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    timeout(WRITE_TIMEOUT, client_writer.write_all(&buf[..n]))
                        .await
                        .map_err(|_| anyhow::anyhow!("Client write timeout ({}s)", WRITE_TIMEOUT.as_secs()))??;
                    if ctx.is_direct {
                        ctx.stats.direct_rx.fetch_add(n as u64, Ordering::Relaxed);
                    } else {
                        ctx.stats.upstream_rx.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    ctx.bytes_received.fetch_add(n as u64, Ordering::Relaxed);
                    ctx.stats.traffic_active.store(true, Ordering::Relaxed);
                }
                Ok(Err(e)) => return Err::<(), anyhow::Error>(e.into()),
                Err(_) => return Err(anyhow::anyhow!("Target connection idle timeout")),
            }
        }
        let _ = timeout(WRITE_TIMEOUT, client_writer.shutdown()).await;
        Ok(())
    };

    tokio::pin!(client_to_target);
    tokio::pin!(target_to_client);
    let mut client_done = false;
    let mut target_done = false;
    let mut linger_timeout = None;

    loop {
        tokio::select! {
            biased;

            r = &mut client_to_target, if !client_done => {
                client_done = true;
                match r {
                    Err(e) => {
                        ctx.tracker.set_error(ctx.conn_id, &e.to_string());
                        log::error!("Client→Target relay error: {}", e);
                        return Err(e);
                    }
                    Ok(()) => {
                        if !target_done {
                            // Linger: wait for the other side to finish draining
                            // before fully closing. Prevents truncation of partial
                            // responses when one half closes early.
                            linger_timeout = Some(Box::pin(tokio::time::sleep(Duration::from_secs(LINGER_TIMEOUT_SECS))));
                        }
                    }
                }
            }
            r = &mut target_to_client, if !target_done => {
                target_done = true;
                match r {
                    Err(e) => {
                        ctx.tracker.set_error(ctx.conn_id, &e.to_string());
                        log::error!("Target→Client relay error: {}", e);
                        return Err(e);
                    }
                    Ok(()) => {
                        if !client_done {
                            // Linger: wait for the other side to finish draining.
                            linger_timeout = Some(Box::pin(tokio::time::sleep(Duration::from_secs(LINGER_TIMEOUT_SECS))));
                        }
                    }
                }
            }
            _ = async {
                if let Some(sleep) = linger_timeout.as_mut() {
                    sleep.await;
                } else {
                    std::future::pending::<()>().await;
                }
            }, if linger_timeout.is_some() => {
                log::debug!("Linger timeout reached for connection {}, shutting down", ctx.conn_id);
                ctx.tracker.set_closed(ctx.conn_id);
                break;
            }
        }

        if client_done && target_done {
            ctx.tracker.set_closed(ctx.conn_id);
            break;
        }
    }

    log::debug!("Connection from {} to {}:{} closed", ctx.peer_addr, ctx.host, ctx.port);
    Ok(())
}

async fn send_error_reply(stream: &mut TcpStream, error_code: u8) -> Result<()> {
    let mut response = BytesMut::with_capacity(10);
    response.put_u8(0x05);
    response.put_u8(error_code);
    response.put_u8(0x00);
    response.put_u8(0x01);
    response.put_u32(0u32.to_be());
    response.put_u16(0u16.to_be());

    stream.write_all(&response).await?;
    Ok(())
}

async fn send_success_reply(stream: &mut TcpStream) -> Result<()> {
    let local_addr = stream.local_addr().ok();
    let mut response = BytesMut::with_capacity(22);
    response.put_u8(0x05); // VER
    response.put_u8(0x00); // REP (success)
    response.put_u8(0x00); // RSV
    match local_addr {
        Some(SocketAddr::V4(addr)) => {
            response.put_u8(0x01); // ATYP (IPv4)
            response.put_slice(&addr.ip().octets());
            response.put_u16(addr.port());
        }
        Some(SocketAddr::V6(addr)) => {
            response.put_u8(0x04); // ATYP (IPv6)
            response.put_slice(&addr.ip().octets());
            response.put_u16(addr.port());
        }
        None => {
            response.put_u8(0x01);
            response.put_u32(0);
            response.put_u16(0);
        }
    }
    stream.write_all(&response).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_hop_by_hop_headers() {
        // Normal \r\n headers — should preserve \r\n exactly (no double \r).
        let input = b"Host: example.com\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n";
        let out = filter_hop_by_hop_headers(input);
        assert_eq!(out, b"Host: example.com\r\nContent-Length: 0\r\n\r\n");

        // \n-only headers — should output \r\n (normalised).
        let input = b"Host: example.com\nConnection: keep-alive\nContent-Length: 0\n\n";
        let out = filter_hop_by_hop_headers(input);
        assert_eq!(out, b"Host: example.com\r\nContent-Length: 0\r\n\r\n");
    }

    #[tokio::test]
    async fn test_socks5_bounds_checking() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // 1. Test case: nmethods = 0
        let client_task = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            // Send VER=5, NMETHODS=0
            stream.write_all(&[0x05, 0x00]).await.unwrap();
        });
        let (mut server_stream, peer_addr) = listener.accept().await.unwrap();
        let mut first_byte = [0u8; 1];
        server_stream.read_exact(&mut first_byte).await.unwrap();
        let rules: Vec<(RuleMatcher, ProxyConfig)> = vec![];
        let res = handle_socks5(first_byte[0], server_stream, peer_addr, &rules).await;
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("SOCKS5 nmethods must be between 1 and 255")
        );
        client_task.await.unwrap();

        // 2. Test case: domain name length = 254 (invalid, > 253)
        let client_task = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            // Send VER=5, NMETHODS=1, METHOD=00
            stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            // Read server method select response
            let mut resp = [0u8; 2];
            stream.read_exact(&mut resp).await.unwrap();
            assert_eq!(resp, [0x05, 0x00]);
            // Send request: VER=5, CMD=1, RSV=0, ATYP=3 (domain), LEN=254 (no host/port payload, triggers early bounds check)
            let req = vec![0x05, 0x01, 0x00, 0x03, 254];
            stream.write_all(&req).await.unwrap();
            // Read error reply
            let mut reply = [0u8; 10];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[0], 0x05); // VER
            assert_eq!(reply[1], 0x08); // REP (0x08 = Address type not supported)
        });
        let (mut server_stream, peer_addr) = listener.accept().await.unwrap();
        let mut first_byte = [0u8; 1];
        server_stream.read_exact(&mut first_byte).await.unwrap();
        let res = handle_socks5(first_byte[0], server_stream, peer_addr, &rules).await;
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("SOCKS5 domain name length must be between 1 and 253")
        );
        client_task.await.unwrap();
    }
}
