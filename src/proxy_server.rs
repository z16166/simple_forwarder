use anyhow::{Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::Ordering;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{Duration, timeout};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_CONNECTIONS: usize = 1024;

use crate::connection_tracker::ConnectionTracker;
use crate::etw_resolver::ExeResolver;
use crate::matcher::RuleMatcher;
use crate::proxy_client::{ProxyClient, ProxyConfig, ProxyType};
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

pub struct HandshakeResult {
    pub client_stream: TcpStream,
    pub target_stream: TcpStream,
    pub host: String,
    pub port: u16,
    pub proxy_desc: String,
    pub is_direct: bool,
    pub protocol: String,
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
            tracker.set_proxy_protocol(conn_id, hr.protocol);
            tracker.set_outbound_target(conn_id, format!("{}:{}", hr.host, hr.port));
            tracker.set_proxy(conn_id, hr.proxy_desc.clone());
            tracker.set_connected(conn_id);

            let result = relay_data(
                hr.client_stream,
                hr.target_stream,
                hr.host,
                hr.port,
                peer_addr,
                stats,
                hr.is_direct,
                conn_id,
                tracker,
                hr.leftover,
                bytes_sent_counter,
                bytes_received_counter,
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

        if buf.len() > 1024 {
            return Err(anyhow::anyhow!("SOCKS4 handshake data too long"));
        }

        let n = stream.read(&mut temp).await?;
        if n == 0 {
            return Err(anyhow::anyhow!("Connection closed during SOCKS4 handshake"));
        }
        buf.put_slice(&temp[..n]);
    }

    let u_end = user_id_end.unwrap();
    let _user_id = buf.split_to(u_end + 1).freeze();

    let host = if is_socks4a {
        let d_end = domain_end.unwrap();
        let domain_len = d_end - (u_end + 1);
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

    log::info!(
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

    let proto = if is_socks4a { "SOCKS4a" } else { "SOCKS4" };
    Ok(HandshakeResult {
        client_stream: stream,
        target_stream,
        host,
        port,
        proxy_desc,
        is_direct,
        protocol: proto.to_string(),
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

    if nmethods == 0 {
        return Err(anyhow::anyhow!("SOCKS5 nmethods must be greater than 0"));
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
            if len == 0 {
                send_error_reply(&mut stream, 0x08).await?;
                return Err(anyhow::anyhow!(
                    "SOCKS5 domain name length must be greater than 0"
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

    log::info!("SOCKS5 request from {}: {}:{}", peer_addr, host, port);

    let (target_stream, proxy_desc, is_direct) =
        connect_to_target(&host, port, resolve_hostname, ip, rules, &mut stream, true).await?;

    send_success_reply(&mut stream).await?;

    let proto = if resolve_hostname {
        "SOCKS5h"
    } else {
        "SOCKS5"
    };
    Ok(HandshakeResult {
        client_stream: stream,
        target_stream,
        host,
        port,
        proxy_desc,
        is_direct,
        protocol: proto.to_string(),
        leftover: Bytes::new(),
    })
}

async fn read_http_headers(stream: &mut TcpStream, first_byte: u8) -> Result<(Vec<u8>, Bytes)> {
    let mut buf = BytesMut::with_capacity(4096);
    buf.put_u8(first_byte);
    let mut temp = [0u8; 1024];
    let mut start_pos = 0;
    loop {
        if let Some(pos) = find_header_separator(&buf, start_pos) {
            if pos > 16384 {
                return Err(anyhow::anyhow!("HTTP headers too long"));
            }
            let headers = buf.split_to(pos).freeze();
            return Ok((headers.to_vec(), buf.freeze()));
        }
        if buf.len() > 16384 {
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

fn find_header_separator(buf: &[u8], start_pos: usize) -> Option<usize> {
    if buf.len() < 2 {
        return None;
    }
    let start = start_pos.saturating_sub(3);
    for i in start..buf.len() - 1 {
        if buf[i] == b'\n' {
            if buf[i + 1] == b'\n' {
                return Some(i + 2);
            }
            if i + 2 < buf.len() && buf[i + 1] == b'\r' && buf[i + 2] == b'\n' {
                return Some(i + 3);
            }
        }
    }
    None
}

fn filter_hop_by_hop_headers(headers: &[u8]) -> Vec<u8> {
    let headers_str = String::from_utf8_lossy(headers);
    let hop_by_hop = [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    ];

    let mut filtered = String::new();
    for line in headers_str.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let is_hop = hop_by_hop.iter().any(|&h| {
            if trimmed.len() > h.len() && trimmed.as_bytes()[h.len()] == b':' {
                trimmed[..h.len()].eq_ignore_ascii_case(h)
            } else {
                false
            }
        });
        if !is_hop {
            filtered.push_str(line);
            filtered.push_str("\r\n");
        }
    }
    filtered.push_str("\r\n");
    filtered.into_bytes()
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
                uri[end_bracket + 2..].parse().unwrap_or(443)
            } else {
                443
            };
            (host, port, true)
        } else {
            // IPv4 or domain: host:port
            let (host, port) = match uri.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), p.parse().unwrap_or(443)),
                None => (uri.to_string(), 443),
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
        let port = uri_parsed.port_u16().unwrap_or(80);
        (host, port, false)
    };

    log::info!(
        "HTTP {} request from {}: {}:{}",
        method,
        peer_addr,
        host,
        port
    );

    let (mut target_stream, proxy_desc, is_direct) = match connect_to_target(
        &host,
        port,
        true,
        None,
        rules,
        &mut stream,
        false,
    )
    .await
    {
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
        protocol: "HTTP".to_string(),
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
            log::info!(
                "Matched rule, forwarding {} to proxy: {}",
                host,
                proxy_config.addr
            );
            let scheme = match proxy_config.proxy_type {
                ProxyType::Socks5 => "socks5",
                ProxyType::Socks5h => "socks5h",
                ProxyType::Http => "http",
            };
            let proxy_url = format!("{}://{}", scheme, proxy_config.addr);
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

    log::info!("No rule matched, connecting directly to {}:{}", host, port);
    match timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => Ok((s, "direct".to_string(), true)),
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

#[allow(clippy::too_many_arguments)]
async fn relay_data(
    stream: TcpStream,
    target_stream: TcpStream,
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
) -> Result<()> {
    let (mut client_reader, mut client_writer) = stream.into_split();
    let (mut target_reader, mut target_writer) = target_stream.into_split();

    let client_to_target = async {
        if !leftover.is_empty() {
            target_writer.write_all(&leftover).await?;
            if is_direct {
                stats
                    .direct_tx
                    .fetch_add(leftover.len() as u64, Ordering::Relaxed);
            } else {
                stats
                    .upstream_tx
                    .fetch_add(leftover.len() as u64, Ordering::Relaxed);
            }
            bytes_sent.fetch_add(leftover.len() as u64, Ordering::Relaxed);
            stats.traffic_active.store(true, Ordering::Relaxed);
        }
        let mut buf = [0u8; 8192];
        loop {
            match timeout(IDLE_TIMEOUT, client_reader.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    target_writer.write_all(&buf[..n]).await?;
                    if is_direct {
                        stats.direct_tx.fetch_add(n as u64, Ordering::Relaxed);
                    } else {
                        stats.upstream_tx.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
                    stats.traffic_active.store(true, Ordering::Relaxed);
                }
                Ok(Err(e)) => return Err::<(), anyhow::Error>(e.into()),
                Err(_) => return Err(anyhow::anyhow!("Client connection idle timeout")),
            }
        }
        let _ = target_writer.shutdown().await;
        Ok(())
    };

    let target_to_client = async {
        let mut buf = [0u8; 8192];
        loop {
            match timeout(IDLE_TIMEOUT, target_reader.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    client_writer.write_all(&buf[..n]).await?;
                    if is_direct {
                        stats.direct_rx.fetch_add(n as u64, Ordering::Relaxed);
                    } else {
                        stats.upstream_rx.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    bytes_received.fetch_add(n as u64, Ordering::Relaxed);
                    stats.traffic_active.store(true, Ordering::Relaxed);
                }
                Ok(Err(e)) => return Err::<(), anyhow::Error>(e.into()),
                Err(_) => return Err(anyhow::anyhow!("Target connection idle timeout")),
            }
        }
        let _ = client_writer.shutdown().await;
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
                        tracker.set_error(conn_id, &e.to_string());
                        log::error!("Client→Target relay error: {}", e);
                        return Err(e);
                    }
                    Ok(()) => {
                        if !target_done {
                            linger_timeout = Some(Box::pin(tokio::time::sleep(Duration::from_secs(15))));
                        }
                    }
                }
            }
            r = &mut target_to_client, if !target_done => {
                target_done = true;
                match r {
                    Err(e) => {
                        tracker.set_error(conn_id, &e.to_string());
                        log::error!("Target→Client relay error: {}", e);
                        return Err(e);
                    }
                    Ok(()) => {
                        if !client_done {
                            linger_timeout = Some(Box::pin(tokio::time::sleep(Duration::from_secs(15))));
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
                log::debug!("Linger timeout reached for connection {}, shutting down", conn_id);
                tracker.set_closed(conn_id);
                break;
            }
        }

        if client_done && target_done {
            tracker.set_closed(conn_id);
            break;
        }
    }

    log::info!("Connection from {} to {}:{} closed", peer_addr, host, port);
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
    fn test_find_header_separator() {
        let b1 = b"Host: localhost\r\n\r\n";
        assert_eq!(find_header_separator(b1, 0), Some(b1.len()));

        let b2 = b"Host: localhost\n\n";
        assert_eq!(find_header_separator(b2, 0), Some(b2.len()));

        let b3 = b"Host: localhost\r\n\n";
        assert_eq!(find_header_separator(b3, 0), Some(b3.len()));

        let b4 = b"Host: localhost\n\r\n";
        assert_eq!(find_header_separator(b4, 0), Some(b4.len()));

        let b5 = b"Host: localhost\r\n";
        assert_eq!(find_header_separator(b5, 0), None);

        // Test start_pos optimization
        let b6 = b"Host: localhost\r\n\r\nLeftover data";
        assert_eq!(find_header_separator(b6, 15), Some(19));
    }
}
