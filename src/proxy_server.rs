use anyhow::{Context, Result};
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tokio::time::{timeout, Duration};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_CONNECTIONS: usize = 1024;

use crate::matcher::RuleMatcher;
use crate::proxy_client::{ProxyClient, ProxyConfig};
use arc_swap::ArcSwap;
use std::sync::Arc;

pub struct ProxyServer {
    listener: TcpListener,
    tx: mpsc::Sender<()>,
    rules: Arc<ArcSwap<Vec<(RuleMatcher, ProxyConfig)>>>,
    semaphore: Arc<Semaphore>,
}

impl ProxyServer {
    pub async fn new(
        listen_addr: SocketAddr,
        tx: mpsc::Sender<()>,
        rules: Arc<ArcSwap<Vec<(RuleMatcher, ProxyConfig)>>>,
    ) -> Result<Self> {
        let listener = TcpListener::bind(listen_addr)
            .await
            .with_context(|| format!("Failed to bind to {}", listen_addr))?;
        log::info!("Proxy server listening on {}", listen_addr);
        Ok(Self {
            listener,
            tx,
            rules,
            semaphore: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        loop {
            match self.listener.accept().await {
                Ok((stream, peer_addr)) => {
                    log::debug!("Accepted connection from {}", peer_addr);
                    let _ = self.tx.try_send(());

                    let tx = self.tx.clone();
                    let rules = self.rules.clone();
                    let permit = match self.semaphore.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            log::warn!("Max connections ({}) reached, rejecting {}", MAX_CONNECTIONS, peer_addr);
                            drop(stream);
                            continue;
                        }
                    };

                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(e) = handle_connection(stream, peer_addr, rules, tx).await {
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

async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    rules: Arc<ArcSwap<Vec<(RuleMatcher, ProxyConfig)>>>,
    tx: mpsc::Sender<()>,
) -> Result<()> {
    let rules_guard = rules.load();
    let res = timeout(HANDSHAKE_TIMEOUT, async {
        let mut first_byte = [0u8; 1];
        stream.read_exact(&mut first_byte).await?;

        if first_byte[0] == 0x05 {
            handle_socks5(first_byte[0], stream, peer_addr, &rules_guard).await
        } else if first_byte[0] == 0x04 {
            handle_socks4(first_byte[0], stream, peer_addr, &rules_guard).await
        } else {
            handle_http(first_byte[0], stream, peer_addr, &rules_guard).await
        }
    }).await;

    match res {
        Ok(Ok((stream, target_stream, host, port))) => {
            relay_data(stream, target_stream, host, port, peer_addr, tx).await
        }
        Ok(Err(e)) => Err(e),
        Err(_) => {
            log::warn!("Handshake with {} timed out", peer_addr);
            Err(anyhow::anyhow!("Handshake timed out"))
        }
    }
}

async fn handle_socks4(
    _first_byte: u8,
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    rules: &[(RuleMatcher, ProxyConfig)],
) -> Result<(TcpStream, TcpStream, String, u16)> {
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

    // Read User ID (null-terminated)
    let mut user_id = vec![];
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await?;
        if byte[0] == 0 { break; }
        user_id.push(byte[0]);
        if user_id.len() > 255 { return Err(anyhow::anyhow!("SOCKS4 User ID too long")); }
    }

    let host = if is_socks4a {
        // Read Domain Name (null-terminated)
        let mut domain = vec![];
        loop {
            stream.read_exact(&mut byte).await?;
            if byte[0] == 0 { break; }
            domain.push(byte[0]);
            if domain.len() > 255 { return Err(anyhow::anyhow!("SOCKS4a domain too long")); }
        }
        String::from_utf8_lossy(&domain).to_string()
    } else {
        Ipv4Addr::from(ip_bytes).to_string()
    };

    let ip = if is_socks4a { None } else { Some(IpAddr::V4(Ipv4Addr::from(ip_bytes))) };

    log::info!("SOCKS4{} request from {}: {}:{}", if is_socks4a { "a" } else { "" }, peer_addr, host, port);

    let target_stream = connect_to_target(&host, port, is_socks4a, ip, &rules, &mut stream, false).await?;

    send_socks4_reply(&mut stream, 0x5A).await?;

    Ok((stream, target_stream, host, port))
}

async fn send_socks4_reply(stream: &mut TcpStream, status: u8) -> Result<()> {
    let mut reply = [0u8; 8];
    reply[1] = status;
    // bytes 2-7 are ignored by SOCKS4 clients for CONNECT
    stream.write_all(&reply).await?;
    Ok(())
}

async fn handle_socks5(
    _first_byte: u8,
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    rules: &[(RuleMatcher, ProxyConfig)],
) -> Result<(TcpStream, TcpStream, String, u16)> {
    // We already read the first byte (version 0x05)
    let mut second_byte = [0u8; 1];
    stream.read_exact(&mut second_byte).await?;
    let nmethods = second_byte[0] as usize;

    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    let selected_method = if methods.contains(&0x00) {
        0x00
    } else {
        0xFF
    };

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
        return Err(anyhow::anyhow!("Unsupported command: {}", cmd));
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
            return Err(anyhow::anyhow!("Unsupported address type: {}", atyp));
        }
    };

    log::info!("SOCKS5 request from {}: {}:{}", peer_addr, host, port);

    let target_stream = connect_to_target(&host, port, resolve_hostname, ip, &rules, &mut stream, true).await?;

    send_success_reply(&mut stream).await?;

    Ok((stream, target_stream, host, port))
}

async fn handle_http(
    first_byte: u8,
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    rules: &[(RuleMatcher, ProxyConfig)],
) -> Result<(TcpStream, TcpStream, String, u16)> {
    let mut request_line = vec![first_byte];
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await?;
        request_line.push(byte[0]);
        if request_line.ends_with(b"\n") {
            break;
        }
        if request_line.len() > 4096 {
            return Err(anyhow::anyhow!("HTTP request line too long"));
        }
    }

    let request_line_str = String::from_utf8_lossy(&request_line).trim().to_string();
    log::debug!("HTTP request line: {}", request_line_str);

    let parts: Vec<&str> = request_line_str.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(anyhow::anyhow!("Invalid HTTP request line: {}", request_line_str));
    }

    let method = parts[0];
    let uri = parts[1];

    let (host, port, is_connect) = if method.to_uppercase() == "CONNECT" {
        if uri.starts_with('[') {
            // IPv6: [::1]:443
            let end_bracket = uri.find(']')
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
        let uri_parsed = uri.parse::<http::Uri>().map_err(|_| anyhow::anyhow!("Failed to parse URI: {}", uri))?;
        let host = uri_parsed.host().ok_or_else(|| anyhow::anyhow!("Missing host in HTTP URI"))?.to_string();
        let port = uri_parsed.port_u16().unwrap_or(80);
        (host, port, false)
    };

    log::info!("HTTP {} request from {}: {}:{}", method, peer_addr, host, port);

    let mut target_stream = connect_to_target(&host, port, true, None, &rules, &mut stream, false).await?;

    if is_connect {
        // CONNECT request: read headers until empty line (discard them)
        let mut line = vec![];
        loop {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).await?;
            line.push(byte[0]);
            if line.ends_with(b"\r\n\r\n") || line.ends_with(b"\n\n") {
                break;
            }
            if line.len() > 8192 {
                return Err(anyhow::anyhow!("HTTP CONNECT headers too long"));
            }
        }
        stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
    } else {
        // Regular GET/POST request: rewrite the request line to origin-form and forward.
        //
        // RFC 7230 §5.3.2 / §5.7.2: browsers talking through an HTTP proxy send the
        // request-target in absolute-form ("GET http://host/path HTTP/1.1"). When this
        // proxy forwards the request directly to the origin server it MUST convert that
        // to origin-form ("GET /path HTTP/1.1"); only an upstream HTTP proxy expects
        // absolute-form. Sending absolute-form to an origin server causes HTTP 400.
        let rewritten_line: Vec<u8> = if uri.starts_with("http://") || uri.starts_with("https://") {
            // Parse out path+query from the absolute URI and rebuild the request line.
            let origin = if let Ok(parsed) = uri.parse::<http::Uri>() {
                let path = parsed.path();
                let path = if path.is_empty() { "/" } else { path };
                match parsed.query() {
                    Some(q) => format!("{path}?{q}"),
                    None    => path.to_string(),
                }
            } else {
                // Fallback: strip scheme+authority manually
                let after_scheme = &uri[uri.find("://").map(|i| i + 3).unwrap_or(0)..];
                let path_start = after_scheme.find('/').map(|i| i).unwrap_or(after_scheme.len());
                let path = &after_scheme[path_start..];
                if path.is_empty() { "/".to_string() } else { path.to_string() }
            };
            let version = if parts.len() >= 3 { parts[2] } else { "HTTP/1.1" };
            format!("{method} {origin} {version}\r\n").into_bytes()
        } else {
            // Already origin-form (Edge sends this); forward as-is.
            request_line.clone()
        };

        log::debug!("Forwarding request line (origin-form): {}",
            String::from_utf8_lossy(&rewritten_line).trim());
        target_stream.write_all(&rewritten_line).await?;

        // Relay headers until \r\n\r\n
        let mut header_buf = [0u8; 1];
        let mut headers = vec![];
        loop {
            stream.read_exact(&mut header_buf).await?;
            headers.push(header_buf[0]);
            if headers.ends_with(b"\r\n\r\n") || headers.ends_with(b"\n\n") {
                break;
            }
            if headers.len() > 16384 {
                return Err(anyhow::anyhow!("HTTP headers too long"));
            }
        }
        target_stream.write_all(&headers).await?;
    }

    Ok((stream, target_stream, host, port))
}

async fn connect_to_target(
    host: &str,
    port: u16,
    resolve_hostname: bool,
    ip: Option<IpAddr>,
    rules: &[(RuleMatcher, ProxyConfig)],
    client_stream: &mut TcpStream,
    is_socks: bool,
) -> Result<TcpStream> {
    for (matcher, proxy_config) in rules {
        if matcher.matches(host, ip) {
            log::info!("Matched rule, forwarding {} to proxy: {}", host, proxy_config.addr);
            let client = ProxyClient::new(proxy_config.clone());
            match client.connect(host, port, resolve_hostname).await {
                Ok(s) => return Ok(s),
                Err(e) => {
                    log::error!("Failed to connect to proxy {}: {}", proxy_config.addr, e);
                    if is_socks {
                        let _ = send_error_reply(client_stream, 0x05).await;
                    }
                    return Err(e);
                }
            }
        }
    }

    log::info!("No rule matched, connecting directly to {}:{}", host, port);
    match timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => {
            log::error!("Failed to connect directly to {}:{}: {}", host, port, e);
            if is_socks {
                let _ = send_error_reply(client_stream, 0x05).await;
            }
            Err(e.into())
        }
        Err(_) => {
            log::error!("Connection to {}:{} timed out", host, port);
            if is_socks {
                let _ = send_error_reply(client_stream, 0x05).await;
            }
            Err(anyhow::anyhow!("Connection timed out"))
        }
    }
}

async fn relay_data(
    stream: TcpStream,
    target_stream: TcpStream,
    host: String,
    port: u16,
    peer_addr: SocketAddr,
    tx: mpsc::Sender<()>,
) -> Result<()> {
    let _ = tx.try_send(());

    let (mut client_reader, mut client_writer) = stream.into_split();
    let (mut target_reader, mut target_writer) = target_stream.into_split();

    let client_to_target = async {
        let mut buf = [0u8; 8192];
        loop {
            match timeout(IDLE_TIMEOUT, client_reader.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    target_writer.write_all(&buf[..n]).await?;
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
                }
                Ok(Err(e)) => return Err::<(), anyhow::Error>(e.into()),
                Err(_) => return Err(anyhow::anyhow!("Target connection idle timeout")),
            }
        }
        let _ = client_writer.shutdown().await;
        Ok(())
    };

    // select! cancels the other direction immediately when one finishes,
    // preventing stale half-connections from lingering for IDLE_TIMEOUT.
    tokio::select! {
        r = client_to_target => {
            if let Err(e) = r {
                log::debug!("Client→Target relay error: {}", e);
            }
        }
        r = target_to_client => {
            if let Err(e) = r {
                log::debug!("Target→Client relay error: {}", e);
            }
        }
    }
    // Remaining stream halves are dropped here, closing both connections

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
    let mut response = BytesMut::with_capacity(10);
    response.put_u8(0x05);
    response.put_u8(0x00);
    response.put_u8(0x00);
    response.put_u8(0x01);
    response.put_u32(0u32.to_be());
    response.put_u16(0u16.to_be());

    stream.write_all(&response).await?;
    Ok(())
}
