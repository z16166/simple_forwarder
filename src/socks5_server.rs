use anyhow::{Context, Result};
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::matcher::RuleMatcher;
use crate::proxy_client::{ProxyClient, ProxyConfig};

pub struct Socks5Server {
    listener: TcpListener,
    tx: mpsc::Sender<()>,
    rules: Vec<(RuleMatcher, ProxyConfig)>,
}

impl Socks5Server {
    pub async fn new(addr: SocketAddr, tx: mpsc::Sender<()>, rules: Vec<(RuleMatcher, ProxyConfig)>) -> Result<Self> {
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("Failed to bind to {}", addr))?;

        log::info!("SOCKS5 server listening on {}", addr);

        Ok(Self { listener, tx, rules })
    }

    pub async fn run(&mut self) -> Result<()> {
        loop {
            match self.listener.accept().await {
                Ok((stream, peer_addr)) => {
                    log::debug!("Accepted connection from {}", peer_addr);
                    let _ = self.tx.send(()).await;

                    let tx = self.tx.clone();
                    let rules = self.rules.clone();

                    tokio::spawn(async move {
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
    rules: Vec<(RuleMatcher, ProxyConfig)>,
    tx: mpsc::Sender<()>,
) -> Result<()> {
    let mut first_byte = [0u8; 1];
    stream.read_exact(&mut first_byte).await?;

    if first_byte[0] == 0x05 {
        handle_socks5(first_byte[0], stream, peer_addr, rules, tx).await
    } else if first_byte[0] == 0x04 {
        handle_socks4(first_byte[0], stream, peer_addr, rules, tx).await
    } else {
        handle_http(first_byte[0], stream, peer_addr, rules, tx).await
    }
}

async fn handle_socks4(
    _first_byte: u8,
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    rules: Vec<(RuleMatcher, ProxyConfig)>,
    tx: mpsc::Sender<()>,
) -> Result<()> {
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

    relay_data(stream, target_stream, host, port, peer_addr, tx).await
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
    rules: Vec<(RuleMatcher, ProxyConfig)>,
    tx: mpsc::Sender<()>,
) -> Result<()> {
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

    relay_data(stream, target_stream, host, port, peer_addr, tx).await
}

async fn handle_http(
    first_byte: u8,
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    rules: Vec<(RuleMatcher, ProxyConfig)>,
    tx: mpsc::Sender<()>,
) -> Result<()> {
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
        let host_port: Vec<&str> = uri.split(':').collect();
        let host = host_port[0].to_string();
        let port = if host_port.len() > 1 {
            host_port[1].parse().unwrap_or(443)
        } else {
            443
        };
        (host, port, true)
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
        // Regular GET/POST request: forward the original request line and headers
        
        // Forward the modified request line if connecting directly,
        // or the original if connecting to an upstream proxy.
        // For simplicity, we'll try to forward the headers and original request line first.
        target_stream.write_all(&request_line).await?;

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

    relay_data(stream, target_stream, host, port, peer_addr, tx).await
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
    match TcpStream::connect((host, port)).await {
        Ok(s) => Ok(s),
        Err(e) => {
            log::error!("Failed to connect directly to {}:{}: {}", host, port, e);
            if is_socks {
                let _ = send_error_reply(client_stream, 0x05).await;
            }
            Err(e.into())
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
    let _ = tx.send(()).await;

    let (mut client_reader, mut client_writer) = stream.into_split();
    let (mut target_reader, mut target_writer) = target_stream.into_split();

    let client_to_target = async {
        let result = tokio::io::copy(&mut client_reader, &mut target_writer).await;
        let _ = target_writer.shutdown().await;
        result
    };

    let target_to_client = async {
        let result = tokio::io::copy(&mut target_reader, &mut client_writer).await;
        let _ = client_writer.shutdown().await;
        result
    };

    let (c2t, t2c) = tokio::join!(client_to_target, target_to_client);

    if let Err(e) = c2t {
        log::debug!("Client to target copy error: {}", e);
    }
    if let Err(e) = t2c {
        log::debug!("Target to client copy error: {}", e);
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
