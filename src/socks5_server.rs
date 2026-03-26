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
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;

    let version = header[0];
    if version != 0x05 {
        return Err(anyhow::anyhow!("Unsupported SOCKS version: {}", version));
    }

    let nmethods = header[1] as usize;
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

    log::info!("Request from {}: {}:{} (atyp={}, resolve_hostname: {})", peer_addr, host, port, atyp, resolve_hostname);

    let mut target_stream = None;

    for (matcher, proxy_config) in &rules {
        log::debug!("Checking rule with host={}, ip={:?}", host, ip);
        if matcher.matches(&host, ip) {
            log::info!("Matched rule, forwarding to proxy: {}", proxy_config.addr);
            let client = ProxyClient::new(proxy_config.clone());
            log::debug!("About to connect to proxy...");
            match client.connect(&host, port, resolve_hostname).await {
                Ok(s) => {
                    log::debug!("Successfully connected to proxy");
                    target_stream = Some(s);
                    break;
                }
                Err(e) => {
                    log::error!("Failed to connect to proxy {}: {}", proxy_config.addr, e);
                    send_error_reply(&mut stream, 0x05).await?;
                    return Err(e);
                }
            }
        }
    }

    if target_stream.is_none() {
        log::info!("No rule matched, connecting directly to {}:{}", host, port);
        match TcpStream::connect((host.as_str(), port)).await {
            Ok(s) => {
                target_stream = Some(s);
            }
            Err(e) => {
                log::error!("Failed to connect directly to {}:{}: {}", host, port, e);
                send_error_reply(&mut stream, 0x05).await?;
                return Err(e.into());
            }
        }
    }

    let target_stream = target_stream.unwrap();

    log::debug!("Successfully connected to target {}:{}", host, port);

    send_success_reply(&mut stream).await?;

    log::debug!("Sent SOCKS5 success reply to client");

    let _ = tx.send(()).await;

    let (mut client_reader, mut client_writer) = stream.into_split();
    let (mut target_reader, mut target_writer) = target_stream.into_split();

    let client_to_target = async {
        log::debug!("Starting client to target data transfer");
        let result = tokio::io::copy(&mut client_reader, &mut target_writer).await;
        if let Ok(bytes) = &result {
            log::info!("Client to target data transfer completed: {} bytes", bytes);
        }
        let _ = target_writer.shutdown().await;
        log::debug!("Target writer shutdown complete");
        result
    };

    let target_to_client = async {
        log::debug!("Starting target to client data transfer");
        let result = tokio::io::copy(&mut target_reader, &mut client_writer).await;
        if let Ok(bytes) = &result {
            log::info!("Target to client data transfer completed: {} bytes", bytes);
        }
        let _ = client_writer.shutdown().await;
        log::debug!("Client writer shutdown complete");
        result
    };

    log::debug!("Waiting for data transfer to complete...");

    let (client_to_target_result, target_to_client_result) = tokio::join!(
        client_to_target,
        target_to_client
    );

    if let Err(e) = client_to_target_result {
        log::debug!("Client to target copy error: {}", e);
    }
    if let Err(e) = target_to_client_result {
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
