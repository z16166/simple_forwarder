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
    let mut buffer = BytesMut::with_capacity(262);

    stream.read_buf(&mut buffer).await?;

    if buffer.is_empty() {
        return Ok(());
    }

    let version = buffer[0];
    if version != 0x05 {
        return Err(anyhow::anyhow!("Unsupported SOCKS version: {}", version));
    }

    let nmethods = buffer[1] as usize;
    let methods = &buffer[2..2 + nmethods];

    let selected_method = if methods.contains(&0x00) {
        0x00
    } else {
        0xFF
    };

    let mut response = BytesMut::with_capacity(2);
    response.put_u8(0x05);
    response.put_u8(selected_method);

    stream.write_all(&response).await?;

    if selected_method == 0xFF {
        return Err(anyhow::anyhow!("No acceptable authentication method"));
    }

    buffer.clear();
    stream.read_buf(&mut buffer).await?;

    if buffer.len() < 4 {
        return Err(anyhow::anyhow!("Invalid SOCKS5 request"));
    }

    let cmd = buffer[1];
    if cmd != 0x01 {
        send_error_reply(&mut stream, 0x07).await?;
        return Err(anyhow::anyhow!("Unsupported command: {}", cmd));
    }

    let atyp = buffer[3];
    let (host, port, resolve_hostname, ip) = match atyp {
        0x01 => {
            let addr = Ipv4Addr::new(buffer[4], buffer[5], buffer[6], buffer[7]);
            let port = u16::from_be_bytes([buffer[8], buffer[9]]);
            (addr.to_string(), port, false, Some(IpAddr::V4(addr)))
        }
        0x03 => {
            let len = buffer[4] as usize;
            if buffer.len() < 5 + len + 2 {
                send_error_reply(&mut stream, 0x01).await?;
                return Err(anyhow::anyhow!("Invalid domain length"));
            }
            let host = String::from_utf8_lossy(&buffer[5..5 + len]).to_string();
            let port = u16::from_be_bytes([buffer[5 + len], buffer[5 + len + 1]]);
            (host, port, true, None)
        }
        0x04 => {
            let addr = Ipv6Addr::new(
                u16::from_be_bytes([buffer[4], buffer[5]]),
                u16::from_be_bytes([buffer[6], buffer[7]]),
                u16::from_be_bytes([buffer[8], buffer[9]]),
                u16::from_be_bytes([buffer[10], buffer[11]]),
                u16::from_be_bytes([buffer[12], buffer[13]]),
                u16::from_be_bytes([buffer[14], buffer[15]]),
                u16::from_be_bytes([buffer[16], buffer[17]]),
                u16::from_be_bytes([buffer[18], buffer[19]]),
            );
            let port = u16::from_be_bytes([buffer[20], buffer[21]]);
            (addr.to_string(), port, false, Some(IpAddr::V6(addr)))
        }
        _ => {
            send_error_reply(&mut stream, 0x08).await?;
            return Err(anyhow::anyhow!("Unsupported address type: {}", atyp));
        }
    };

    log::info!("Request from {}: {}:{} (resolve_hostname: {})", peer_addr, host, port, resolve_hostname);

    let mut target_stream = None;

    for (matcher, proxy_config) in &rules {
        if matcher.matches(&host, ip) {
            log::info!("Matched rule, forwarding to proxy: {}", proxy_config.addr);
            let client = ProxyClient::new(proxy_config.clone());
            match client.connect(&host, port, resolve_hostname).await {
                Ok(s) => {
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

    let mut target_stream = target_stream.unwrap();

    send_success_reply(&mut stream).await?;

    let _ = tx.send(()).await;

    let (mut client_reader, mut client_writer) = stream.split();
    let (mut target_reader, mut target_writer) = target_stream.split();

    let client_to_target = async {
        tokio::io::copy(&mut client_reader, &mut target_writer).await
    };

    let target_to_client = async {
        tokio::io::copy(&mut target_reader, &mut client_writer).await
    };

    tokio::select! {
        result = client_to_target => {
            if let Err(e) = result {
                log::debug!("Client to target copy error: {}", e);
            }
        }
        result = target_to_client => {
            if let Err(e) = result {
                log::debug!("Target to client copy error: {}", e);
            }
        }
    }

    log::debug!("Connection from {} to {}:{} closed", peer_addr, host, port);

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
