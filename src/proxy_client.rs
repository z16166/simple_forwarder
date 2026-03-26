use anyhow::{Context, Result};
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
    
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

fn get_socks5_error(code: u8) -> &'static str {
    match code {
        0x00 => "succeeded",
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "Network unreachable",
        0x04 => "Host unreachable",
        0x05 => "Connection refused",
        0x06 => "TTL expired",
        0x07 => "Command not supported",
        0x08 => "Address type not supported",
        _ => "unknown error",
    }
}

#[derive(Debug, Clone)]
pub enum ProxyType {
    Socks5,
    Socks5h,
    Http,
}

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub proxy_type: ProxyType,
    pub addr: String,
}

impl ProxyConfig {
    pub fn from_url(url: &str) -> Result<Self> {
        let url = url.trim().trim_matches('`').trim_matches('"');

        let (proxy_type, rest) = if url.starts_with("socks5h://") {
            (ProxyType::Socks5h, &url[10..])
        } else if url.starts_with("socks5://") {
            (ProxyType::Socks5, &url[9..])
        } else if url.starts_with("http://") {
            (ProxyType::Http, &url[7..])
        } else {
            return Err(anyhow::anyhow!("Unsupported proxy URL: {}", url));
        };

        // Validate that rest contains a port
        if !rest.contains(':') {
            return Err(anyhow::anyhow!("Proxy address must include a port: {}", rest));
        }

        Ok(Self { proxy_type, addr: rest.to_string() })
    }
}

pub struct ProxyClient {
    config: ProxyConfig,
}

impl ProxyClient {
    pub fn new(config: ProxyConfig) -> Self {
        Self { config }
    }

    pub async fn connect(&self, host: &str, port: u16, resolve_hostname: bool) -> Result<TcpStream> {
        let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(&self.config.addr))
            .await
            .with_context(|| format!("Proxy connection timed out: {}", self.config.addr))?
            .with_context(|| format!("Failed to connect to proxy {}", self.config.addr))?;

        let should_resolve = match self.config.proxy_type {
            ProxyType::Socks5 => true,
            ProxyType::Socks5h => false,
            ProxyType::Http => true,
        };

        let final_host = if should_resolve && resolve_hostname {
            match timeout(HANDSHAKE_TIMEOUT, tokio::net::lookup_host(format!("{}:{}", host, port))).await {
                Ok(Ok(mut addrs)) => addrs.next().map(|a| a.ip().to_string()).unwrap_or_else(|| host.to_string()),
                _ => host.to_string(),
            }
        } else {
            host.to_string()
        };

        let handshake_result = match self.config.proxy_type {
            ProxyType::Socks5 | ProxyType::Socks5h => {
                timeout(HANDSHAKE_TIMEOUT, self.socks5_connect(&mut stream, &final_host, port, !should_resolve)).await
            }
            ProxyType::Http => {
                timeout(HANDSHAKE_TIMEOUT, self.http_connect(&mut stream, &final_host, port)).await
            }
        };

        match handshake_result {
            Ok(Ok(_)) => Ok(stream),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(anyhow::anyhow!("Handshake with proxy timed out")),
        }
    }

    async fn socks5_connect(
        &self,
        stream: &mut TcpStream,
        host: &str,
        port: u16,
        is_socks5h: bool,
    ) -> Result<()> {
        log::debug!("SOCKS5 handshake with proxy {}", self.config.addr);

        let mut request = [0u8; 3];
        request[0] = 0x05;
        request[1] = 0x01;
        request[2] = 0x00;

        stream.write_all(&request).await?;

        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;

        if response[0] != 0x05 {
            return Err(anyhow::anyhow!("Invalid SOCKS5 version: {}", response[0]));
        }

        if response[1] != 0x00 {
            return Err(anyhow::anyhow!("SOCKS5 authentication failed, only 'NO AUTHENTICATION' is supported"));
        }

        log::debug!("SOCKS5 handshake successful, sending connect request");

        let mut request = BytesMut::with_capacity(256);
        request.put_u8(0x05);
        request.put_u8(0x01);
        request.put_u8(0x00);

        let addr_parse = host.parse::<std::net::IpAddr>();
        
        match addr_parse {
            Ok(addr) => {
                match addr {
                    std::net::IpAddr::V4(ipv4) => {
                        log::debug!("Connecting to {}:{} (IPv4) via proxy", host, port);
                        request.put_u8(0x01);
                        request.put_slice(&ipv4.octets());
                    }
                    std::net::IpAddr::V6(ipv6) => {
                        log::debug!("Connecting to {}:{} (IPv6) via proxy", host, port);
                        request.put_u8(0x04);
                        request.put_slice(&ipv6.octets());
                    }
                }
            }
            Err(_) if is_socks5h => {
                log::debug!("Connecting to {}:{} (Domain) via proxy (SOCKS5h)", host, port);
                request.put_u8(0x03);
                let host_bytes = host.as_bytes();
                if host_bytes.len() > 255 {
                    return Err(anyhow::anyhow!("Hostname too long"));
                }
                request.put_u8(host_bytes.len() as u8);
                request.put_slice(host_bytes);
            }
            Err(_) => {
                return Err(anyhow::anyhow!("Hostname {} found but upstream proxy requires an IP address (standard SOCKS5) and local resolution failed or was disabled", host));
            }
        }

        request.put_u16(port); // put_u16 already uses Big Endian

        stream.write_all(&request).await?;

        let mut response_header = [0u8; 4];
        stream.read_exact(&mut response_header).await?;

        if response_header[0] != 0x05 {
            return Err(anyhow::anyhow!("Invalid SOCKS5 version in connect response"));
        }

        if response_header[1] != 0x00 {
            return Err(anyhow::anyhow!("SOCKS5 connect failed with code: {} ({})", response_header[1], get_socks5_error(response_header[1])));
        }

        let atyp = response_header[3];
        match atyp {
            0x01 => {
                let mut addr_port = [0u8; 6];
                stream.read_exact(&mut addr_port).await?;
            }
            0x03 => {
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf).await?;
                let len = len_buf[0] as usize;
                let mut rest = vec![0u8; len + 2];
                stream.read_exact(&mut rest).await?;
            }
            0x04 => {
                let mut addr_port = [0u8; 18];
                stream.read_exact(&mut addr_port).await?;
            }
            _ => return Err(anyhow::anyhow!("Invalid ATYP in SOCKS5 response: {}", atyp)),
        }

        log::debug!("SOCKS5 connect successful");

        Ok(())
    }

    async fn http_connect(&self, stream: &mut TcpStream, host: &str, port: u16) -> Result<()> {
        log::debug!("HTTP CONNECT to {}:{} via proxy {}", host, port, self.config.addr);
        let connect_request = format!(
            "CONNECT {}:{} HTTP/1.1\r\n\
             Host: {}:{}\r\n\
             \r\n",
            host, port, host, port
        );

        stream.write_all(connect_request.as_bytes()).await?;

        let mut response = Vec::new();
        let mut byte = [0u8; 1];
        
        loop {
            stream.read_exact(&mut byte).await?;
            response.push(byte[0]);
            
            if response.ends_with(b"\r\n\r\n") {
                break;
            }
            
            if response.len() > 8192 {
                return Err(anyhow::anyhow!("HTTP CONNECT response headers too long"));
            }
        }

        let response_str = String::from_utf8_lossy(&response);
        let status_line = response_str.lines().next().unwrap_or("");
        if status_line.contains(" 200") {
            Ok(())
        } else {
            Err(anyhow::anyhow!("HTTP CONNECT failed: {}", status_line.trim()))
        }
    }
}
