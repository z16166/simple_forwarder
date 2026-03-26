use anyhow::{Context, Result};
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub enum ProxyType {
    Socks5,
    Socks5h,
    Http,
}

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub proxy_type: ProxyType,
    pub addr: SocketAddr,
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

        let addr: SocketAddr = rest.parse()
            .with_context(|| format!("Invalid proxy address: {}", rest))?;

        Ok(Self { proxy_type, addr })
    }
}

pub struct ProxyClient {
    config: ProxyConfig,
}

impl ProxyClient {
    pub fn new(config: ProxyConfig) -> Self {
        Self { config }
    }

    pub async fn connect(&self, host: &str, port: u16, _resolve_hostname: bool) -> Result<TcpStream> {
        let mut stream = TcpStream::connect(self.config.addr)
            .await
            .with_context(|| format!("Failed to connect to proxy {}", self.config.addr))?;

        match self.config.proxy_type {
            ProxyType::Socks5 => self.socks5_connect(&mut stream, host, port, false).await?,
            ProxyType::Socks5h => self.socks5_connect(&mut stream, host, port, true).await?,
            ProxyType::Http => self.http_connect(&mut stream, host, port).await?,
        }

        Ok(stream)
    }

    async fn socks5_connect(
        &self,
        stream: &mut TcpStream,
        host: &str,
        port: u16,
        resolve_hostname: bool,
    ) -> Result<()> {
        let mut request = BytesMut::with_capacity(4);
        request.put_u8(0x05);
        request.put_u8(0x01);
        request.put_u8(0x00);

        stream.write_all(&request).await?;

        let mut response = BytesMut::with_capacity(2);
        stream.read_buf(&mut response).await?;

        if response.len() < 2 {
            return Err(anyhow::anyhow!("Invalid SOCKS5 handshake response"));
        }

        if response[1] != 0x00 {
            return Err(anyhow::anyhow!("SOCKS5 authentication failed"));
        }

        let mut request = BytesMut::with_capacity(256);
        request.put_u8(0x05);
        request.put_u8(0x01);
        request.put_u8(0x00);

        if resolve_hostname {
            request.put_u8(0x03);
            let host_bytes = host.as_bytes();
            if host_bytes.len() > 255 {
                return Err(anyhow::anyhow!("Hostname too long"));
            }
            request.put_u8(host_bytes.len() as u8);
            request.put_slice(host_bytes);
        } else {
            let addr: std::net::IpAddr = host.parse()
                .with_context(|| format!("Invalid IP address: {}", host))?;
            match addr {
                std::net::IpAddr::V4(ipv4) => {
                    request.put_u8(0x01);
                    request.put_slice(&ipv4.octets());
                }
                std::net::IpAddr::V6(ipv6) => {
                    request.put_u8(0x04);
                    request.put_slice(&ipv6.octets());
                }
            }
        }

        request.put_u16(port.to_be());

        stream.write_all(&request).await?;

        let mut response = BytesMut::with_capacity(10);
        stream.read_buf(&mut response).await?;

        if response.len() < 4 {
            return Err(anyhow::anyhow!("Invalid SOCKS5 connect response"));
        }

        if response[1] != 0x00 {
            return Err(anyhow::anyhow!("SOCKS5 connect failed with code: {}", response[1]));
        }

        Ok(())
    }

    async fn http_connect(&self, stream: &mut TcpStream, host: &str, port: u16) -> Result<()> {
        let connect_request = format!(
            "CONNECT {}:{} HTTP/1.1\r\n\
             Host: {}:{}\r\n\
             Proxy-Connection: keep-alive\r\n\
             \r\n",
            host, port, host, port
        );

        stream.write_all(connect_request.as_bytes()).await?;

        let mut response = BytesMut::with_capacity(1024);
        stream.read_buf(&mut response).await?;

        let response_str = String::from_utf8_lossy(&response);
        if !response_str.starts_with("HTTP/1.1 200") && !response_str.starts_with("HTTP/1.0 200") {
            return Err(anyhow::anyhow!("HTTP CONNECT failed: {}", response_str.lines().next().unwrap_or("")));
        }

        Ok(())
    }
}
