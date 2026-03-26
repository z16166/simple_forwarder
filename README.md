# Simple Forwarder

A high-performance SOCKS5 proxy forwarder written in Rust 2024 Edition.

## Features

- SOCKS5/SOCKS5h server for incoming connections
- Forward traffic to SOCKS5/SOCKS5h/HTTP proxies based on rules
- Domain wildcard matching using wildmatch crate
- IP and CIDR matching (IPv4 and IPv6)
- Asynchronous I/O using Tokio
- System tray support with traffic indicator
- Cross-platform support (Windows, macOS, Linux)
- Configurable logging (console or file)

## Configuration

Edit `config.yaml` to configure the proxy:

```yaml
log:
  log_type: console  # or "file"
  file: null         # required if log_type is "file"

listen:
  addr: "127.0.0.1"
  port: 1080

rules:
  - match_patterns:
      - "*.google.com"
      - "192.168.1.0/24"
    forward_to: "socks5://192.168.2.74:8080"
```

## Building

```bash
cargo build --release
```

## Windows GUI Mode

On Windows, the executable is built as a GUI application (no console window).

## Usage

Run the executable and configure your applications to use the SOCKS5 proxy at `127.0.0.1:1080`.
