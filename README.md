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

### Rule Matching

The proxy supports three types of pattern matching:

1. **Domain Wildcard**: `*.google.com` matches any subdomain of google.com
2. **Single IP**: `192.168.1.1` matches exactly this IP address
3. **CIDR**: `192.168.1.0/24` matches any IP in this range (supports both IPv4 and IPv6)

Rules are evaluated in order. The first matching rule is used to forward the traffic. If no rule matches, the connection is made directly.

### Proxy Protocols

The `forward_to` field supports three proxy protocols:

- `socks5://host:port` - Standard SOCKS5 (client resolves DNS)
- `socks5h://host:port` - SOCKS5 with remote DNS resolution
- `http://host:port` - HTTP CONNECT proxy

## Building

```bash
cargo build --release
```

## Windows GUI Mode

On Windows, the executable is built as a GUI application (no console window).

## Usage

1. Run the executable
2. Configure your applications to use SOCKS5 proxy at `127.0.0.1:1080`
3. The system tray icon shows:
   - Gray icon: No active traffic
   - Green icon: Active traffic forwarding
4. Right-click the tray icon and select "Quit" to exit

## Development

### Building from Source

```bash
# Clone the repository
git clone https://github.com/z16166/simple_forwarder.git
cd simple_forwarder

# Build
cargo build --release
```

### Running Tests

```bash
cargo test
```

## License

This project is open source and available under the MIT License.
