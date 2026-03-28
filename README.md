# Simple Forwarder

A high-performance Multi-Protocol Proxy Forwarder written in Rust 2024 Edition.

## Features

- **Multi-Protocol Inbound**: Automatically detects and handles SOCKS5, SOCKS4, and HTTP proxy protocols on the same port.
- **Rule-Based Forwarding**: Forward traffic to SOCKS5, SOCKS5h, or HTTP proxies based on flexible matching rules.
- **Protocol Auto-Detection**: Zero-configuration switching between SOCKS5 (`0x05`), SOCKS4 (`0x04`), and HTTP (ASCII).
- **Domain Wildcard Matching**: Support for `*.domain.com` which matches both subdomains and the root domain.
- **Hot-Reloading**: Automatically detects changes to `config.yaml` and reloads routing rules without service interruption using RCU-style updates (`arc-swap`).
- **IP and CIDR Matching**: Supports both IPv4 and IPv6 address/range matching.
- **Run at Startup**: Optional setting in the system tray menu to automatically launch the application on system login via the Windows Registry.
- **Asynchronous I/O**: High performance using the Tokio runtime.
- **System Tray support**: Visual traffic indicator (gray/green), autostart toggle, and easy exit menu.
- **Cross-platform**: Support for Windows, macOS, and Linux.
- **Configurable logging**: Detailed console or file-based logs with local-time support.

## Configuration

Edit `config.yaml` to configure the proxy:

```yaml
log:
  log_type: none     # options: "none" (default), "console", "file"
  level: warn        # log level: debug, info, warn, error
  file: null         # required if log_type is "file"
  flush_interval_secs: 5 # flush interval for file logs (default: 5)
  flush_count: 100   # flush every N entries for file logs (default: 100)

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

1. **Domain Wildcard**: `*.google.com` matches any subdomain (e.g. `www.google.com`) and also the root domain (`google.com`).
2. **Single IP**: `192.168.1.1` matches exactly this IP address.
3. **CIDR**: `192.168.1.0/24` matches any IP in this range (supports both IPv4 and IPv6).

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

On Windows, the application runs as a GUI process by default.
- **Default (none)**: The application runs silently in the background with no console window. You can interact with it via the system tray.
- **Console Mode**: If `log_type` is set to `console` in `config.yaml`, a console window will be automatically allocated to show real-time logs.
- **File Mode**: If `log_type` is set to `file`, logs are written to the specified file with periodic flushing for performance. No console window is shown.

## Usage

1. Run the executable.
2. Configure your applications to use **SOCKS5**, **SOCKS4**, or **HTTP** proxy at `127.0.0.1:1080`.
3. The Proxy Server automatically detects the protocol and applies your configured rules.
4. The system tray icon shows:
   - Gray icon: No active traffic
   - Green icon: Active traffic forwarding
5. Right-click the tray icon and select "Quit" to exit

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
