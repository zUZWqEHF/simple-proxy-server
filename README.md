# SimpleProtocol Server

A lightweight, single-binary encrypted proxy server written in Go. Designed to work with SimpleProtocol-compatible clients (Android / iOS).

## Features

- **Zero-config** — auto-generates a 256-bit PSK on first run, persists to a stable file (`~/.simpleproxy/psk.hex` by default)
- **Single binary** — no dependencies, no config files needed
- **QR code** — prints a scannable QR code containing the connection URI on startup
- **AES-256-GCM** encrypted framed transport with HKDF-SHA256 key derivation
- **HMAC-SHA256** handshake authentication with timestamp verification (±30s window)
- **Anti-replay** nonce cache to prevent replay attacks
- **Anti-probe** — on auth failure, sends random data before closing (doesn't reveal it's a proxy)
- **Bidirectional relay** — supports any TCP traffic (HTTP, HTTPS, etc.)
- **Foreground / daemon mode** — run with `-fg` for console logging, or daemonise automatically
- **Smart IP detection** — tries overseas + CN-accessible IP services with automatic fallback
- **Environment variable override** — set `SP_SERVER_IP` to skip auto-detection (useful for NAT/CDN/domain)

## Protocol

```
Client → Server Handshake:
  [nonce 32B] [timestamp 8B BE] [HMAC-SHA256 32B] [pad_len 2B BE] [padding 32-256B]

Key Derivation (HKDF-SHA256):
  c2s_key = HKDF(psk, nonce, "simple-c2s", 32)
  s2c_key = HKDF(psk, nonce, "simple-s2c", 32)

Encrypted Frame Format:
  [encrypted_length (2+16 bytes)] [encrypted_payload (N+16 bytes)]

Nonce Construction (12 bytes):
  [4-byte prefix from handshake nonce] [8-byte big-endian counter]
  Length frame uses counter*2, payload frame uses counter*2+1

First encrypted frame = SOCKS5-style target address:
  Type 0x01 (IPv4): [0x01] [4B IP] [2B port BE]
  Type 0x03 (Domain): [0x03] [1B len] [domain] [2B port BE]
  Type 0x04 (IPv6): [0x04] [16B IP] [2B port BE]
```

## Connection URI

```
simple://BASE64URL(port:hex_psk:host)#ServerName
```

Example: `simple://MjMzMzM6YWJjZDEyMzQuLi46MzUuMTkyLjU4LjIxNA#MyServer`

Clients scan this URI via QR code or import directly.

## Requirements

- Go 1.20+ (for building)
- Linux / macOS / Windows (any platform Go supports)

## Build

```bash
# Clone and build
cd simpleserver
go mod tidy
go build -o simpleserver .

# Cross-compile for Linux
GOOS=linux GOARCH=amd64 go build -o simpleserver-linux-amd64 .
```

## Usage

```bash
# First run — generates PSK, prints QR code, starts daemon
./simpleserver -p 23333

# Foreground mode (recommended for debugging, logs to stdout)
./simpleserver -fg -p 23333

# Custom port
./simpleserver -p 8443

# Custom PSK file path (recommended for scripted deployments)
./simpleserver -p 23333 -psk-file /etc/simpleproxy/psk.hex
```

### Command-line flags

| Flag | Default | Description |
|------|---------|-------------|
| `-p` | `23333` | Listen port |
| `-fg` | `false` | Run in foreground (don't daemonise) |
| `-psk-file` | `~/.simpleproxy/psk.hex` | Persistent PSK file path |

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SP_SERVER_IP` | *(empty)* | Manually specify server IP or domain. When set, skips auto-detection entirely. Useful for NAT/CDN/domain setups. |
| `SP_VERBOSE_LOG` | `0` | Set to `1` to enable verbose relay logging (per-connection byte counts, etc.) |

```bash
# Example: manually set server IP (skips all auto-detection)
SP_SERVER_IP=my.domain.com ./simpleserver -fg -p 23333

# Example: use a specific IP behind NAT
SP_SERVER_IP=203.0.113.50 ./simpleserver -p 23333

# Example: enable verbose logging
SP_VERBOSE_LOG=1 ./simpleserver -fg -p 23333
```

### IP auto-detection strategy

When `SP_SERVER_IP` is **not** set, the server automatically detects your public IP using multiple services with fallback:

| Priority | IPv4 Service | IPv6 Service |
|----------|-------------|-------------|
| 1 (overseas) | `api.ipify.org` | `api6.ipify.org` |
| 2 (overseas) | `ifconfig.me/ip` | — |
| 3 (CN-accessible) | `myip.ipip.net/ip` | `6.ipw.cn` |
| 4 (CN-accessible) | `4.ipw.cn` | — |

IPv4 and IPv6 detection run in parallel. If all services fail, the server will interactively prompt you to enter your IP (or you can set `SP_SERVER_IP` to avoid the prompt).

### First run output

```
  ╔═══════════════════════════════════════════╗
  ║         SimpleProtocol Server             ║
  ╚═══════════════════════════════════════════╝

  Endpoint : 35.192.58.214:23333
  PSK      : a1b2c3d4...
  PSK file : /home/user/.simpleproxy/psk.hex

  URI:
  simple://MjMzMzM6YTFiMmMz...#SimpleServer

  █████████████████████████████
  █ ▄▄▄▄▄ █ ▀▄▀▀█▀█ ▄▄▄▄▄ █  (QR Code)
  ...

  Daemon started (PID 12345)
```

Scan the QR code with the Android / iOS client to connect.

### Logging

- **Foreground mode** (`-fg`): logs to stdout
- **Daemon mode**: logs to `/tmp/simpleserver.log`

```bash
# Monitor daemon logs
tail -f /tmp/simpleserver.log
```

## Deploy as systemd service

```bash
# Copy binary
sudo cp simpleserver /usr/local/bin/

# Create service file
sudo tee /etc/systemd/system/simpleserver.service > /dev/null << 'EOF'
[Unit]
Description=SimpleProtocol Proxy Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/simpleserver -fg -p 23333
Restart=always
RestartSec=5
Environment="_SP_DAEMON=0"

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
sudo systemctl enable simpleserver
sudo systemctl start simpleserver
sudo journalctl -u simpleserver -f
```

## Architecture

```
┌──────────────────────────── Client Device ─────────────────────────┐
│                                                                     │
│  Apps (browser, etc.)                                               │
│       │  TCP / UDP                                                  │
│       ▼                                                             │
│  ┌─────────┐     IP packets      ┌──────────────────────────┐      │
│  │ TUN fd  │ ──────────────────→ │ Packet Reader (userspace │      │
│  │ 10.0.0.2│ ←──────────────── │  TCP stack + DNS proxy)   │      │
│  └─────────┘    crafted packets  └──────────┬───────────────┘      │
│                                              │ TCP connect          │
│                                              ▼                      │
│                                   ┌──────────────────────┐         │
│                                   │ sing-box (mixed-in)  │         │
│                                   │ 127.0.0.1:2080       │         │
│                                   │                      │         │
│                                   │ ┌──────────────────┐ │         │
│                                   │ │  Route decision  │ │         │
│                                   │ │  • intl → proxy  │ │         │
│                                   │ │  • domestic→direct│ │         │
│                                   │ │  • DNS → dns-out │ │         │
│                                   │ └──┬──────────┬────┘ │         │
│                                   │    │          │      │         │
│                                   │  proxy      direct   │         │
│                                   │  outbound   outbound │         │
│                                   └──┬──────────┬────────┘         │
│                                      │          │                   │
│                            ┌─────────┘          └──→ Physical NIC  │
│                            ▼                       (bypass TUN)     │
│                 ┌────────────────────────┐                          │
│                 │ SimpleProtocol Bridge   │                          │
│                 │ (SOCKS5 → Mux Tunnel)  │                          │
│                 │ 127.0.0.1:16080        │                          │
│                 └──────────┬─────────────┘                          │
│                            │ AES-256-GCM encrypted                  │
│                            │ Mux multiplexed TCP                    │
└────────────────────────────┼────────────────────────────────────────┘
                             │
                             ▼
          ┌──────────────────────────────────────────────────┐
          │            SimpleProtocol Server                  │
          │                                                  │
          │  ┌───────────────────────────────────────────┐   │
          │  │ Listener (:23333)                         │   │
          │  │                                           │   │
          │  │  1. Handshake verification                │   │
          │  │     [nonce 32B][ts 8B][HMAC 32B][padding] │   │
          │  │                                           │   │
          │  │  2. HKDF-SHA256 key derivation            │   │
          │  │     c2s_key, s2c_key (AES-256-GCM)        │   │
          │  │                                           │   │
          │  │  3. Mux demultiplex                       │   │
          │  │     Stream 1 ──→ dial target-a:443        │   │
          │  │     Stream 2 ──→ dial target-b:80         │   │
          │  │     Stream N ──→ dial target-n:port       │   │
          │  └───────────────────────────────────────────┘   │
          └──────────────────────────────────────────────────┘
```

### Key Design Points

- **Single encrypted TCP** — Client and server maintain one mux-multiplexed AES-256-GCM connection carrying all streams.
- **HMAC-SHA256 handshake** — Timestamp-verified (±30s window) with anti-replay nonce cache.
- **Anti-probe** — On auth failure, server sends random data before closing, making port scanning unable to identify the service.
- **HKDF key derivation** — Each connection derives unique c2s/s2c session keys from a fresh 32-byte random nonce.
- **Mux demux** — Server unpacks multiplexed streams and dials target servers independently, with async CONNECT to prevent head-of-line blocking.

## Client Apps

| Platform | Repository |
|----------|------------|
| Android | [simple-proxy-client-android](https://github.com/zUZWqEHF/simple-proxy-client-android) |
| iOS | [simple-proxy-client-ios](https://github.com/zUZWqEHF/simple-proxy-client-ios) |

After starting the server, scan the QR code shown in your terminal with a client app, or manually import the connection URI.

## Security

- **PSK storage**: The 256-bit pre-shared key is stored in `~/.simpleproxy/psk.hex` by default (or the `-psk-file` path you provide). Keep this file secure and backed up.
- **Timestamp window**: Handshake requires client/server clocks within ±30 seconds (uses UTC Unix epoch, timezone-independent).
- **Nonce replay protection**: Each nonce can only be used once within a 2-minute window.
- **Forward secrecy**: Each connection derives unique session keys from a fresh random nonce via HKDF.
- **Anti-probing**: Failed authentication connections receive random data, making port scanning unable to identify the service.

## License

MIT