# vscan

A fast, concurrent port scanner written in Go.

## Features

- **TCP Connect scanning** — Full TCP handshake, works without root
- **SYN half-open scanning** — Stealthier SYN scan (requires root)
- **CIDR range support** — Scan entire subnets (e.g., `192.168.1.0/24`)
- **Service detection** — Banner grabbing and service identification on open ports
- **Host discovery** — Auto-detects alive hosts before scanning
- **Multiple output formats** — CLI table, JSON, and CSV
- **Worker pool concurrency** — Configurable goroutine pool for fast scanning
- **Port range parsing** — Supports `80,443`, `1-1024`, and `top100` presets

## Install

```bash
go install github.com/ivoidable/vscan@latest
```

Or build from source:

```bash
git clone https://github.com/ivoidable/vscan
cd vscan
go build -o vscan .
```

## Usage

```bash
# Scan a single host (top 100 ports)
vscan scan 192.168.1.1

# Scan specific ports
vscan scan 192.168.1.1 -p 80,443,8080

# Scan a port range
vscan scan 192.168.1.1 -p 1-1024

# Scan an entire subnet
vscan scan 192.168.1.0/24 -p 80,443

# SYN scan (requires root)
vscan scan 192.168.1.1 -p 1-1024 --scan syn --iface en0

# Service detection with banner grabbing
vscan scan 192.168.1.1 -p 1-100 --service-detect

# Export to JSON
vscan scan 192.168.1.1 -p 80,443 --output json --out results.json

# Export to CSV
vscan scan 192.168.1.1 -p 80,443 --output csv --out results.csv

# Tune concurrency and timeout
vscan scan 192.168.1.1 -p 1-65535 --workers 500 --timeout 1s
```

## Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ports` | `-p` | `top100` | Port spec: `80`, `1-1024`, `80,443,8080` |
| `--scan` | | `tcp` | Scan type: `tcp` or `syn` |
| `--output` | `-o` | `cli` | Output format: `cli`, `json`, `csv` |
| `--out` | | | Write results to file |
| `--workers` | `-w` | `100` | Concurrent goroutines |
| `--timeout` | `-t` | `2s` | Per-port timeout |
| `--service-detect` | | `false` | Enable banner grabbing |
| `--no-ping` | | `false` | Skip host discovery |
| `--iface` | | | Network interface for SYN scan |

## Scan Types

| Type | Method | Root Required | Speed | Stealth |
|------|--------|---------------|-------|---------|
| TCP Connect | Full 3-way handshake | No | Fast | Low |
| SYN Half-open | SYN → SYN/ACK, then RST | Yes | Faster | Medium |

## Project Structure

```
vscan/
├── main.go                 # Entry point
├── cmd/
│   ├── root.go             # Root cobra command
│   ├── scan.go             # Scan subcommand
│   └── version.go          # Version subcommand
├── pkg/
│   ├── scanner/            # Core scan engine
│   │   ├── types.go        # ScanConfig, ScanResult structs
│   │   ├── tcp.go          # TCP Connect scan
│   │   ├── syn.go          # SYN half-open scan (gopacket)
│   │   └── scanner.go      # Worker pool orchestrator
│   ├── detect/
│   │   └── service.go      # Banner grabbing + service detection
│   ├── netutil/
│   │   ├── ports.go        # Port range parsing
│   │   └── cidr.go         # CIDR expansion
│   └── output/
│       ├── cli.go          # Pretty terminal table
│       ├── json.go         # JSON export
│       └── csv.go          # CSV export
└── internal/
    └── defaults.go         # Default constants
```

## Concurrency Model

Uses a worker pool pattern with configurable goroutine count. Jobs are dispatched through a channel and results are collected synchronously. This prevents socket exhaustion while maintaining high throughput.

## Service Detection

When `--service-detect` is enabled, open ports are probed for banners:
- HTTP services receive a `HEAD /` request
- SSH banners are read directly
- MySQL, Redis, and other services use protocol-specific probes
- Results include service name and version when available

## Testing

```bash
go test ./...
```

## License

MIT
