# Go Port Scanner

[![Go Version](https://img.shields.io/badge/Go-1.16+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/Kathitjoshi/GopherRecon)
[![Go Report Card](https://goreportcard.com/badge/github.com/Kathitjoshi/GopherRecon)](https://goreportcard.com/report/github.com/Kathitjoshi/GopherRecon)
[![GitHub release](https://img.shields.io/github/release/Kathitjoshi/GopherRecon.svg)](https://github.com/Kathitjoshi/GopherRecon/releases)
[![GitHub stars](https://img.shields.io/github/stars/Kathitjoshi/GopherRecon.svg)](https://github.com/Kathitjoshi/GopherRecon/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/Kathitjoshi/GopherRecon.svg)](https://github.com/Kathitjoshi/GopherRecon/network)
[![GitHub issues](https://img.shields.io/github/issues/Kathitjoshi/GopherRecon.svg)](https://github.com/Kathitjoshi/GopherRecon/issues)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/Kathitjoshi/GopherRecon/graphs/commit-activity)

A high-performance TCP port scanner written in Go with both command-line interface (CLI) and web UI capabilities. Features concurrent scanning, service detection, banner grabbing, and multiple output formats.

## Features

- **Dual Mode Operation**: CLI for automation and Web UI for interactive use
- **High Performance**: Concurrent scanning with configurable thread pools
- **Service Detection**: Identifies common services running on open ports
- **Banner Grabbing**: Captures service banners for reconnaissance
- **Multiple Output Formats**: JSON, CSV, and human-readable text reports
- **Flexible Port Specification**: Support for ranges, lists, and file input
- **Real-time Progress**: JSON-formatted logging for integration with monitoring systems
- **Graceful Interruption**: Handles Ctrl+C and context cancellation properly

## Installation

### Prerequisites
- Go 1.16 or later

### Build from Source
```bash
git clone https://github.com/Kathitjoshi/GopherRecon.git
cd GopherRecon
go build -o portscanner PortScanner.go
```

### Direct Run
```bash
go run PortScanner.go [options]
```

## Usage

### Command Line Interface (CLI)

#### Basic Scanning
```bash
# Scan common web ports
./portscanner -host example.com -ports 80,443,8080

# Scan a port range
./portscanner -host 192.168.1.1 -ports 1-1000

# Scan with service detection and banner grabbing
./portscanner -host scanme.nmap.org -ports 1-1024 -service -banner
```

#### Advanced Options
```bash
# High-speed scan with custom threads and timeout
./portscanner -host target.com -ports 1-65535 -threads 500 -timeout 500ms

# Scan from port file with JSON output
./portscanner -host 10.0.0.1 -port-file ports.txt -output results.json -format json

# Verbose scanning (logs closed ports)
./portscanner -host target.com -ports 1-100 -verbose
```

#### CLI Options
- `-host string`: Target host to scan (required)
- `-ports string`: Port specification (e.g., "80,443,1000-2000")
- `-port-file string`: File containing ports to scan (one per line)
- `-threads int`: Number of concurrent scanning threads (default: CPU cores × 50)
- `-timeout duration`: Connection timeout (default: 2s)
- `-service`: Enable service detection (default: true)
- `-banner`: Enable banner grabbing (default: false)
- `-verbose`: Log closed ports for debugging
- `-output string`: Output file path
- `-format string`: Output format - "txt", "json", or "csv" (default: "txt")

### Web User Interface

#### Starting the Web UI
```bash
# Start on default port 8080
./portscanner -ui

# Start on custom port
./portscanner -ui -ui-port 9000
```

Then navigate to `http://localhost:8080` in your browser.

#### Web UI Features
- Interactive form for scan configuration
- Real-time results display
- Responsive design for mobile and desktop
- Persistent form values between scans
- Detailed port information table

## Port Specification Formats

### Range Notation
- Single port: `80`
- Multiple ports: `80,443,8080`
- Port range: `1-1000`
- Combined: `22,80,443,1000-2000,8080-8090`

### Port File Format
Create a text file with one port per line:
```
# Common web ports
80
443
8080
8443

# SSH and FTP
22
21
```

## Output Formats

### Text Format (Default)
Human-readable report with scan summary and open port details.

### JSON Format
Machine-readable format perfect for automation:
```json
{
  "host": "example.com",
  "start_time": "2024-01-15T10:30:00Z",
  "end_time": "2024-01-15T10:30:05Z",
  "duration": "5.2s",
  "ports": [
    {
      "port": 80,
      "status": "open",
      "service": "HTTP",
      "response_time": "45ms",
      "timestamp": "2024-01-15T10:30:02Z"
    }
  ],
  "summary": {
    "total_scanned": 1000,
    "open_ports": 3,
    "closed_ports": 997
  }
}
```

### CSV Format
Spreadsheet-compatible format for data analysis.

## Performance Tuning

### Thread Configuration
- **Low bandwidth/high latency**: 50-100 threads
- **Local network**: 200-500 threads  
- **High-speed connection**: 500-1000 threads

### Timeout Settings
- **Local network**: 100ms-500ms
- **Internet hosts**: 1s-3s
- **Slow/unstable connections**: 5s-10s

### Memory Considerations
Each thread consumes minimal memory (~8KB), but consider:
- Very large port ranges (1-65535) with high thread counts
- Banner grabbing increases memory usage per open port
- Results are stored in memory until scan completion

## Integration Examples

### CI/CD Pipeline
```bash
# Security scan in build pipeline
./portscanner -host staging.myapp.com -ports 1-1024 -format json -output security-scan.json
```

### Monitoring Script
```bash
#!/bin/bash
# Daily security audit
./portscanner -host $1 -ports 1-65535 -threads 1000 -output "scan-$(date +%Y%m%d).json" -format json
```

### Docker Integration
```dockerfile
FROM golang:1.19-alpine AS builder
WORKDIR /app
COPY PortScanner.go .
RUN go build -o portscanner PortScanner.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/portscanner .
CMD ["./portscanner", "-ui", "-ui-port", "8080"]
```

## Logging and Monitoring

The scanner outputs structured JSON logs suitable for log aggregation systems:

```json
{"event":"scan_start", "host":"example.com", "ports_to_scan":1000, "threads":100}
{"event":"scan_result", "host":"example.com", "port":80, "status":"open", "service":"HTTP"}
{"event":"scan_finished", "host":"example.com", "status":"completed", "duration":"2.5s", "open_ports":3}
```

## Security Considerations

- **Permission**: Some systems require elevated privileges for certain scans
- **Rate Limiting**: Respect target system limits to avoid being blocked
- **Legal Compliance**: Only scan systems you own or have explicit permission to test
- **Firewall Logs**: Port scanning generates log entries on target systems
- **Network Policies**: Consider corporate network policies before scanning

## Troubleshooting

### Common Issues

#### "Host resolution failed"
```bash
# Verify DNS resolution
nslookup example.com
# Try IP address directly
./portscanner -host 192.168.1.1 -ports 80
```

#### "Too many open files"
```bash
# Increase system limits
ulimit -n 65536
# Or reduce thread count
./portscanner -host target.com -ports 1-1000 -threads 50
```

#### Web UI "Template not found"
The scanner automatically creates templates. If issues persist:
```bash
# Remove and restart to recreate templates
rm -rf templates/
./portscanner -ui
```

### Performance Issues
- Reduce thread count for stability
- Increase timeout for slow networks
- Use smaller port ranges for testing
- Monitor system resource usage

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup
```bash
git clone https://github.com/Kathitjoshi/GopherRecon.git
cd GopherRecon
go mod init portscanner
go run PortScanner.go -h
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is intended for legitimate security testing and network administration purposes only. Users are responsible for complying with applicable laws and regulations. The authors are not responsible for any misuse of this software.

## Acknowledgments

- Inspired by nmap and other network discovery tools
- Built with Go's excellent concurrency primitives
- Web UI uses semantic HTML and responsive CSS
