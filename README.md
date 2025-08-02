# Enhanced TCP Port Scanner 🔍

[![Go](https://img.shields.io/badge/Go-1.19+-00ADD8.svg)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)](https://github.com/Kathitjoshi/GopherRecon)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)](https://github.comKathitjoshi/GopherRecon)
[![Security](https://img.shields.io/badge/Security-Ethical%20Use%20Only-red.svg)](https://github.com/Kathitjoshi/GopherRecon)
[![Concurrency](https://img.shields.io/badge/Concurrency-High%20Performance-blue.svg)](https://github.com/Kathitjoshi/GopherRecon)

A high-performance, concurrent TCP port scanner written in Go with advanced features including service detection, banner grabbing, and multiple output formats. Designed for security professionals, network administrators, and penetration testers.

## 🚀 Features

### Core Scanning Capabilities
- **🔥 High-Performance Concurrent Scanning** - Utilizes Go's goroutines for lightning-fast scans
- **🎯 Flexible Port Specification** - Single ports, ranges, comma-separated lists, or file-based input
- **⏱️ Configurable Timeouts** - Customizable connection timeouts for different network conditions
- **🛡️ Service Detection** - Automatic identification of common services (HTTP, SSH, FTP, etc.)
- **📋 Banner Grabbing** - Capture service banners and initial responses
- **🚦 Graceful Interruption** - Ctrl+C handling with partial results preservation

### Output & Reporting
- **📄 Multiple Output Formats** - JSON, CSV, and human-readable text reports
- **📊 Comprehensive Statistics** - Detailed scan summaries and timing information
- **🔍 Structured Logging** - JSON-formatted logs perfect for SIEM integration
- **💾 File Export** - Save results to files for later analysis

### Advanced Features
- **🧵 Thread Control** - Configurable concurrency levels (default: CPU cores × 50)
- **📝 Verbose Mode** - Optional logging of closed ports for complete visibility
- **🌐 Host Validation** - DNS resolution verification before scanning
- **⚡ Real-time Progress** - Live logging of scan results as they complete

## 🛠️ Installation

### Option 1: Download Binary (Easiest)
```bash
# Download latest release for your platform
wget https://github.com/Kathitjoshi/GopherRecon/releases/latest/download/GopherRecon-linux-amd64
chmod +x GopherRecon-linux-amd64
./GopherRecon-linux-amd64 --help
```

### Option 2: Build from Source
```bash
# Clone the repository
git clone https://github.com/Kathitjoshi/GopherRecon.git
cd GopherRecon

# Build the binary
go build -o GopherRecon PortScanner.go

# Run the scanner
./GopherRecon --help
```

### Option 3: Install with Go
```bash
go install github.com/Kathitjoshi/GopherRecon@latest
```

## 🎯 Quick Start

### Basic Usage Examples

**Scan common ports on a website:**
```bash
./GopherRecon -host example.com -ports 80,443,8080
```

**Scan a range of ports with high concurrency:**
```bash
./GopherRecon -host 192.168.1.1 -ports 1-1000 -threads 200
```

**Full scan with banner grabbing and JSON output:**
```bash
./GopherRecon -host target.com -ports 1-65535 -banner -verbose -output results.json -format json
```

**Scan ports from a file:**
```bash
./GopherRecon -host server.local -port-file common-ports.txt -output scan-results.csv -format csv
```

## 📖 Command Line Options

| Flag | Default | Description |
|------|---------|-------------|
| `-host` | `localhost` | Target host to scan (domain or IP) |
| `-ports` | `1-1024` | Port specification (ranges, lists, or single ports) |
| `-port-file` | - | File containing ports to scan (one per line) |
| `-timeout` | `2s` | Connection timeout (e.g., 500ms, 2s, 1m) |
| `-threads` | `CPU×50` | Maximum concurrent goroutines |
| `-verbose` | `false` | Log closed ports in addition to open ports |
| `-service` | `true` | Enable service detection for common ports |
| `-banner` | `false` | Enable banner grabbing from open ports |
| `-output` | - | Output file path for results |
| `-format` | `txt` | Output format: `txt`, `json`, or `csv` |

## 📋 Port Specification Formats

The scanner supports flexible port specification:

```bash
# Single ports
-ports 80,443,8080

# Port ranges  
-ports 1-1000

# Mixed format
-ports 80,443,1000-2000,8080-8090

# From file (ports.txt)
-port-file ports.txt
```

**Example ports.txt file:**
```
# Common web ports
80
443
8080
8443

# Database ports
3306
5432
1433
```

## 📊 Output Formats

### Text Format (Default)
```
Port Scan Report
================

Target Host: example.com
Scan Time: 2024-01-15 14:30:25 UTC
Duration: 2.345s
Total Ports Scanned: 1000
Open Ports: 3
Closed Ports: 997

Open Ports Details:
-------------------
  Port 22/tcp (SSH) - 45.234ms
  Port 80/tcp (HTTP) - 67.891ms - "Apache/2.4.41"
  Port 443/tcp (HTTPS) - 89.123ms
```

### JSON Format
```json
{
  "host": "example.com",
  "start_time": "2024-01-15T14:30:25Z",
  "end_time": "2024-01-15T14:30:27Z",
  "duration": "2.345s",
  "ports": [
    {
      "port": 22,
      "status": "open",
      "service": "SSH",
      "response_time": "45.234ms",
      "timestamp": "2024-01-15T14:30:25Z"
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
```csv
Port,Status,Service,Response_Time,Banner
22,open,SSH,45.234ms,"OpenSSH 8.2"
80,open,HTTP,67.891ms,"Apache/2.4.41"
443,open,HTTPS,89.123ms,""
```

## 🔧 Advanced Usage

### Performance Tuning
```bash
# High-speed scanning with 500 concurrent threads
./GopherRecon -host target.com -ports 1-65535 -threads 500 -timeout 500ms

# Conservative scanning for slow networks
./GopherRecon -host target.com -ports 1-1000 -threads 50 -timeout 5s
```

### Security Testing Workflow
```bash
# 1. Quick discovery scan
./GopherRecon -host target.com -ports 1-1000 -output discovery.json -format json

# 2. Detailed scan of open ports with banner grabbing
./GopherRecon -host target.com -port-file open-ports.txt -banner -service -output detailed.txt

# 3. Full comprehensive scan
./GopherRecon -host target.com -ports 1-65535 -banner -verbose -threads 200 -output full-scan.csv -format csv
```

### Integration with Other Tools
```bash
# Extract open ports for further scanning
cat results.json | jq -r '.ports[] | select(.status=="open") | .port' > open-ports.txt

# Use with nmap for detailed service enumeration
./GopherRecon -host target.com -ports 1-1000 -format json -output quick-scan.json
# Then run nmap on discovered open ports
```

## 🚦 Signal Handling

The scanner supports graceful interruption:
- **Ctrl+C**: Stops scanning and returns partial results
- **SIGTERM**: Graceful shutdown with result preservation
- All completed scans are included in the final report

## 📈 Performance Characteristics

| Scenario | Ports | Threads | Typical Duration |
|----------|-------|---------|-----------------|
| Quick web scan | 10 common ports | 50 | < 1 second |
| Standard scan | 1-1024 | 200 | 10-30 seconds |
| Full port scan | 1-65535 | 500 | 2-10 minutes |

*Performance varies based on network conditions and target responsiveness*

## 🛡️ Security & Ethical Use

### ⚠️ Important Legal Notice
This tool is intended for:
- ✅ Authorized security testing
- ✅ Network administration
- ✅ Educational purposes
- ✅ Testing your own systems

**Always ensure you have explicit permission before scanning any network or system you don't own.**

### Best Practices
- Always obtain written authorization before scanning
- Respect rate limits and don't overwhelm target systems
- Be aware of local laws and regulations
- Consider the impact on network resources
- Document your testing activities

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### Development Setup
```bash
# Clone and setup
git clone https://github.com/Kathitjoshi/GopherRecon.git
cd GopherRecon

# Run tests
go test ./...

# Build and test
go build -o GopherRecon PortScanner.go
./GopherRecon -host localhost -ports 22,80,443
```

### Contribution Ideas
- [ ] Add more service fingerprints
- [ ] Implement UDP scanning
- [ ] Add IPv6 support
- [ ] Create web-based interface
- [ ] Add more output formats (XML, HTML)
- [ ] Implement port knocking detection
- [ ] Add integration with vulnerability databases

## 📋 Roadmap

### Version 2.0
- [ ] UDP port scanning capabilities
- [ ] IPv6 support
- [ ] Plugin system for custom service detection
- [ ] Web-based dashboard
- [ ] Database integration for result storage

### Version 1.5
- [ ] More service fingerprints
- [ ] XML output format
- [ ] Port scan timing templates
- [ ] Integration with popular security tools

## 🐛 Troubleshooting

### Common Issues

**"Permission denied" errors:**
```bash
# On Linux/Mac, may need elevated privileges for certain operations
sudo ./GopherRecon -host target.com -ports 1-1024
```

**"Too many open files" error:**
```bash
# Reduce thread count
./GopherRecon -host target.com -ports 1-65535 -threads 100
```

**Slow scanning:**
```bash
# Reduce timeout and increase threads
./GopherRecon -host target.com -ports 1-1000 -timeout 500ms -threads 200
```

### Performance Tips
- Adjust thread count based on your system capabilities
- Use shorter timeouts for local network scanning
- Consider network bandwidth when setting thread counts
- Use port files to focus on relevant ports

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with the powerful Go programming language
- Inspired by classic tools like Nmap and Masscan
- Thanks to the cybersecurity community for testing and feedback
- Special thanks to contributors and issue reporters

## 📊 Project Stats

![GitHub repo size](https://img.shields.io/github/repo-size/Kathitjoshi/GopherRecon)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/Kathitjoshi/GopherRecon)
![Go version](https://img.shields.io/github/go-mod/go-version/Kathitjoshi/GopherRecon)

---

**⚡ Fast. Reliable. Secure.** 

*Remember: With great scanning power comes great responsibility. Always scan ethically and legally.*

🔍 **Happy Scanning!** If you find this tool useful, please give it a ⭐ star on GitHub!
