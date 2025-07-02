# Enhanced TCP Port Scanner

A high-performance, feature-rich TCP port scanner written in Go with advanced capabilities including service detection, banner grabbing, and comprehensive reporting.

## 🚀 Features

- **High Performance**: Multi-threaded scanning with configurable concurrency
- **Flexible Port Specification**: Support for ranges, comma-separated lists, and file input
- **Service Detection**: Automatic identification of common services
- **Banner Grabbing**: Capture service banners for detailed reconnaissance
- **Multiple Output Formats**: JSON, CSV, and human-readable text reports
- **Real-time Progress**: Live updates during scanning with colored output
- **Graceful Shutdown**: Interrupt handling with Ctrl+C
- **Comprehensive Statistics**: Detailed scan metrics and timing information

## 📦 Installation

### Prerequisites
- Go 1.19 or higher

### Build from Source
```bash
git clone <repository-url>
cd port-scanner
go build -o portscan PortScanner.go
```

### Quick Install
```bash
go install github.com/Kathitjoshi/GopherRecon@latest
```

## 🔧 Usage

### Basic Scanning
```bash
# Scan common ports on localhost
./portscan -host localhost

# Scan specific ports
./portscan -host example.com -ports 80,443,8080

# Scan port range
./portscan -host 192.168.1.1 -ports 1-1000
```

### Advanced Options
```bash
# Enable banner grabbing and service detection
./portscan -host target.com -ports 1-65535 -banner -service

# High-speed scanning with custom threading
./portscan -host example.com -ports 1-10000 -threads 500 -timeout 1s

# Verbose output (show closed ports)
./portscan -host localhost -ports 1-100 -verbose

# Scan from port file
./portscan -host target.com -port-file common-ports.txt
```

### Output and Reporting
```bash
# Save results to JSON
./portscan -host example.com -ports 1-1000 -output results.json -format json

# Generate CSV report
./portscan -host target.com -ports 80-8080 -output scan.csv -format csv

# Text report with all features
./portscan -host example.com -ports 1-65535 -banner -service -output report.txt
```

## 📋 Command Line Options

| Flag | Default | Description |
|------|---------|-------------|
| `-host` | localhost | Target host to scan |
| `-ports` | 1-1024 | Port specification (ranges, lists) |
| `-port-file` | | File containing ports (one per line) |
| `-timeout` | 2s | Connection timeout |
| `-threads` | CPU*50 | Maximum concurrent scans |
| `-verbose` | false | Show closed ports |
| `-service` | true | Enable service detection |
| `-banner` | false | Enable banner grabbing |
| `-output` | | Output file for results |
| `-format` | txt | Output format (txt, json, csv) |

## 📄 Port File Format

Create a text file with one port per line:
```
22
80
443
8080
# Comments are supported
3306
5432
```

## 📊 Output Formats

### JSON Output
```json
{
  "host": "example.com",
  "start_time": "2024-01-15T10:30:00Z",
  "duration": "5.2s",
  "ports": [
    {
      "port": 80,
      "status": "open",
      "service": "HTTP",
      "banner": "nginx/1.18.0",
      "response_time": "45ms",
      "timestamp": "2024-01-15T10:30:01Z"
    }
  ],
  "summary": {
    "total_scanned": 1024,
    "open_ports": 3,
    "closed_ports": 1021
  }
}
```

### CSV Output
```csv
Port,Status,Service,Response_Time,Banner
80,open,HTTP,45ms,nginx/1.18.0
443,open,HTTPS,52ms,nginx/1.18.0
22,open,SSH,38ms,OpenSSH_8.0
```

## 🎯 Common Use Cases

### Network Discovery
```bash
# Quick scan of common ports
./portscan -host 192.168.1.0/24 -ports 22,80,443,3389

# Full TCP scan
./portscan -host target.com -ports 1-65535 -threads 1000
```

### Service Enumeration
```bash
# Detailed service analysis
./portscan -host target.com -ports 1-10000 -service -banner -output services.json -format json
```

### Security Assessment
```bash
# Comprehensive security scan
./portscan -host target.com -port-file security-ports.txt -banner -verbose -output security-scan.txt
```

## 🔍 Service Detection

The scanner automatically detects common services:

| Port | Service | Description |
|------|---------|-------------|
| 21 | FTP | File Transfer Protocol |
| 22 | SSH | Secure Shell |
| 23 | Telnet | Telnet Protocol |
| 25 | SMTP | Email Server |
| 53 | DNS | Domain Name System |
| 80 | HTTP | Web Server |
| 443 | HTTPS | Secure Web Server |
| 3306 | MySQL | MySQL Database |
| 3389 | RDP | Remote Desktop |
| 5432 | PostgreSQL | PostgreSQL Database |

## ⚡ Performance Tips

1. **Optimize Threading**: Use `-threads` based on your system and network
   ```bash
   # For local networks
   ./portscan -host 192.168.1.1 -threads 200
   
   # For internet hosts
   ./portscan -host example.com -threads 50
   ```

2. **Adjust Timeouts**: Lower timeouts for faster scanning
   ```bash
   ./portscan -host fast-host.com -timeout 500ms
   ```

3. **Target Specific Ports**: Focus on relevant ports
   ```bash
   ./portscan -host web-server.com -ports 80,443,8080,8443
   ```

## 🛡️ Security Considerations

- **Legal Usage**: Only scan hosts you own or have permission to test
- **Rate Limiting**: Some firewalls may block aggressive scanning
- **Detection**: Port scanning can be detected by IDS/IPS systems
- **Responsible Disclosure**: Report vulnerabilities responsibly

## 🐛 Troubleshooting

### Common Issues

**DNS Resolution Errors**
```bash
# Use IP address instead of hostname
./portscan -host 192.168.1.1 -ports 80
```

**Timeout Issues**
```bash
# Increase timeout for slow networks
./portscan -host slow-host.com -timeout 5s
```

**Too Many Open Files**
```bash
# Reduce thread count
./portscan -host target.com -threads 50
```

## 📝 Examples

### Basic Web Server Scan
```bash
./portscan -host example.com -ports 80,443,8080,8443 -service -banner
```

### Database Server Assessment
```bash
./portscan -host db-server.com -ports 1433,3306,5432,1521,6379 -banner -output db-scan.json -format json
```

### Network Range Scan
```bash
for i in {1..254}; do
  ./portscan -host 192.168.1.$i -ports 22,80,443 -timeout 1s >> network-scan.txt
done
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for educational and authorized testing purposes only. Users are responsible for complying with applicable laws and regulations. The authors are not responsible for any misuse of this software.

## 🔗 Related Tools

- **Nmap**: Network exploration and security auditing
- **Masscan**: High-speed port scanner
- **Zmap**: Internet-wide network scanner

---

**Happy Scanning!** 🎯
