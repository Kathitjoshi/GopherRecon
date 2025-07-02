// Enhanced TCP Port Scanner with Advanced Features
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// PortResult represents the result of a port scan
type PortResult struct {
	Port      int           `json:"port"`
	Status    string        `json:"status"`
	Service   string        `json:"service,omitempty"`
	Banner    string        `json:"banner,omitempty"`
	Response  time.Duration `json:"response_time"`
	Timestamp time.Time     `json:"timestamp"`
}

// ScanResult represents the complete scan results
type ScanResult struct {
	Host      string       `json:"host"`
	StartTime time.Time    `json:"start_time"`
	EndTime   time.Time    `json:"end_time"`
	Duration  time.Duration `json:"duration"`
	Ports     []PortResult `json:"ports"`
	Summary   ScanSummary  `json:"summary"`
}

// ScanSummary provides scan statistics
type ScanSummary struct {
	Total  int `json:"total_scanned"`
	Open   int `json:"open_ports"`
	Closed int `json:"closed_ports"`
}

// Scanner manages the port scanning operation
type Scanner struct {
	host        string
	timeout     time.Duration
	threads     int
	verbose     bool
	serviceScan bool
	bannerGrab  bool
	results     []PortResult
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
}

// Common port-to-service mapping
var commonServices = map[int]string{
	21:   "FTP",
	22:   "SSH",
	23:   "Telnet",
	25:   "SMTP",
	53:   "DNS",
	80:   "HTTP",
	110:  "POP3",
	135:  "RPC",
	139:  "NetBIOS",
	143:  "IMAP",
	443:  "HTTPS",
	993:  "IMAPS",
	995:  "POP3S",
	1433: "MSSQL",
	1521: "Oracle",
	3306: "MySQL",
	3389: "RDP",
	5432: "PostgreSQL",
	5900: "VNC",
	6379: "Redis",
	8080: "HTTP-Alt",
	8443: "HTTPS-Alt",
}

// NewScanner creates a new scanner instance
func NewScanner(host string, timeout time.Duration, threads int, verbose, serviceScan, bannerGrab bool) *Scanner {
	ctx, cancel := context.WithCancel(context.Background())
	return &Scanner{
		host:        host,
		timeout:     timeout,
		threads:     threads,
		verbose:     verbose,
		serviceScan: serviceScan,
		bannerGrab:  bannerGrab,
		results:     make([]PortResult, 0),
		ctx:         ctx,
		cancel:      cancel,
	}
}

// grabBanner attempts to grab service banner
func (s *Scanner) grabBanner(conn net.Conn) string {
	if !s.bannerGrab {
		return ""
	}
	
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}
	
	banner := strings.TrimSpace(string(buffer[:n]))
	if len(banner) > 100 {
		banner = banner[:100] + "..."
	}
	return banner
}

// scanPort performs a single port scan
func (s *Scanner) scanPort(port int, sem chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	defer func() { <-sem }()
	
	select {
	case <-s.ctx.Done():
		return
	default:
	}
	
	startTime := time.Now()
	address := fmt.Sprintf("%s:%d", s.host, port)
	
	conn, err := net.DialTimeout("tcp", address, s.timeout)
	responseTime := time.Since(startTime)
	
	result := PortResult{
		Port:      port,
		Response:  responseTime,
		Timestamp: time.Now(),
	}
	
	if err != nil {
		result.Status = "closed"
		if s.verbose {
			s.logResult(result, "❌")
		}
	} else {
		result.Status = "open"
		
		// Get service name
		if s.serviceScan {
			if service, exists := commonServices[port]; exists {
				result.Service = service
			}
		}
		
		// Grab banner
		result.Banner = s.grabBanner(conn)
		conn.Close()
		
		s.logResult(result, "✅")
	}
	
	s.mu.Lock()
	s.results = append(s.results, result)
	s.mu.Unlock()
}

// logResult prints scan results
func (s *Scanner) logResult(result PortResult, icon string) {
	service := ""
	if result.Service != "" {
		service = fmt.Sprintf(" (%s)", result.Service)
	}
	
	banner := ""
	if result.Banner != "" {
		banner = fmt.Sprintf(" - %s", result.Banner)
	}
	
	fmt.Printf("%s Port %d%s [%s] (%v)%s\n", 
		icon, result.Port, service, result.Status, result.Response, banner)
}

// parsePortRange parses port ranges and comma-separated ports
func parsePortRange(portStr string) ([]int, error) {
	var ports []int
	
	parts := strings.Split(portStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		
		if strings.Contains(part, "-") {
			// Handle range (e.g., "80-90")
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
			
			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start port: %s", rangeParts[0])
			}
			
			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end port: %s", rangeParts[1])
			}
			
			if start > end || start < 1 || end > 65535 {
				return nil, fmt.Errorf("invalid port range: %d-%d", start, end)
			}
			
			for i := start; i <= end; i++ {
				ports = append(ports, i)
			}
		} else {
			// Handle single port
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("port out of range: %d", port)
			}
			
			ports = append(ports, port)
		}
	}
	
	return ports, nil
}

// loadPortsFromFile loads ports from a file
func loadPortsFromFile(filename string) ([]int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	
	var ports []int
	scanner := bufio.NewScanner(file)
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		port, err := strconv.Atoi(line)
		if err != nil {
			continue
		}
		
		if port >= 1 && port <= 65535 {
			ports = append(ports, port)
		}
	}
	
	return ports, scanner.Err()
}

// validateHost validates the target host
func validateHost(host string) error {
	// Try to resolve the host
	_, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("unable to resolve host '%s': %v", host, err)
	}
	return nil
}

// generateReport creates a comprehensive scan report
func (s *Scanner) generateReport(scanResult ScanResult, format, outputFile string) error {
	var content []byte
	var err error
	
	switch strings.ToLower(format) {
	case "json":
		content, err = json.MarshalIndent(scanResult, "", "  ")
	case "txt":
		content = []byte(s.generateTextReport(scanResult))
	case "csv":
		content = []byte(s.generateCSVReport(scanResult))
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
	
	if err != nil {
		return err
	}
	
	return os.WriteFile(outputFile, content, 0644)
}

// generateTextReport creates a human-readable text report
func (s *Scanner) generateTextReport(scanResult ScanResult) string {
	var report strings.Builder
	
	report.WriteString(fmt.Sprintf("Port Scan Report\n"))
	report.WriteString(fmt.Sprintf("================\n\n"))
	report.WriteString(fmt.Sprintf("Target Host: %s\n", scanResult.Host))
	report.WriteString(fmt.Sprintf("Scan Time: %s\n", scanResult.StartTime.Format("2006-01-02 15:04:05")))
	report.WriteString(fmt.Sprintf("Duration: %s\n", scanResult.Duration))
	report.WriteString(fmt.Sprintf("Total Ports Scanned: %d\n", scanResult.Summary.Total))
	report.WriteString(fmt.Sprintf("Open Ports: %d\n", scanResult.Summary.Open))
	report.WriteString(fmt.Sprintf("Closed Ports: %d\n\n", scanResult.Summary.Closed))
	
	// Open ports section
	openPorts := make([]PortResult, 0)
	for _, port := range scanResult.Ports {
		if port.Status == "open" {
			openPorts = append(openPorts, port)
		}
	}
	
	if len(openPorts) > 0 {
		report.WriteString("Open Ports:\n")
		report.WriteString("-----------\n")
		for _, port := range openPorts {
			service := port.Service
			if service == "" {
				service = "Unknown"
			}
			
			line := fmt.Sprintf("Port %d/tcp - %s (%v)", port.Port, service, port.Response)
			if port.Banner != "" {
				line += fmt.Sprintf(" - %s", port.Banner)
			}
			report.WriteString(line + "\n")
		}
	}
	
	return report.String()
}

// generateCSVReport creates a CSV report
func (s *Scanner) generateCSVReport(scanResult ScanResult) string {
	var report strings.Builder
	
	report.WriteString("Port,Status,Service,Response_Time,Banner\n")
	for _, port := range scanResult.Ports {
		report.WriteString(fmt.Sprintf("%d,%s,%s,%v,%s\n", 
			port.Port, port.Status, port.Service, port.Response, 
			strings.ReplaceAll(port.Banner, ",", ";")))
	}
	
	return report.String()
}

// Run executes the port scan
func (s *Scanner) Run(ports []int) ScanResult {
	startTime := time.Now()
	
	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	
	go func() {
		<-sigChan
		fmt.Println("\n🛑 Scan interrupted by user")
		s.cancel()
	}()
	
	fmt.Printf("🔍 Scanning %d ports on %s with %d threads...\n", len(ports), s.host, s.threads)
	fmt.Printf("⚙️  Timeout: %v | Service Detection: %v | Banner Grabbing: %v\n", 
		s.timeout, s.serviceScan, s.bannerGrab)
	fmt.Println("Press Ctrl+C to stop the scan\n")
	
	sem := make(chan struct{}, s.threads)
	var wg sync.WaitGroup
	
	for _, port := range ports {
		select {
		case <-s.ctx.Done():
			break
		default:
		}
		
		wg.Add(1)
		sem <- struct{}{}
		go s.scanPort(port, sem, &wg)
	}
	
	wg.Wait()
	endTime := time.Now()
	duration := endTime.Sub(startTime)
	
	// Sort results by port number
	sort.Slice(s.results, func(i, j int) bool {
		return s.results[i].Port < s.results[j].Port
	})
	
	// Calculate summary
	summary := ScanSummary{Total: len(s.results)}
	for _, result := range s.results {
		if result.Status == "open" {
			summary.Open++
		} else {
			summary.Closed++
		}
	}
	
	fmt.Printf("\n📊 Scan Summary:\n")
	fmt.Printf("   Total Ports: %d\n", summary.Total)
	fmt.Printf("   Open Ports: %d\n", summary.Open)
	fmt.Printf("   Closed Ports: %d\n", summary.Closed)
	fmt.Printf("   Duration: %s\n", duration)
	
	return ScanResult{
		Host:      s.host,
		StartTime: startTime,
		EndTime:   endTime,
		Duration:  duration,
		Ports:     s.results,
		Summary:   summary,
	}
}

func main() {
	// Command line flags
	host := flag.String("host", "localhost", "Target host to scan")
	portRange := flag.String("ports", "1-1024", "Port range (e.g., 80,443,8080 or 1-1000 or 1-100,8080,9000-9010)")
	portFile := flag.String("port-file", "", "File containing ports to scan (one per line)")
	timeout := flag.Duration("timeout", 2*time.Second, "Connection timeout")
	threads := flag.Int("threads", runtime.NumCPU()*50, "Maximum concurrent scans")
	verbose := flag.Bool("verbose", false, "Verbose output (show closed ports)")
	serviceScan := flag.Bool("service", true, "Enable service detection")
	bannerGrab := flag.Bool("banner", false, "Enable banner grabbing")
	output := flag.String("output", "", "Output file for results")
	format := flag.String("format", "txt", "Output format (txt, json, csv)")
	
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Enhanced TCP Port Scanner\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -host example.com -ports 80,443,8080\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -host 192.168.1.1 -ports 1-1000 -threads 200\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -host target.com -port-file ports.txt -banner -output results.json -format json\n", os.Args[0])
	}
	
	flag.Parse()
	
	// Validate host
	if err := validateHost(*host); err != nil {
		fmt.Printf("❌ Error: %v\n", err)
		os.Exit(1)
	}
	
	// Parse ports
	var ports []int
	var err error
	
	if *portFile != "" {
		ports, err = loadPortsFromFile(*portFile)
		if err != nil {
			fmt.Printf("❌ Error loading ports from file: %v\n", err)
			os.Exit(1)
		}
	} else {
		ports, err = parsePortRange(*portRange)
		if err != nil {
			fmt.Printf("❌ Error parsing port range: %v\n", err)
			os.Exit(1)
		}
	}
	
	if len(ports) == 0 {
		fmt.Println("❌ Error: No valid ports to scan")
		os.Exit(1)
	}
	
	// Validate parameters
	if *threads <= 0 {
		fmt.Println("❌ Error: Thread count must be positive")
		os.Exit(1)
	}
	
	// Create and run scanner
	scanner := NewScanner(*host, *timeout, *threads, *verbose, *serviceScan, *bannerGrab)
	result := scanner.Run(ports)
	
	// Save results if output file specified
	if *output != "" {
		if err := scanner.generateReport(result, *format, *output); err != nil {
			fmt.Printf("❌ Error saving results: %v\n", err)
		} else {
			fmt.Printf("📄 Results saved to %s (%s format)\n", *output, *format)
		}
	}
}