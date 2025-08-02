package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
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

//-----------------------------------------------------------------------------
// Data Structures
//-----------------------------------------------------------------------------

// PortResult represents the outcome of scanning a single port.
type PortResult struct {
	Port      int           `json:"port"`              // The port number scanned
	Status    string        `json:"status"`            // "open" or "closed"
	Service   string        `json:"service,omitempty"` // Detected service (e.g., "HTTP", "SSH")
	Banner    string        `json:"banner,omitempty"`  // Grabbed banner information
	Response  time.Duration `json:"response_time"`     // Time taken for connection
	Timestamp time.Time     `json:"timestamp"`         // Time when the scan result was recorded
}

// ScanResult aggregates the results of an entire scan operation.
type ScanResult struct {
	Host      string        `json:"host"`            // The target host that was scanned
	StartTime time.Time     `json:"start_time"`      // When the scan began
	EndTime   time.Time     `json:"end_time"`        // When the scan finished
	Duration  time.Duration `json:"duration"`        // Total duration of the scan
	Ports     []PortResult  `json:"ports"`           // List of individual port scan results
	Summary   ScanSummary   `json:"summary"`         // Statistical summary of the scan
	Error     string        `json:"error,omitempty"` // Any error encountered during the overall scan
}

// ScanSummary provides statistics about the scanned ports.
type ScanSummary struct {
	Total  int `json:"total_scanned"` // Total number of ports attempted
	Open   int `json:"open_ports"`    // Number of open ports found
	Closed int `json:"closed_ports"`  // Number of closed ports encountered
}

// Scanner manages the overall port scanning operation.
type Scanner struct {
	host        string
	timeout     time.Duration
	threads     int
	verbose     bool
	serviceScan bool
	bannerGrab  bool
	results     []PortResult       // Stores the results of each port scan
	mu          sync.RWMutex       // Mutex to protect access to 'results' slice
	ctx         context.Context    // Context for cancellation
	cancel      context.CancelFunc // Function to cancel the context
}

//-----------------------------------------------------------------------------
// Global Constants & Mappings
//-----------------------------------------------------------------------------

// commonServices maps well-known port numbers to their standard service names.
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

//-----------------------------------------------------------------------------
// Scanner Methods
//-----------------------------------------------------------------------------

// NewScanner creates and returns a new Scanner instance, initialized with the
// provided scanning parameters and a cancellable context.
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

// grabBanner attempts to read and return the initial banner from an open connection.
// It applies a short read deadline to prevent hanging on unresponsive services.
func (s *Scanner) grabBanner(conn net.Conn) string {
	if !s.bannerGrab {
		return ""
	}

	// Set a short deadline for reading the banner
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return "" // Return empty string if no banner or error
	}

	banner := strings.TrimSpace(string(buffer[:n]))
	// Truncate long banners for cleaner output
	if len(banner) > 100 {
		banner = banner[:100] + "..."
	}
	return banner
}

// scanPort performs a TCP connection attempt to a single port.
// It records the status, response time, and optionally banner/service info.
// 'sem' is a semaphore channel for limiting concurrent goroutines.
// 'wg' is a WaitGroup to signal completion.
func (s *Scanner) scanPort(port int, sem chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()          // Decrement the WaitGroup counter when done
	defer func() { <-sem }() // Release a slot in the semaphore when done

	// Check if the scan has been cancelled before attempting connection
	select {
	case <-s.ctx.Done():
		return // Exit if context is cancelled
	default:
		// Continue if context is not cancelled
	}

	startTime := time.Now()
	address := fmt.Sprintf("%s:%d", s.host, port)

	// Attempt to establish a TCP connection with a timeout
	conn, err := net.DialTimeout("tcp", address, s.timeout)
	responseTime := time.Since(startTime)

	result := PortResult{
		Port:      port,
		Response:  responseTime,
		Timestamp: time.Now(),
	}

	if err != nil {
		// Port is closed or unreachable
		result.Status = "closed"
		if s.verbose {
			// Log closed ports in JSON format for cloud logging
			log.Printf(`{"event":"scan_result", "host":"%s", "port":%d, "status":"closed", "response_time":"%s", "error":"%v"}`,
				s.host, port, responseTime, err)
		}
	} else {
		// Port is open
		result.Status = "open"

		// Detect common service if enabled
		if s.serviceScan {
			if service, exists := commonServices[port]; exists {
				result.Service = service
			}
		}

		// Grab banner if enabled
		result.Banner = s.grabBanner(conn)
		conn.Close() // Close the connection immediately after use

		// Log open ports in JSON format for cloud logging
		log.Printf(`{"event":"scan_result", "host":"%s", "port":%d, "status":"open", "service":"%s", "response_time":"%s", "banner":"%s"}`,
			s.host, port, result.Service, responseTime, strings.ReplaceAll(result.Banner, "\n", "\\n"))
	}

	// Safely add result to the shared slice
	s.mu.Lock()
	s.results = append(s.results, result)
	s.mu.Unlock()
}

// Run initiates and manages the port scanning process.
// It takes a list of ports to scan and returns the complete ScanResult.
func (s *Scanner) Run(ports []int) ScanResult {
	startTime := time.Now()
	var scanError error // To capture any error that might interrupt the scan

	// Set up signal handling to allow graceful shutdown (e.g., Ctrl+C)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Goroutine to listen for cancellation signals
	go func() {
		select {
		case <-sigChan:
			log.Println(`{"event":"scan_interruption", "message":"Scan interrupted by user signal"}`)
			s.cancel() // Signal the scanner's context to cancel
		case <-s.ctx.Done():
			// Context was cancelled externally (e.g., due to an unhandled error upstream)
			log.Println(`{"event":"scan_interruption", "message":"Scan context cancelled internally"}`)
		}
	}()

	// Initial logging of scan parameters
	log.Printf(`{"event":"scan_start", "host":"%s", "ports_to_scan":%d, "threads":%d, "timeout":"%s", "service_detection":%t, "banner_grabbing":%t}`,
		s.host, len(ports), s.threads, s.timeout, s.serviceScan, s.bannerGrab)
	fmt.Println("Press Ctrl+C to stop the scan (only visible in CLI mode)") // User-friendly message for CLI

	// Semaphore to limit concurrent goroutines
	sem := make(chan struct{}, s.threads)
	var wg sync.WaitGroup // WaitGroup to wait for all goroutines to finish

	// Iterate over each port and start a scan goroutine
	for _, port := range ports {
		// Check for cancellation before launching new goroutine
		select {
		case <-s.ctx.Done():
			scanError = s.ctx.Err() // Capture the cancellation error
			goto EndScan            // Jump to the cleanup section
		default:
			// Continue if context is active
		}

		wg.Add(1)                     // Increment WaitGroup counter for each new goroutine
		sem <- struct{}{}             // Acquire a slot in the semaphore (blocks if full)
		go s.scanPort(port, sem, &wg) // Launch port scan in a new goroutine
	}

	wg.Wait() // Wait for all scan goroutines to complete

EndScan: // Label for the goto statement on cancellation
	endTime := time.Now()
	duration := endTime.Sub(startTime)

	// Safely retrieve and sort the results
	s.mu.RLock() // Acquire read lock before accessing results
	sortedResults := make([]PortResult, len(s.results))
	copy(sortedResults, s.results)
	s.mu.RUnlock() // Release read lock

	sort.Slice(sortedResults, func(i, j int) bool {
		return sortedResults[i].Port < sortedResults[j].Port
	})

	// Calculate scan summary
	summary := ScanSummary{Total: len(sortedResults)}
	for _, res := range sortedResults {
		if res.Status == "open" {
			summary.Open++
		} else {
			summary.Closed++
		}
	}

	// Assemble the final ScanResult
	result := ScanResult{
		Host:      s.host,
		StartTime: startTime,
		EndTime:   endTime,
		Duration:  duration,
		Ports:     sortedResults,
		Summary:   summary,
	}
	if scanError != nil {
		result.Error = fmt.Sprintf("Scan interrupted: %v", scanError)
	}

	// Final scan completion log
	log.Printf(`{"event":"scan_finished", "host":"%s", "status":"%s", "duration":"%s", "open_ports":%d, "total_ports":%d, "error":"%s"}`,
		s.host, func() string {
			if scanError != nil {
				return "interrupted"
			}
			return "completed"
		}(), duration, summary.Open, summary.Total, result.Error)

	return result
}

//-----------------------------------------------------------------------------
// Helper Functions
//-----------------------------------------------------------------------------

// parsePortRange parses a string containing single ports, comma-separated lists,
// and port ranges (e.g., "80,443,100-200"). It returns a sorted slice of unique port integers.
func parsePortRange(portStr string) ([]int, error) {
	var ports []int

	parts := strings.Split(portStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)

		if strings.Contains(part, "-") {
			// Handle port range (e.g., "80-90")
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range format: %q", part)
			}

			startStr, endStr := strings.TrimSpace(rangeParts[0]), strings.TrimSpace(rangeParts[1])
			start, err := strconv.Atoi(startStr)
			if err != nil {
				return nil, fmt.Errorf("invalid start port in range %q: %w", part, err)
			}
			end, err := strconv.Atoi(endStr)
			if err != nil {
				return nil, fmt.Errorf("invalid end port in range %q: %w", part, err)
			}

			if start > end || start < 1 || end > 65535 {
				return nil, fmt.Errorf("port range %d-%d is invalid (must be 1-65535, start <= end)", start, end)
			}

			for i := start; i <= end; i++ {
				ports = append(ports, i)
			}
		} else {
			// Handle single port
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port number: %q", part)
			}

			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("port %d out of valid range (1-65535)", port)
			}

			ports = append(ports, port)
		}
	}

	// Filter out duplicates and sort for consistent output
	uniquePorts := make(map[int]bool)
	var sortedPorts []int
	for _, p := range ports {
		if !uniquePorts[p] {
			uniquePorts[p] = true
			sortedPorts = append(sortedPorts, p)
		}
	}
	sort.Ints(sortedPorts)
	return sortedPorts, nil
}

// loadPortsFromFile reads a list of port numbers from a given file, one per line.
// It ignores empty lines and lines starting with '#'.
func loadPortsFromFile(filename string) ([]int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open port file %q: %w", filename, err)
	}
	defer file.Close()

	var ports []int
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}

		port, err := strconv.Atoi(line)
		if err != nil {
			log.Printf("Warning: Skipping invalid port entry in file %q: %q (error: %v)", filename, line, err)
			continue // Log warning and skip if line is not a valid integer
		}

		if port < 1 || port > 65535 {
			log.Printf("Warning: Skipping port %d in file %q: out of valid range (1-65535)", port, filename)
			continue
		}
		ports = append(ports, port)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading port file %q: %w", filename, err)
	}

	// Filter duplicates and sort
	uniquePorts := make(map[int]bool)
	var sortedPorts []int
	for _, p := range ports {
		if !uniquePorts[p] {
			uniquePorts[p] = true
			sortedPorts = append(sortedPorts, p)
		}
	}
	sort.Ints(sortedPorts)
	return sortedPorts, nil
}

// validateHost attempts to resolve the given host string to ensure it's a valid network target.
func validateHost(host string) error {
	_, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("unable to resolve host %q: %w", host, err)
	}
	return nil
}

// generateReport converts the ScanResult into a byte slice based on the specified format.
func generateReport(scanResult ScanResult, format string) ([]byte, error) {
	var content []byte
	var err error

	switch strings.ToLower(format) {
	case "json":
		// Marshal JSON with indentation for readability
		content, err = json.MarshalIndent(scanResult, "", "  ")
	case "txt":
		content = []byte(generateTextReport(scanResult))
	case "csv":
		content = []byte(generateCSVReport(scanResult))
	default:
		return nil, fmt.Errorf("unsupported output format: %q", format)
	}

	return content, err
}

// generateTextReport creates a human-readable, multi-line text report.
func generateTextReport(scanResult ScanResult) string {
	var report strings.Builder

	report.WriteString("Port Scan Report\n")
	report.WriteString("================\n\n")
	report.WriteString(fmt.Sprintf("Target Host: %s\n", scanResult.Host))
	report.WriteString(fmt.Sprintf("Scan Time: %s\n", scanResult.StartTime.Format("2006-01-02 15:04:05 MST")))
	report.WriteString(fmt.Sprintf("Duration: %s\n", scanResult.Duration.Round(time.Millisecond))) // Round duration for clarity
	report.WriteString(fmt.Sprintf("Total Ports Scanned: %d\n", scanResult.Summary.Total))
	report.WriteString(fmt.Sprintf("Open Ports: %d\n", scanResult.Summary.Open))
	report.WriteString(fmt.Sprintf("Closed Ports: %d\n\n", scanResult.Summary.Closed))
	if scanResult.Error != "" {
		report.WriteString(fmt.Sprintf("Scan Status: Interrupted/Failed - %s\n\n", scanResult.Error))
	} else {
		report.WriteString("Scan Status: Completed Successfully\n\n")
	}

	// Filter and display open ports
	openPorts := make([]PortResult, 0)
	for _, port := range scanResult.Ports {
		if port.Status == "open" {
			openPorts = append(openPorts, port)
		}
	}

	if len(openPorts) > 0 {
		report.WriteString("Open Ports Details:\n")
		report.WriteString("-------------------\n")
		for _, port := range openPorts {
			serviceInfo := ""
			if port.Service != "" {
				serviceInfo = fmt.Sprintf(" (%s)", port.Service)
			}
			bannerInfo := ""
			if port.Banner != "" {
				bannerInfo = fmt.Sprintf(" - %q", port.Banner) // Use %q to quote banner string
			}
			report.WriteString(fmt.Sprintf("  Port %d/tcp%s - %s%s\n",
				port.Port, serviceInfo, port.Response.Round(time.Microsecond), bannerInfo)) // Microsecond for more precision
		}
		report.WriteString("\n")
	} else {
		report.WriteString("No open ports found.\n\n")
	}

	return report.String()
}

// generateCSVReport creates a CSV formatted string of the scan results.
func generateCSVReport(scanResult ScanResult) string {
	var report strings.Builder

	// CSV Header
	report.WriteString("Port,Status,Service,Response_Time,Banner\n")

	// Iterate through all results and format as CSV lines
	for _, port := range scanResult.Ports {
		// Replace commas and newlines in banner to prevent CSV parsing issues
		sanitizedBanner := strings.ReplaceAll(port.Banner, ",", ";")
		sanitizedBanner = strings.ReplaceAll(sanitizedBanner, "\n", "\\n")
		sanitizedBanner = strings.ReplaceAll(sanitizedBanner, "\r", "\\r")

		report.WriteString(fmt.Sprintf("%d,%s,%s,%s,%q\n", // %q for banner to handle internal quotes
			port.Port, port.Status, port.Service, port.Response.Round(time.Microsecond), sanitizedBanner))
	}

	return report.String()
}

//-----------------------------------------------------------------------------
// Main Function
//-----------------------------------------------------------------------------

func main() {
	// Configure logging output. All log.Print* calls will go to stdout without
	// Go's default timestamp/source information, which is beneficial for cloud logging systems.
	log.SetOutput(os.Stdout)
	log.SetFlags(0)

	// Define command-line flags
	host := flag.String("host", "localhost", "Target host to scan (e.g., example.com or 192.168.1.1)")
	portRange := flag.String("ports", "1-1024", "Port range (e.g., \"80,443,8080\" or \"1-1000\" or \"1-100,8080-8081\")")
	portFile := flag.String("port-file", "", "Path to a file containing ports to scan (one port number per line)")
	timeout := flag.Duration("timeout", 2*time.Second, "Connection timeout duration (e.g., \"500ms\", \"2s\", \"1m\")")
	threads := flag.Int("threads", runtime.NumCPU()*50, "Maximum number of concurrent goroutines for scanning")
	verbose := flag.Bool("verbose", false, "Enable verbose output to log closed ports (in addition to open ports)")
	serviceScan := flag.Bool("service", true, "Enable detection of common services based on port number")
	bannerGrab := flag.Bool("banner", false, "Enable banner grabbing to extract initial service responses")
	outputFile := flag.String("output", "", "Path to the file where scan results will be saved")
	outputFormat := flag.String("format", "txt", "Output format for the report file (available: \"txt\", \"json\", \"csv\")")

	// Custom usage message for --help
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Enhanced TCP Port Scanner\n\n")
		fmt.Fprintf(os.Stderr, "A concurrent TCP port scanner with service detection and banner grabbing capabilities.\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults() // Prints all defined flags and their default values/descriptions
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  Scan common web ports on example.com:\n")
		fmt.Fprintf(os.Stderr, "    %s -host example.com -ports 80,443,8080\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Scan a range with more threads and save JSON output:\n")
		fmt.Fprintf(os.Stderr, "    %s -host 192.168.1.1 -ports 1-1000 -threads 200 -output results.json -format json\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Scan ports from a file with banner grabbing (verbose output):\n")
		fmt.Fprintf(os.Stderr, "    %s -host target.com -port-file ports.txt -banner -verbose -output results.csv -format csv\n", os.Args[0])
	}

	flag.Parse() // Parse command-line arguments into defined flags

	// Validate the target host
	if err := validateHost(*host); err != nil {
		log.Fatalf(`{"event":"validation_error", "message":"Host resolution failed", "host":"%s", "error":"%v"}`, *host, err)
	}

	// Determine ports to scan from either range or file
	var portsToScan []int
	var err error
	if *portFile != "" {
		portsToScan, err = loadPortsFromFile(*portFile)
		if err != nil {
			log.Fatalf(`{"event":"config_error", "message":"Failed to load ports from file", "file":"%s", "error":"%v"}`, *portFile, err)
		}
	} else {
		portsToScan, err = parsePortRange(*portRange)
		if err != nil {
			log.Fatalf(`{"event":"config_error", "message":"Failed to parse port range", "range":"%s", "error":"%v"}`, *portRange, err)
		}
	}

	// Ensure there are valid ports to scan
	if len(portsToScan) == 0 {
		log.Fatalf(`{"event":"config_error", "message":"No valid ports to scan specified. Please check --ports or --port-file."}`)
	}

	// Validate thread count
	if *threads <= 0 {
		log.Fatalf(`{"event":"config_error", "message":"Thread count must be a positive integer, received: %d"}`, *threads)
	}

	// Initialize and run the scanner
	scanner := NewScanner(*host, *timeout, *threads, *verbose, *serviceScan, *bannerGrab)
	finalScanResult := scanner.Run(portsToScan)

	// Save results to file if an output path is provided
	if *outputFile != "" {
		reportContent, err := generateReport(finalScanResult, *outputFormat)
		if err != nil {
			log.Printf(`{"event":"report_error", "message":"Failed to generate report", "format":"%s", "error":"%v"}`, *outputFormat, err)
		} else {
			if err := os.WriteFile(*outputFile, reportContent, 0644); err != nil {
				log.Printf(`{"event":"file_write_error", "message":"Failed to write report to file", "file":"%s", "error":"%v"}`, *outputFile, err)
			} else {
				log.Printf(`{"event":"report_saved", "message":"Scan report successfully saved", "file":"%s", "format":"%s"}`, *outputFile, *outputFormat)
			}
		}
	} else {
		// If no output file is specified, print a user-friendly summary to standard output
		fmt.Println("\n--- Scan Summary ---")
		fmt.Printf("Target Host: %s\n", finalScanResult.Host)
		fmt.Printf("Scan Duration: %s\n", finalScanResult.Duration.Round(time.Millisecond))
		fmt.Printf("Ports Scanned: %d\n", finalScanResult.Summary.Total)
		fmt.Printf("Open Ports: %d\n", finalScanResult.Summary.Open)
		if finalScanResult.Error != "" {
			fmt.Printf("Scan Status: %s\n", finalScanResult.Error)
		} else {
			fmt.Println("Scan Status: Completed")
		}

		if finalScanResult.Summary.Open > 0 {
			fmt.Println("\nOpen Ports:")
			for _, port := range finalScanResult.Ports {
				if port.Status == "open" {
					serviceInfo := ""
					if port.Service != "" {
						serviceInfo = fmt.Sprintf(" (%s)", port.Service)
					}
					bannerInfo := ""
					if port.Banner != "" {
						bannerInfo = fmt.Sprintf(" - %q", port.Banner)
					}
					fmt.Printf("  %d/tcp%s - %s%s\n", port.Port, serviceInfo, port.Response.Round(time.Microsecond), bannerInfo)
				}
			}
		} else {
			fmt.Println("No open ports found.")
		}
		fmt.Println("--------------------")
	}
}
