package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag" // Used for command-line arguments
	"fmt"
	"html/template" // Used for web UI templates
	"log"
	"net"
	"net/http" // Used for web UI server
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

//-----------------------------------------------------------------------------
// Core Port Scanner Data Structures
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

// FullScanResult aggregates the results of an entire scan operation.
type FullScanResult struct {
	Host      string          `json:"host"`            // The target host that was scanned
	StartTime time.Time       `json:"start_time"`      // When the scan began
	EndTime   time.Time       `json:"end_time"`        // When the scan finished
	Duration  time.Duration   `json:"duration"`        // Total duration of the scan
	Ports     []PortResult    `json:"ports"`           // List of individual port scan results
	Summary   PortScanSummary `json:"summary"`         // Statistical summary of the scan
	Error     string          `json:"error,omitempty"` // Any error encountered during the overall scan
}

// PortScanSummary provides statistics about the scanned ports.
type PortScanSummary struct {
	Total  int `json:"total_scanned"` // Total number of ports attempted
	Open   int `json:"open_ports"`    // Number of open ports found
	Closed int `json:"closed_ports"`  // Number of closed ports encountered
}

// PortScanner manages the overall port scanning operation.
type PortScanner struct {
	host        string
	timeout     time.Duration
	threads     int
	verbose     bool
	serviceScan bool
	bannerGrab  bool
	results     []PortResult       // Stores the results of each port scan
	mu          sync.RWMutex       // Mutex to protect access to 'results' slice
	ctx         context.Context    // Context for cancellation of internal goroutines
	cancel      context.CancelFunc // Function to cancel the internal context
}

//-----------------------------------------------------------------------------
// Web UI Related Data Structures
//-----------------------------------------------------------------------------

// TemplateData for rendering the HTML UI.
type TemplateData struct {
	Title string
	// ScanResult is now a pointer to FullScanResult
	ScanResult     *FullScanResult
	Error          string // Any error message to display in the UI
	HostInput      string // Value to pre-fill the host input field
	PortsInput     string // Value to pre-fill the ports input field
	ThreadsInput   string // Value to pre-fill the threads input field
	TimeoutInput   string // Value to pre-fill the timeout input field
	BannerChecked  bool   // To control the banner grabbing checkbox state
	ServiceChecked bool   // To control the service detection checkbox state
}

//-----------------------------------------------------------------------------
// Global Constants & Mappings
//-----------------------------------------------------------------------------

// commonServices maps well-known port numbers to their standard service names.
var commonServices = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
	80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
	443: "HTTPS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
	3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
	8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}

// templates holds our parsed HTML templates for the UI.
var templates *template.Template

//-----------------------------------------------------------------------------
// Port Scanner Methods
//-----------------------------------------------------------------------------

// NewPortScanner creates and returns a new PortScanner instance, initialized with the
// provided scanning parameters and a cancellable context.
func NewPortScanner(host string, timeout time.Duration, threads int, verbose, serviceScan, bannerGrab bool) *PortScanner {
	// Context for the *scanner's internal goroutines*, not the main server lifecycle
	ctx, cancel := context.WithCancel(context.Background())
	return &PortScanner{
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

// NewPortScannerWithContext creates a PortScanner with a provided context for cancellation
func NewPortScannerWithContext(ctx context.Context, host string, timeout time.Duration, threads int, verbose, serviceScan, bannerGrab bool) *PortScanner {
	scanCtx, cancel := context.WithCancel(ctx)
	return &PortScanner{
		host:        host,
		timeout:     timeout,
		threads:     threads,
		verbose:     verbose,
		serviceScan: serviceScan,
		bannerGrab:  bannerGrab,
		results:     make([]PortResult, 0),
		ctx:         scanCtx,
		cancel:      cancel,
	}
}

// grabBanner attempts to read and return the initial banner from an open connection.
// It applies a short read deadline to prevent hanging on unresponsive services.
func (ps *PortScanner) grabBanner(conn net.Conn) string {
	if !ps.bannerGrab {
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
func (ps *PortScanner) scanPort(port int, sem chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()          // Decrement the WaitGroup counter when done
	defer func() { <-sem }() // Release a slot in the semaphore when done

	// Check if the scan has been cancelled before attempting connection
	select {
	case <-ps.ctx.Done():
		return // Exit if context is cancelled
	default:
		// Continue if context is not cancelled
	}

	startTime := time.Now()
	address := fmt.Sprintf("%s:%d", ps.host, port)

	// Attempt to establish a TCP connection with a timeout
	conn, err := net.DialTimeout("tcp", address, ps.timeout)
	responseTime := time.Since(startTime)

	result := PortResult{ // Use PortResult
		Port:      port,
		Response:  responseTime,
		Timestamp: time.Now(),
	}

	if err != nil {
		// Port is closed or unreachable
		result.Status = "closed"
		if ps.verbose {
			// Log closed ports in JSON format for cloud logging (CLI only usually)
			log.Printf(`{"event":"scan_result", "host":"%s", "port":%d, "status":"closed", "response_time":"%s", "error":"%v"}`,
				ps.host, port, responseTime, err)
		}
	} else {
		// Port is open
		result.Status = "open"

		// Detect common service if enabled
		if ps.serviceScan {
			if service, exists := commonServices[port]; exists {
				result.Service = service
			}
		}

		// Grab banner if enabled
		result.Banner = ps.grabBanner(conn)
		conn.Close() // Close the connection immediately after use

		// Log open ports in JSON format for cloud logging
		log.Printf(`{"event":"scan_result", "host":"%s", "port":%d, "status":"open", "service":"%s", "response_time":"%s", "banner":"%s"}`,
			ps.host, port, result.Service, responseTime, strings.ReplaceAll(result.Banner, "\n", "\\n"))
	}

	// Safely add result to the shared slice
	ps.mu.Lock()
	ps.results = append(ps.results, result)
	ps.mu.Unlock()
}

// Run initiates and manages the port scanning process.
// It takes a list of ports to scan and returns the complete FullScanResult.
func (ps *PortScanner) Run(ports []int) FullScanResult { // Return FullScanResult
	startTime := time.Now()
	var scanError error // To capture any error that might interrupt the scan

	// Setup internal cancellation via context
	// For CLI, this allows Ctrl+C to stop it. For UI, the request context drives it.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Goroutine to listen for cancellation signals
	go func() {
		select {
		case <-sigChan:
			log.Println(`{"event":"scan_interruption", "message":"Scan interrupted by user signal"}`)
			ps.cancel() // Signal the scanner's context to cancel
		case <-ps.ctx.Done():
			// Context was cancelled externally (e.g., by HTTP request cancellation in UI mode)
			log.Println(`{"event":"scan_interruption", "message":"Scan context cancelled internally"}`)
		}
	}()

	// Initial logging of scan parameters
	log.Printf(`{"event":"scan_start", "host":"%s", "ports_to_scan":%d, "threads":%d, "timeout":"%s", "service_detection":%t, "banner_grabbing":%t}`,
		ps.host, len(ports), ps.threads, ps.timeout, ps.serviceScan, ps.bannerGrab)
	// In UI mode, this message is not typically shown directly to user, but goes to logs.
	// In CLI mode, the "Press Ctrl+C" message would be printed here.

	// Semaphore to limit concurrent goroutines
	sem := make(chan struct{}, ps.threads)
	var wg sync.WaitGroup // WaitGroup to wait for all goroutines to finish

	// Iterate over each port and start a scan goroutine
	for _, port := range ports {
		// Check for cancellation before launching new goroutine
		select {
		case <-ps.ctx.Done():
			scanError = ps.ctx.Err() // Capture the cancellation error
			goto EndScan             // Jump to the cleanup section
		default:
			// Continue if context is not cancelled
		}

		wg.Add(1)                      // Increment WaitGroup counter for each new goroutine
		sem <- struct{}{}              // Acquire a slot in the semaphore (blocks if full)
		go ps.scanPort(port, sem, &wg) // Launch port scan in a new goroutine
	}

	wg.Wait() // Wait for all scan goroutines to complete

EndScan: // Label for the goto statement on cancellation
	endTime := time.Now()
	duration := endTime.Sub(startTime)

	// Safely retrieve and sort the results
	ps.mu.RLock() // Acquire read lock before accessing results
	sortedResults := make([]PortResult, len(ps.results))
	copy(sortedResults, ps.results)
	ps.mu.RUnlock() // Release read lock

	sort.Slice(sortedResults, func(i, j int) bool {
		return sortedResults[i].Port < sortedResults[j].Port
	})

	// Calculate scan summary
	summary := PortScanSummary{Total: len(sortedResults)}
	for _, res := range sortedResults {
		if res.Status == "open" {
			summary.Open++
		} else {
			summary.Closed++
		}
	}

	// Assemble the final FullScanResult
	result := FullScanResult{ // Use FullScanResult
		Host:      ps.host,
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
		result.Host, func() string {
			if scanError != nil {
				return "interrupted"
			}
			return "completed"
		}(), duration, summary.Open, summary.Total, result.Error)

	return result
}

//-----------------------------------------------------------------------------
// Helper Functions (for both CLI and UI)
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

// generateReport converts the FullScanResult into a byte slice based on the specified format.
// (This is primarily for CLI output, not used by the integrated UI directly)
func generateReport(scanResult FullScanResult, format string) ([]byte, error) {
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
func generateTextReport(scanResult FullScanResult) string {
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
func generateCSVReport(scanResult FullScanResult) string {
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
// Web UI Handlers & Helpers (Integrated)
//-----------------------------------------------------------------------------

// handleHome serves the main page with the scan input form for the UI mode.
func handleHome(w http.ResponseWriter, r *http.Request) {
	// Only serve "/" path, redirect others or show 404
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	data := TemplateData{
		Title:          "Go Port Scanner UI",
		HostInput:      "scanme.nmap.org", // Default values for convenience
		PortsInput:     "80,443,22",
		ThreadsInput:   "100",
		TimeoutInput:   "2s",
		ServiceChecked: true,  // Default to checked
		BannerChecked:  false, // Default to unchecked
	}
	renderTemplate(w, "index.html", data)
}

// handleScan processes the scan request from the UI, executes the integrated scanner logic,
// and renders the results.
func handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form values
	host := r.FormValue("host")
	portsStr := r.FormValue("ports")
	threadsStr := r.FormValue("threads")
	timeoutStr := r.FormValue("timeout")
	banner := r.FormValue("banner")   // "on" if checked, "" otherwise
	service := r.FormValue("service") // "on" if checked, "" otherwise

	// Initialize template data with submitted inputs for persistence
	data := TemplateData{
		Title:          "Go Port Scanner UI", // Will be updated to results title
		HostInput:      host,
		PortsInput:     portsStr,
		ThreadsInput:   threadsStr,
		TimeoutInput:   timeoutStr,
		BannerChecked:  banner == "on",
		ServiceChecked: service == "on",
	}

	// Basic input validation
	if host == "" || portsStr == "" {
		data.Error = "Host and Ports are required."
		renderTemplate(w, "index.html", data)
		return
	}

	// Parse threads (use default if empty or invalid)
	threads := runtime.NumCPU() * 50 // Default
	if t, err := strconv.Atoi(threadsStr); err == nil && t > 0 {
		threads = t
	}

	// Parse timeout (use default if empty or invalid)
	timeout := 2 * time.Second // Default
	if t, err := time.ParseDuration(timeoutStr); err == nil && t > 0 {
		timeout = t
	}

	// Validate host (DNS resolution)
	if err := validateHost(host); err != nil {
		data.Error = fmt.Sprintf("Host validation failed: %v", err)
		renderTemplate(w, "index.html", data)
		return
	}

	// Parse ports string into a slice of integers
	ports, err := parsePortRange(portsStr)
	if err != nil {
		data.Error = fmt.Sprintf("Invalid port range/list: %v", err)
		renderTemplate(w, "index.html", data)
		return
	}
	if len(ports) == 0 {
		data.Error = "No valid ports to scan after parsing. Please provide a valid range or list."
		renderTemplate(w, "index.html", data)
		return
	}

	log.Printf("INFO: Web-triggered scan for host: %s, ports: %s (threads: %d, timeout: %s, banner: %t, service: %t)",
		host, portsStr, threads, timeout.String(), data.BannerChecked, data.ServiceChecked)

	// Create and run the PortScanner instance using the HTTP request's context
	portScanner := NewPortScannerWithContext(r.Context(), host, timeout, threads, false, data.ServiceChecked, data.BannerChecked) // verbose false for UI
	fullScanResult := portScanner.Run(ports)                                                                                      // This executes the scan directly

	data.ScanResult = &fullScanResult                          // Attach the scan result to template data
	data.Title = fmt.Sprintf("Port Scan Results for %s", host) // Update page title

	if fullScanResult.Error != "" {
		data.Error = fullScanResult.Error // Display scanner errors in UI
	}

	// Render the template with the results (or error message)
	renderTemplate(w, "index.html", data)
}

// renderTemplate parses and executes the specified HTML template.
func renderTemplate(w http.ResponseWriter, tmpl string, data TemplateData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := templates.ExecuteTemplate(w, tmpl, data)
	if err != nil {
		log.Printf("Error executing template %s: %v", tmpl, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// createDefaultTemplate creates a simple HTML template for the UI.
// This function will be called once if the templates/index.html file is missing.
func createDefaultTemplate(filename string) error {
	content := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        body { 
            font-family: sans-serif; 
            margin: 20px; 
            background-color: #f4f4f4; 
            color: #333; 
            line-height: 1.6;
        }
        .container { 
            max-width: 900px; 
            margin: 0 auto; 
            background-color: #fff; 
            padding: 20px; 
            border-radius: 8px; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); 
        }
        h1, h2 { color: #0056b3; }
        .form-section { 
            margin-bottom: 30px; 
            padding: 20px; 
            border: 1px solid #ddd; 
            border-radius: 8px; 
            background-color: #e9f0f7; 
        }
        .form-section label { 
            display: block; 
            margin-bottom: 5px; 
            font-weight: bold; 
        }
        .form-section input[type="text"],
        .form-section input[type="number"] {
            width: calc(100% - 22px);
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 4px;
            margin-bottom: 10px;
        }
        .form-section button { 
            background-color: #007bff; 
            color: white; 
            padding: 10px 20px; 
            border: none; 
            border-radius: 4px; 
            cursor: pointer; 
            font-size: 16px; 
        }
        .form-section button:hover { background-color: #0056b3; }
        .checkbox-group { 
            display: flex; 
            align-items: center; 
            margin-bottom: 10px; 
        }
        .checkbox-group label { 
            margin-bottom: 0; 
            margin-left: 5px; 
        }
        .error-message { 
            color: red; 
            background-color: #ffe0e0; 
            border: 1px solid red; 
            padding: 10px; 
            border-radius: 5px; 
            margin-bottom: 20px; 
        }
        .results-section { 
            margin-top: 30px; 
            border-top: 2px solid #0056b3; 
            padding-top: 20px; 
        }
        .summary-box { 
            display: flex; 
            justify-content: space-around; 
            background-color: #f0f8ff; 
            padding: 15px; 
            border-radius: 8px; 
            margin-bottom: 20px; 
            border: 1px solid #cfe2ff; 
            flex-wrap: wrap; 
        }
        .summary-item { 
            text-align: center; 
            margin: 5px 10px; 
        }
        .summary-item strong { 
            display: block; 
            font-size: 1.2em; 
            color: #007bff; 
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin-top: 20px; 
        }
        th, td { 
            border: 1px solid #ddd; 
            padding: 8px; 
            text-align: left; 
        }
        th { background-color: #e2e2e2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .status-open { color: green; font-weight: bold; }
        .status-closed { color: gray; }
        .no-results { 
            text-align: center; 
            color: #666; 
            font-style: italic; 
        }
        pre { 
            background-color: #eee; 
            padding: 10px; 
            border-radius: 4px; 
            overflow-x: auto; 
            white-space: pre-wrap; 
            word-break: break-all; 
            font-size: 0.9em; 
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>{{.Title}}</h1>

        <div class="form-section">
            <h2>Start a New Port Scan</h2>
            {{if .Error}}
            <div class="error-message">{{.Error}}</div>
            {{end}}
            <form action="/scan" method="POST">
                <label for="host">Target Host (IP or Domain):</label>
                <input type="text" id="host" name="host" value="{{.HostInput}}" placeholder="e.g., scanme.nmap.org" required>

                <label for="ports">Ports (e.g., 80,443,1-1000):</label>
                <input type="text" id="ports" name="ports" value="{{.PortsInput}}" placeholder="e.g., 1-1024,8080" required>

                <label for="threads">Concurrent Threads:</label>
                <input type="number" id="threads" name="threads" value="{{.ThreadsInput}}" min="1" placeholder="e.g., 100">

                <label for="timeout">Connection Timeout (e.g., 500ms, 2s, 1m):</label>
                <input type="text" id="timeout" name="timeout" value="{{.TimeoutInput}}" placeholder="e.g., 2s">

                <div class="checkbox-group">
                    <input type="checkbox" id="service" name="service" {{if .ServiceChecked}}checked{{end}}>
                    <label for="service">Enable Service Detection</label>
                </div>

                <div class="checkbox-group">
                    <input type="checkbox" id="banner" name="banner" {{if .BannerChecked}}checked{{end}}>
                    <label for="banner">Enable Banner Grabbing</label>
                </div>

                <button type="submit">Scan Now</button>
            </form>
        </div>

        {{if .ScanResult}}
        <div class="results-section">
            <h2>Results for {{.ScanResult.Host}}</h2>
            <p><strong>Started:</strong> {{.ScanResult.StartTime.Format "2006-01-02 15:04:05 MST"}}</p>
            <p><strong>Finished:</strong> {{.ScanResult.EndTime.Format "2006-01-02 15:04:05 MST"}}</p>
            <p><strong>Duration:</strong> {{.ScanResult.Duration}}</p>
            {{if .ScanResult.Error}}
            <p class="error-message"><strong>Scan Error:</strong> {{.ScanResult.Error}}</p>
            {{end}}

            <div class="summary-box">
                <div class="summary-item">Total Ports: <strong>{{.ScanResult.Summary.Total}}</strong></div>
                <div class="summary-item">Open Ports: <strong style="color: green;">{{.ScanResult.Summary.Open}}</strong></div>
                <div class="summary-item">Closed Ports: <strong style="color: gray;">{{.ScanResult.Summary.Closed}}</strong></div>
            </div>

            <h3>Port Details:</h3>
            {{if .ScanResult.Ports}}
            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Status</th>
                        <th>Service</th>
                        <th>Response Time</th>
                        <th>Banner</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .ScanResult.Ports}}
                    <tr>
                        <td>{{.Port}}</td>
                        <td class="status-{{.Status}}">{{.Status}}</td>
                        <td>{{if .Service}}{{.Service}}{{else}}Unknown{{end}}</td>
                        <td>{{.Response}}</td>
                        <td>{{if .Banner}}<pre>{{.Banner}}</pre>{{else}}-{{end}}</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
            {{else}}
            <p class="no-results">No results to display.</p>
            {{end}}
        </div>
        {{end}}
    </div>
</body>
</html>`
	return os.WriteFile(filename, []byte(content), 0644)
}

//-----------------------------------------------------------------------------
// Main Function (Unified CLI & UI)
//-----------------------------------------------------------------------------

func main() {
	// Configure logging output. All log.Print* calls will go to stdout without
	// Go's default timestamp/source information, which is beneficial for cloud logging systems.
	log.SetOutput(os.Stdout)
	log.SetFlags(0)

	// Define command-line flags
	hostCLI := flag.String("host", "", "Target host to scan (CLI only)")
	portRangeCLI := flag.String("ports", "", "Port range (CLI only)")
	portFileCLI := flag.String("port-file", "", "File containing ports to scan (CLI only)")
	timeoutCLI := flag.Duration("timeout", 2*time.Second, "Connection timeout duration (CLI only)")
	threadsCLI := flag.Int("threads", runtime.NumCPU()*50, "Maximum concurrent goroutines for scanning (CLI only)")
	verboseCLI := flag.Bool("verbose", false, "Enable verbose output to log closed ports (CLI only)")
	serviceScanCLI := flag.Bool("service", true, "Enable service detection (CLI only)")
	bannerGrabCLI := flag.Bool("banner", false, "Enable banner grabbing (CLI only)")
	outputFileCLI := flag.String("output", "", "Path to the file where scan results will be saved (CLI only)")
	outputFormatCLI := flag.String("format", "txt", "Output format for the report file (CLI only: \"txt\", \"json\", \"csv\")")

	runUI := flag.Bool("ui", false, "Run as a web UI server on :8080 (CLI flags ignored)")
	uiPort := flag.String("ui-port", "8080", "Port for the web UI server to listen on (UI mode only)")

	// Custom usage message for --help
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Enhanced TCP Port Scanner (CLI & Web UI)\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Modes:\n")
		fmt.Fprintf(os.Stderr, "  Default (CLI Mode): Performs a single scan and exits.\n")
		fmt.Fprintf(os.Stderr, "  Web UI Mode: Runs a local web server to provide a graphical interface for scanning.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults() // Prints all defined flags and their default values/descriptions
		fmt.Fprintf(os.Stderr, "\nCLI Mode Examples:\n")
		fmt.Fprintf(os.Stderr, "  Scan common web ports on example.com:\n")
		fmt.Fprintf(os.Stderr, "    %s -host example.com -ports 80,443,8080\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Scan a range with more threads and save JSON output:\n")
		fmt.Fprintf(os.Stderr, "    %s -host 192.168.1.1 -ports 1-1000 -threads 200 -output results.json -format json\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Web UI Mode Examples:\n")
		fmt.Fprintf(os.Stderr, "  Run UI on default port 8080:\n")
		fmt.Fprintf(os.Stderr, "    %s -ui\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Run UI on a custom port 9000:\n")
		fmt.Fprintf(os.Stderr, "    %s -ui -ui-port 9000\n", os.Args[0])
	}

	flag.Parse() // Parse command-line arguments into defined flags

	if *runUI {
		// --- Run as Web UI Server ---
		log.Printf("INFO: Starting web UI server on :%s", *uiPort)

		// Explicitly "use" CLI-only flags to satisfy the compiler when in UI mode.
		// These variables are always declared due to flag.String/flag.Duration/flag.Int calls.
		// We dereference them once and assign to `_` to signal to the compiler they are used.
		_ = *hostCLI
		_ = *portRangeCLI
		_ = *portFileCLI
		_ = *timeoutCLI
		_ = *threadsCLI
		_ = *verboseCLI
		_ = *serviceScanCLI
		_ = *bannerGrabCLI
		_ = *outputFileCLI
		_ = *outputFormatCLI

		// Create 'templates' directory if it doesn't exist
		templatesDir := "templates"
		if err := os.MkdirAll(templatesDir, 0755); err != nil {
			log.Fatalf(`{"event":"startup_error", "message":"Failed to create templates directory", "dir":"%s", "error":"%v"}`, templatesDir, err)
		}

		// Create default 'index.html' template if it's missing or remove existing corrupted one
		defaultTemplatePath := filepath.Join(templatesDir, "index.html")

		// Always remove and recreate the template to avoid corruption issues
		if _, err := os.Stat(defaultTemplatePath); err == nil {
			log.Printf("INFO: Removing existing template %q to recreate it...", defaultTemplatePath)
			os.Remove(defaultTemplatePath)
		}

		log.Printf("INFO: Creating fresh template %q...", defaultTemplatePath)
		if err := createDefaultTemplate(defaultTemplatePath); err != nil {
			log.Fatalf(`{"event":"startup_error", "message":"Failed to create default index.html template", "file":"%s", "error":"%v"}`, defaultTemplatePath, err)
		}

		// Parse all HTML templates from the 'templates' directory
		var err error
		templates, err = template.ParseGlob(filepath.Join(templatesDir, "*.html"))
		if err != nil {
			log.Fatalf(`{"event":"startup_error", "message":"Failed to parse templates", "dir":"%s", "error":"%v"}`, templatesDir, err)
		}
		log.Println("INFO: Templates loaded successfully for UI.")

		// Register HTTP Handlers for the UI
		http.HandleFunc("/", handleHome)
		http.HandleFunc("/scan", handleScan) // This handles the scan submission

		log.Printf("INFO: Web UI server listening on http://localhost:%s", *uiPort)
		// This blocks forever, serving HTTP requests. No explicit top-level context/cancel needed here.
		log.Fatal(http.ListenAndServe(":"+*uiPort, nil))

	} else {
		// --- Run as CLI Tool ---
		log.Println("INFO: Running in CLI mode.")
		// Check if host is provided for CLI mode
		if *hostCLI == "" {
			fmt.Fprintf(os.Stderr, "Error: --host is required in CLI mode. Use -h for help.\n")
			os.Exit(1)
		}

		if *portRangeCLI == "" && *portFileCLI == "" {
			fmt.Fprintf(os.Stderr, "Error: Either --ports or --port-file is required in CLI mode. Use -h for help.\n")
			os.Exit(1)
		}

		// Validate the target host
		if err := validateHost(*hostCLI); err != nil {
			log.Fatalf(`{"event":"validation_error", "message":"Host resolution failed", "host":"%s", "error":"%v"}`, *hostCLI, err)
		}

		// Determine ports to scan from either range or file
		var portsToScan []int
		var err error
		if *portFileCLI != "" {
			portsToScan, err = loadPortsFromFile(*portFileCLI)
			if err != nil {
				log.Fatalf(`{"event":"config_error", "message":"Failed to load ports from file", "file":"%s", "error":"%v"}`, *portFileCLI, err)
			}
		} else {
			portsToScan, err = parsePortRange(*portRangeCLI)
			if err != nil {
				log.Fatalf(`{"event":"config_error", "message":"Failed to parse port range", "range":"%s", "error":"%v"}`, *portRangeCLI, err)
			}
		}

		// Ensure there are valid ports to scan
		if len(portsToScan) == 0 {
			log.Fatalf(`{"event":"config_error", "message":"No valid ports to scan specified. Please check --ports or --port-file."}`)
		}

		// Validate thread count
		if *threadsCLI <= 0 {
			log.Fatalf(`{"event":"config_error", "message":"Thread count must be a positive integer, received: %d"}`, *threadsCLI)
		}

		// Initialize and run the scanner
		// In CLI mode, we can show verbose output if requested
		scanner := NewPortScanner(*hostCLI, *timeoutCLI, *threadsCLI, *verboseCLI, *serviceScanCLI, *bannerGrabCLI)
		finalScanResult := scanner.Run(portsToScan)

		// Save results to file if an output path is provided
		if *outputFileCLI != "" {
			reportContent, err := generateReport(finalScanResult, *outputFormatCLI)
			if err != nil {
				log.Printf(`{"event":"report_error", "message":"Failed to generate report", "format":"%s", "error":"%v"}`, *outputFormatCLI, err)
			} else {
				if err := os.WriteFile(*outputFileCLI, reportContent, 0644); err != nil {
					log.Printf(`{"event":"file_write_error", "message":"Failed to write report to file", "file":"%s", "error":"%v"}`, *outputFileCLI, err)
				} else {
					log.Printf(`{"event":"report_saved", "message":"Scan report successfully saved", "file":"%s", "format":"%s"}`, *outputFileCLI, *outputFormatCLI)
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
}
