package main
import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type FirewallConfig struct {
	BlockedPorts                  []int  `json:"blocked_ports"`
	ConnectionLogPath             string `json:"connection_log_path"`
	DatabaseName                  string `json:"database_name"`
	PortScanThreshold             int    `json:"port_scan_threshold"`
	PortScanWindowMinutes         int    `json:"port_scan_window_minutes"`
	RepeatOffenderSuspiciousCount int    `json:"repeat_offender_suspicious_count"`
	RepeatOffenderBlockCount      int    `json:"repeat_offender_block_count"`
	MaxRecordsBeforeCleanup       int    `json:"max_records_before_cleanup"`
}

type FirewallCounts struct {
	Allowed   int
	Blocked   int
	PortScans int
}

type PortAttempt struct {
	Port int
	Time time.Time
}

func main() {
	fmt.Println("--- ALINA'S LIVE PORT SECURITY SYSTEM ---")
	fmt.Println()

	config, err := loadFirewallConfig("firewall_config.json")
	if err != nil {
		fmt.Println("Error loading config:", err)
		return
	}

	logFile, err := os.Open(config.ConnectionLogPath)
	if err != nil {
		fmt.Println("Error: could not open", config.ConnectionLogPath)
		return
	}
	defer logFile.Close()

	reportFile, err := os.Create("output.txt")
	if err != nil {
		fmt.Println("Error creating output report file")
		return
	}
	defer reportFile.Close()
	reportWriter := bufio.NewWriter(reportFile)

	blocklistFile, err := os.Create("blocked_source_ips.txt")
	if err != nil {
		fmt.Println("Error creating blocklist file")
		return
	}
	defer blocklistFile.Close()
	blocklistWriter := bufio.NewWriter(blocklistFile)

	db, err := sql.Open("sqlite", config.DatabaseName)
	if err != nil {
		fmt.Println("Error opening database:", err)
		return
	}
	defer db.Close()

	createTableSQL := `
	CREATE TABLE IF NOT EXISTS firewall_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		event_type TEXT,
		source_ip TEXT,
		port INTEGER,
		event_time TEXT
	);`
	_, err = db.Exec(createTableSQL)
	if err != nil {
		fmt.Println("Error creating table:", err)
		return
	}

	counts := FirewallCounts{}
	ipPortAttempts := make(map[string][]PortAttempt)
	flaggedScanIPs := make(map[string]bool)
	ipBlockedAttemptTimes := make(map[string][]time.Time)
	suspiciousIPs := make(map[string]bool)
	blockedSourceIPs := make(map[string]bool)

	loadPreviouslyBlockedIPs(db, blockedSourceIPs)

	reader := bufio.NewReader(logFile)
	for {
		line, err := reader.ReadString('\n')

		if len(line) > 0 {
			cleanLine := strings.TrimRight(line, "\r\n")
			if strings.TrimSpace(cleanLine) != "" {
				processConnectionLine(cleanLine, config, &counts, db,
					reportWriter, blocklistWriter,
					ipPortAttempts, flaggedScanIPs,
					ipBlockedAttemptTimes, suspiciousIPs, blockedSourceIPs)

				cleanupOldFirewallRecords(db, config.MaxRecordsBeforeCleanup)
			}
		}

		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Println("Error reading file:", err)
			break
		}
	}

	fmt.Println()
	fmt.Println("\t\t\t---------- Firewall Summary ----------")
	fmt.Printf("Allowed connections: %d\n", counts.Allowed)
	fmt.Printf("Blocked connections: %d\n", counts.Blocked)
	fmt.Printf("Port scans detected: %d\n", counts.PortScans)

	reportWriter.WriteString("\n\t\t\t---------- Firewall Summary ----------\n")
	reportWriter.WriteString(fmt.Sprintf("Allowed connections: %d\n", counts.Allowed))
	reportWriter.WriteString(fmt.Sprintf("Blocked connections: %d\n", counts.Blocked))
	reportWriter.WriteString(fmt.Sprintf("Port scans detected: %d\n", counts.PortScans))

	reportWriter.WriteString("\n\t\t\t---------- Suspicious IPs ----------\n")
	for ip := range suspiciousIPs {
		reportWriter.WriteString(ip + "\n")
	}

	reportWriter.WriteString("\n\t\t\t---------- Blocked IPs ----------\n")
	for ip := range blockedSourceIPs {
		reportWriter.WriteString(ip + "\n")
	}

	reportWriter.Flush()
	blocklistWriter.Flush()

	fmt.Println()
	fmt.Println("Full report saved to output.txt")
	fmt.Println("Blocked source IPs saved to blocked_source_ips.txt")
	fmt.Println("All events also saved to", config.DatabaseName)
}

func processConnectionLine(
	line string,
	config FirewallConfig,
	counts *FirewallCounts,
	db *sql.DB,
	reportWriter *bufio.Writer,
	blocklistWriter *bufio.Writer,
	ipPortAttempts map[string][]PortAttempt,
	flaggedScanIPs map[string]bool,
	ipBlockedAttemptTimes map[string][]time.Time,
	suspiciousIPs map[string]bool,
	blockedSourceIPs map[string]bool,
) {
	parts := strings.Split(line, " ")
	if len(parts) < 4 {
		return
	}

	timestampText := parts[0] + " " + parts[1]
	sourceIP := parts[2]

	if blockedSourceIPs[sourceIP] {
		return
	}

	port, convErr := strconv.Atoi(parts[3])
	if convErr != nil {
		return
	}

	eventTime, parseErr := time.Parse("2006-01-02 15:04:05", timestampText)
	if parseErr != nil {
		eventTime, parseErr = time.Parse("2006/01/02 15:04:05", timestampText)
		if parseErr != nil {
			fmt.Println("WARNING: could not read timestamp format, skipping entry line:", line)
			return
		}
	}

	isBlocked := checkPort(port, config.BlockedPorts, counts)

	if isBlocked {
		fmt.Printf("\a WARNING: Connection to port %d from %s is BLOCKED! (dangerous port)\n", port, sourceIP)
		reportWriter.WriteString(fmt.Sprintf("BLOCKED: %s tried port %d at %s\n", sourceIP, port, timestampText))
		
		reportWriter.Flush() 
		
		saveFirewallEvent(db, "blocked_port", sourceIP, port, timestampText)

		windowDuration := time.Duration(config.PortScanWindowMinutes) * time.Minute
		validTimes := []time.Time{}
		for _, t := range ipBlockedAttemptTimes[sourceIP] {
			if eventTime.Sub(t) <= windowDuration {
				validTimes = append(validTimes, t)
			}
		}
		validTimes = append(validTimes, eventTime)
		ipBlockedAttemptTimes[sourceIP] = validTimes

		if len(validTimes) >= config.RepeatOffenderBlockCount {
			if !blockedSourceIPs[sourceIP] {
				blockedSourceIPs[sourceIP] = true
				fmt.Printf("\a SOURCE IP BLOCKED: %s hit dangerous ports %d times — entire IP now blocked\n", sourceIP, len(validTimes))
				reportWriter.WriteString(fmt.Sprintf("IP BLOCKED: %s — %d dangerous port attempts\n", sourceIP, len(validTimes)))
				reportWriter.Flush()
				blocklistWriter.WriteString(sourceIP + "\n")
				blocklistWriter.Flush()
				saveFirewallEvent(db, "ip_blocked", sourceIP, 0, timestampText)
			}
		} else if len(validTimes) >= config.RepeatOffenderSuspiciousCount {
			if !suspiciousIPs[sourceIP] {
				suspiciousIPs[sourceIP] = true
				fmt.Printf("\a SUSPICIOUS: %s hit dangerous ports %d times — now being watched closely\n", sourceIP, len(validTimes))
				reportWriter.WriteString(fmt.Sprintf("SUSPICIOUS: %s — %d dangerous port attempts\n", sourceIP, len(validTimes)))
				reportWriter.Flush()
			}
		}
	} else {
		fmt.Printf("SAFE: Connection from %s on port %d allowed.\n", sourceIP, port)
		reportWriter.WriteString(fmt.Sprintf("ALLOWED: %s used port %d at %s\n", sourceIP, port, timestampText))
		reportWriter.Flush()
	}

	windowDuration := time.Duration(config.PortScanWindowMinutes) * time.Minute
	validAttempts := []PortAttempt{}
	for _, attempt := range ipPortAttempts[sourceIP] {
		if eventTime.Sub(attempt.Time) <= windowDuration {
			validAttempts = append(validAttempts, attempt)
		}
	}

	alreadyTried := false
	for _, attempt := range validAttempts {
		if attempt.Port == port {
			alreadyTried = true
		}
	}
	if alreadyTried == false {
		validAttempts = append(validAttempts, PortAttempt{Port: port, Time: eventTime})
	}
	ipPortAttempts[sourceIP] = validAttempts

	if len(validAttempts) >= config.PortScanThreshold {
		if !flaggedScanIPs[sourceIP] {
			flaggedScanIPs[sourceIP] = true
			counts.PortScans++
			fmt.Printf("\a PORT SCAN DETECTED: %s tried %d different ports within %d minutes!\n", sourceIP, len(validAttempts), config.PortScanWindowMinutes)
			reportWriter.WriteString(fmt.Sprintf("PORT SCAN: %s tried %d ports within %d minutes\n", sourceIP, len(validAttempts), config.PortScanWindowMinutes))
			reportWriter.Flush()
			saveFirewallEvent(db, "port_scan", sourceIP, 0, timestampText)
		}
	}
}

func loadFirewallConfig(path string) (FirewallConfig, error) {
	var config FirewallConfig
	data, err := os.ReadFile(path)
	if err != nil {
		return config, err
	}
	err = json.Unmarshal(data, &config)
	return config, err
}

func checkPort(port int, blockedPorts []int, counts *FirewallCounts) bool {
	for _, blocked := range blockedPorts {
		if port == blocked {
			counts.Blocked++
			return true
		}
	}
	counts.Allowed++
	return false
}

func saveFirewallEvent(db *sql.DB, eventType string, ip string, port int, timestamp string) {
	insertSQL := `INSERT INTO firewall_events (event_type, source_ip, port, event_time) VALUES (?, ?, ?, ?);`
	_, err := db.Exec(insertSQL, eventType, ip, port, timestamp)
	if err != nil {
		fmt.Println("Error saving to database:", err)
	}
}

func cleanupOldFirewallRecords(db *sql.DB, maxRecords int) {
	cleanupSQL := `
	DELETE FROM firewall_events WHERE id NOT IN (
		SELECT id FROM firewall_events ORDER BY id DESC LIMIT ?
	);`
	_, err := db.Exec(cleanupSQL, maxRecords)
	if err != nil {
		fmt.Println("Error during cleanup:", err)
	}
}

func loadPreviouslyBlockedIPs(db *sql.DB, blockedSourceIPs map[string]bool) {
	rows, err := db.Query("SELECT DISTINCT source_ip FROM firewall_events WHERE event_type = 'ip_blocked';")
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var ip string
		if scanErr := rows.Scan(&ip); scanErr == nil {
			blockedSourceIPs[ip] = true
		}
	}

	if len(blockedSourceIPs) > 0 {
		fmt.Printf("Loaded %d previously blocked IP(s) from database.\n", len(blockedSourceIPs))
	}
}
