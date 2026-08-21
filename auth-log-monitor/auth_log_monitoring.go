package main

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type ThreatCounts struct {
	FailedPassword     int
	UnauthorizedAccess int
	PortScan           int
}

type Config struct {
	LogFilePath              string `json:"log_file_path"`
	DatabaseName              string `json:"database_name"`
	BlockThreshold            int    `json:"block_threshold"`
	BlockTimeWindowMinutes    int    `json:"block_time_window_minutes"`
	MaxRecordsBeforeCleanup   int    `json:"max_records_before_cleanup"`
}

var ipRegex = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)

func main() {
	fmt.Println("Starting Cloud Server Log Monitoring")
	fmt.Println()

	config, err := loadConfig("config.json")
	if err != nil {
		fmt.Println("Error loading config.json:", err)
		return
	}

	logFileName := config.LogFilePath
	if len(os.Args) > 1 {
		logFileName = os.Args[1]
	}

	logFile, err := os.Open(logFileName)
	if err != nil {
		fmt.Println("Error: could not open", logFileName)
		return
	}
	defer logFile.Close()

	reportFile, err := os.Create("output.txt")
	if err != nil {
		fmt.Println("Error: could not create report file")
		return
	}
	defer reportFile.Close()
	reportWriter := bufio.NewWriter(reportFile)
	defer reportWriter.Flush()

	blocklistFile, err := os.Create("blocked_ips.txt")
	if err != nil {
		fmt.Println("Error: could not create blocklist file")
		return
	}
	defer blocklistFile.Close()
	blocklistWriter := bufio.NewWriter(blocklistFile)
	defer blocklistWriter.Flush()

	db, err := sql.Open("sqlite", config.DatabaseName)
	if err != nil {
		fmt.Println("Error: could not open database")
		return
	}
	defer db.Close()

	createTableSQL := `
	CREATE TABLE IF NOT EXISTS threats (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		threat_type TEXT,
		ip_address TEXT,
		event_time TEXT
	);`
	_, err = db.Exec(createTableSQL)
	if err != nil {
		fmt.Println("Error creating table:", err)
		return
	}

	counts := ThreatCounts{}
	totalLinesRead := 0
	firstThreatTime := ""
	lastThreatTime := ""

	ipAttackTimes := make(map[string][]time.Time)
	blockedIPs := make(map[string]bool)
	suspiciousIPs := make(map[string]bool)

	reader := bufio.NewReader(logFile)
	linesProcessedInThisRun := 0

	fmt.Println("Watching log file... (this demo will process existing lines, then exit)")
	fmt.Println()

	for {
		line, err := reader.ReadString('\n')

		if len(line) > 0 {
			logLine := strings.TrimRight(line, "\r\n")
			totalLinesRead++
			linesProcessedInThisRun++

			isThreat, threatType, timestamp := processLine(logLine, &counts)
			extractedIP := extractIP(logLine)

			if isThreat {
				fmt.Printf("\a Threat Detected! Details: %s\n", logLine)
				reportWriter.WriteString("THREAT: " + logLine + "\n")

				if firstThreatTime == "" {
					firstThreatTime = timestamp
				}
				lastThreatTime = timestamp

				saveThreatToDatabase(db, threatType, extractedIP, timestamp)
				cleanupOldRecords(db, config.MaxRecordsBeforeCleanup)

				if extractedIP != "" {
					eventTime, parseErr := time.Parse("2006-01-02 15:04:05", timestamp)
					if parseErr == nil {
						
						windowDuration := time.Duration(config.BlockTimeWindowMinutes) * time.Minute
						validTimes := []time.Time{}
						for _, t := range ipAttackTimes[extractedIP] {
							if eventTime.Sub(t) <= windowDuration {
								validTimes = append(validTimes, t)
							}
						}
						validTimes = append(validTimes, eventTime)
						ipAttackTimes[extractedIP] = validTimes

						/*
							Yeh do-level system hai, real security tools jaisa:
							- 5 attempts pe: IP ko "suspicious" list mein daalo,
							  sirf warning do, abhi block mat karo.
							- 7 ya usse zyada pe: ab pakka block kar do.
							Isse hum sirf ek sudden switch (block/no-block) ki
							jagah, dheere dheere zyada strict nazar rakhte hain,
							bilkul jaise real IDS/SIEM tools karte hain.
						*/
						if len(validTimes) >= config.BlockThreshold && !blockedIPs[extractedIP] {
							blockedIPs[extractedIP] = true
							fmt.Printf("\a BLOCKED: %s hit %d attempts within %d minutes — auto-blocked\n",
								extractedIP, len(validTimes), config.BlockTimeWindowMinutes)
							blocklistWriter.WriteString(extractedIP + "\n")
							reportWriter.WriteString(fmt.Sprintf("BLOCKED: %s — %d attempts in %d minutes\n",
								extractedIP, len(validTimes), config.BlockTimeWindowMinutes))
						} else if len(validTimes) >= 5 && !suspiciousIPs[extractedIP] {
							suspiciousIPs[extractedIP] = true
							fmt.Printf("\a SUSPICIOUS: %s hit %d attempts — added to watch list\n",
								extractedIP, len(validTimes))
							reportWriter.WriteString(fmt.Sprintf("SUSPICIOUS: %s — %d attempts, now being watched closely\n",
								extractedIP, len(validTimes)))
						}
					}
				}
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

	totalHighRiskAlerts := counts.FailedPassword + counts.UnauthorizedAccess + counts.PortScan

	fmt.Println()
	fmt.Println("\t\t\t---------- Monitoring Summary ----------")
	fmt.Printf("Total log lines read: %d\n", totalLinesRead)
	fmt.Printf("Failed password attempts: %d\n", counts.FailedPassword)
	fmt.Printf("Unauthorized access attempts: %d\n", counts.UnauthorizedAccess)
	fmt.Printf("Port scans detected: %d\n", counts.PortScan)
	fmt.Printf("Total high-risk alerts raised: %d\n", totalHighRiskAlerts)
	fmt.Printf("First threat seen at: %s\n", firstThreatTime)
	fmt.Printf("Last threat seen at: %s\n", lastThreatTime)
	fmt.Println()

	reportWriter.WriteString("\n\t\t\t---------- Monitoring Summary ----------\n")
	reportWriter.WriteString(fmt.Sprintf("Total log lines read: %d\n", totalLinesRead))
	reportWriter.WriteString(fmt.Sprintf("Failed password attempts: %d\n", counts.FailedPassword))
	reportWriter.WriteString(fmt.Sprintf("Unauthorized access attempts: %d\n", counts.UnauthorizedAccess))
	reportWriter.WriteString(fmt.Sprintf("Port scans detected: %d\n", counts.PortScan))
	reportWriter.WriteString(fmt.Sprintf("Total high-risk alerts raised: %d\n", totalHighRiskAlerts))

	fmt.Println()
	fmt.Println("Monitoring Done.")
	fmt.Println("Full report saved to security_report.txt")
	fmt.Println("Blocked IPs saved to blocked_ips.txt")
	fmt.Println("All threats also saved to", config.DatabaseName)
}

func loadConfig(path string) (Config, error) {
	var config Config
	fileData, err := os.ReadFile(path)
	if err != nil {
		return config, err
	}
	err = json.Unmarshal(fileData, &config)
	return config, err
}

func processLine(logLine string, counts *ThreatCounts) (bool, string, string) {
	timestamp := ""
	if strings.HasPrefix(logLine, "[") {
		endBracket := strings.Index(logLine, "]")
		if endBracket != -1 {
			timestamp = logLine[1:endBracket]
		}
	}

	if strings.Contains(logLine, "CRITICAL") && strings.Contains(logLine, "Failed password") {
		counts.FailedPassword++
		return true, "Failed Password", timestamp
	}

	if strings.Contains(logLine, "WARN") && strings.Contains(logLine, "Unauthorized access attempt") {
		counts.UnauthorizedAccess++
		return true, "Unauthorized Access", timestamp
	}

	if strings.Contains(logLine, "WARN") && strings.Contains(logLine, "Port scan detected") {
		counts.PortScan++
		return true, "Port Scan", timestamp
	}

	return false, "", timestamp
}

func extractIP(logLine string) string {
	match := ipRegex.FindString(logLine)
	return match
}

func saveThreatToDatabase(db *sql.DB, threatType string, ip string, timestamp string) {
	insertSQL := `INSERT INTO threats (threat_type, ip_address, event_time) VALUES (?, ?, ?);`
	_, err := db.Exec(insertSQL, threatType, ip, timestamp)
	if err != nil {
		fmt.Println("Error saving to database:", err)
	}
}

func cleanupOldRecords(db *sql.DB, maxRecords int) {
	cleanupSQL := `
	DELETE FROM threats WHERE id NOT IN (
		SELECT id FROM threats ORDER BY id DESC LIMIT ?
	);`
	_, err := db.Exec(cleanupSQL, maxRecords)
	if err != nil {
		fmt.Println("Error during cleanup:", err)
	}
}
