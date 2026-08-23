package main
import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Config struct {
	BlacklistIPs        []string `json:"blacklist_ips"`
	BlacklistCIDRRanges []string `json:"blacklist_cidr_ranges"`
	LogFile              string  `json:"log_file"`
	OutputFile            string `json:"output_file"`
	DatabaseFile         string  `json:"database_file"`
}

func loadConfig(path string) (*Config, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(file, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func writeLog(path string, message string) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Could not open log file:", err)
		return
	}
	defer file.Close()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	file.WriteString(fmt.Sprintf("[%s] %s\n", timestamp, message))
}

func writeOutput(path string, visitorIP string, allowed bool, matchedRule string) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Could not open output file:", err)
		return
	}
	defer file.Close()

	status := "ALLOWED"
	if !allowed {
		status = "DENIED"
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	report := fmt.Sprintf(
		"---------------------------------------\nCheck time : %s\nVisitor IP : %s\nResult     : %s\nRule       : %s\n",
		timestamp, visitorIP, status, matchedRule,
	)
	file.WriteString(report)
}

func openDatabase(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	createTable := `
	CREATE TABLE IF NOT EXISTS access_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		visitor_ip TEXT,
		result TEXT,
		matched_rule TEXT,
		checked_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	if _, err := db.Exec(createTable); err != nil {
		return nil, err
	}
	return db, nil
}

func saveAccessCheck(db *sql.DB, ip string, result string, matchedRule string) {
	db.Exec(
		"INSERT INTO access_log (visitor_ip, result, matched_rule) VALUES (?, ?, ?)",
		ip, result, matchedRule,
	)
}

func buildExactMatchSet(ips []string) map[string]bool {
	set := make(map[string]bool)
	for _, ip := range ips {
		set[ip] = true
	}
	return set
}

func parseCIDRRanges(cidrStrings []string) []*net.IPNet {
	var ranges []*net.IPNet
	for _, cidrStr := range cidrStrings {
		_, network, err := net.ParseCIDR(cidrStr)
		if err == nil {
			ranges = append(ranges, network)
		}
	}
	return ranges
}

func checkAccess(visitorIP net.IP, exactSet map[string]bool, cidrRanges []*net.IPNet) (bool, string) {
	if exactSet[visitorIP.String()] {
		return false, "exact match: " + visitorIP.String()
	}

	for _, network := range cidrRanges {
		if network.Contains(visitorIP) {
			return false, "range match: " + network.String()
		}
	}

	return true, "not blacklisted"
}

func main() {
	cfg, err := loadConfig("ip-blacklist-filter-config.json")
	if err != nil {
		fmt.Println("Could not load ip-blacklist-filter-config.json:", err)
		return
	}

	db, err := openDatabase(cfg.DatabaseFile)
	if err != nil {
		fmt.Println("Could not open database:", err)
		return
	}
	defer db.Close()

	exactSet := buildExactMatchSet(cfg.BlacklistIPs)
	cidrRanges := parseCIDRRanges(cfg.BlacklistCIDRRanges)

	fmt.Println("--- ALINA'S LIVE MULTI-IP FIREWALL ---")
	fmt.Print("Enter your IP Address to check network permission: ")

	reader := bufio.NewReader(os.Stdin)
	rawInput, _ := reader.ReadString('\n')
	visitorInput := strings.TrimSpace(rawInput)

	visitorIP := net.ParseIP(visitorInput)
	if visitorIP == nil {
		fmt.Println("INVALID INPUT: that is not a real IP address.")
		writeLog(cfg.LogFile, fmt.Sprintf("Rejected invalid input: %q", visitorInput))
		saveAccessCheck(db, visitorInput, "INVALID", "not a valid IP format")
		return
	}

	allowed, matchedRule := checkAccess(visitorIP, exactSet, cidrRanges)

	if allowed {
		fmt.Println("ACCESS ALLOWED! Welcome to the network.")
	} else {
		fmt.Println("ACCESS DENIED! Your IP is blacklisted in our database.")
	}

	status := "ALLOWED"
	if !allowed {
		status = "DENIED"
	}

	writeLog(cfg.LogFile, fmt.Sprintf("IP %s %s (%s)", visitorIP, status, matchedRule))
	writeOutput(cfg.OutputFile, visitorIP.String(), allowed, matchedRule)
	saveAccessCheck(db, visitorIP.String(), status, matchedRule)

	fmt.Println("\nThis check was saved in", cfg.DatabaseFile, ",", cfg.LogFile, "and", cfg.OutputFile)
}
