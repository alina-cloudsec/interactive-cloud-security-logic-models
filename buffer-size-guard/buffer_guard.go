package main
import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Config struct {
	MaxInputBytes            int64  `json:"max_input_bytes"`
	WarningAfterAttempts     int    `json:"warning_after_attempts"`
	BlockAfterAttempts       int    `json:"block_after_attempts"`
	LogFile                  string `json:"log_file"`
	DatabaseFile              string `json:"database_file"`
	HistoryCleanupAfterHours int    `json:"history_cleanup_after_hours"`
}

func loadConfig(path string) (*Config, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	err = json.Unmarshal(file, &cfg)
	if err != nil {
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
	line := fmt.Sprintf("[%s] %s\n", timestamp, message)
	file.WriteString(line)
}

func openDatabase(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	createHistory := `
	CREATE TABLE IF NOT EXISTS attempt_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		session_ip TEXT,
		attempt_number INTEGER,
		input_size INTEGER,
		status TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	createSuspicious := `
	CREATE TABLE IF NOT EXISTS suspicious_ips (
		ip TEXT PRIMARY KEY,
		flagged_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	createBlocked := `
	CREATE TABLE IF NOT EXISTS blocked_ips (
		ip TEXT PRIMARY KEY,
		blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	if _, err := db.Exec(createHistory); err != nil {
		return nil, err
	}
	if _, err := db.Exec(createSuspicious); err != nil {
		return nil, err
	}
	if _, err := db.Exec(createBlocked); err != nil {
		return nil, err
	}

	return db, nil
}

func isBlocked(db *sql.DB, ip string) bool {
	var foundIP string
	row := db.QueryRow("SELECT ip FROM blocked_ips WHERE ip = ?", ip)
	err := row.Scan(&foundIP)
	return err == nil 
}

func countRejected(db *sql.DB, ip string) int {
	var count int
	row := db.QueryRow("SELECT COUNT(*) FROM attempt_history WHERE session_ip = ? AND status = 'REJECTED'", ip)
	row.Scan(&count)
	return count
}

func saveAttempt(db *sql.DB, ip string, attemptNumber int, size int64, status string) {
	db.Exec(
		"INSERT INTO attempt_history (session_ip, attempt_number, input_size, status) VALUES (?, ?, ?, ?)",
		ip, attemptNumber, size, status,
	)
}

func markSuspicious(db *sql.DB, ip string) {
	db.Exec("INSERT OR IGNORE INTO suspicious_ips (ip) VALUES (?)", ip)
}

func blockIP(db *sql.DB, ip string) {
	db.Exec("INSERT OR IGNORE INTO blocked_ips (ip) VALUES (?)", ip)
}

func cleanupOldHistory(db *sql.DB, hours int) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour).Format("2006-01-02 15:04:05")
	db.Exec("DELETE FROM attempt_history WHERE created_at < ?", cutoff)
}

func readGuardedInput(maxBytes int64) string {
	limited := io.LimitReader(os.Stdin, maxBytes+1)
	reader := bufio.NewReader(limited)
	raw, _ := reader.ReadString('\n')
	return strings.TrimSpace(raw)
}

func main() {
	cfg, err := loadConfig("buffer-guard-config.json")
	if err != nil {
		fmt.Println("Could not load buffer-guard-config.json:", err)
		return
	}

	db, err := openDatabase(cfg.DatabaseFile)
	if err != nil {
		fmt.Println("Could not open database:", err)
		return
	}
	defer db.Close()

	cleanupOldHistory(db, cfg.HistoryCleanupAfterHours)
	sessionIP := "192.168.1.50"

	fmt.Println(" ------ALINA'S BUFFER INPUT GUARD-----")
	fmt.Printf("Max allowed size: %d bytes\n", cfg.MaxInputBytes)

	if isBlocked(db, sessionIP) {
		fmt.Println("\aSECURITY BLOCK: this IP is already on the permanent block list.")
		writeLog(cfg.LogFile, fmt.Sprintf("Blocked IP %s tried to connect and was refused.", sessionIP))
		return
	}

	attempt := 0
	success := false

	for attempt < 20 { 
		attempt = attempt + 1
		fmt.Printf("\n[Attempt %d] Enter your message(in the terminal): ", attempt)

		input := readGuardedInput(cfg.MaxInputBytes)
		size := int64(len(input))

		if size <= cfg.MaxInputBytes {
			fmt.Println("STATUS: SAFE — input accepted.")
			saveAttempt(db, sessionIP, attempt, size, "ACCEPTED")
			writeLog(cfg.LogFile, fmt.Sprintf("IP %s: attempt %d ACCEPTED (%d bytes)", sessionIP, attempt, size))
			success = true
			break
		}

		saveAttempt(db, sessionIP, attempt, size, "REJECTED")
		writeLog(cfg.LogFile, fmt.Sprintf("IP %s: attempt %d REJECTED (%d bytes)", sessionIP, attempt, size))

		rejectedCount := countRejected(db, sessionIP)

		if rejectedCount >= cfg.BlockAfterAttempts {
			blockIP(db, sessionIP)
			writeLog(cfg.LogFile, fmt.Sprintf("IP %s BLOCKED after %d oversized attempts", sessionIP, rejectedCount))
			fmt.Println("\a SECURITY BLOCK: too many oversized attempts. This IP is now permanently blocked.")
			return
		} else if rejectedCount >= cfg.WarningAfterAttempts {
			markSuspicious(db, sessionIP)
			writeLog(cfg.LogFile, fmt.Sprintf("IP %s marked SUSPICIOUS after %d oversized attempts", sessionIP, rejectedCount))
			fmt.Printf("\a WARNING: input rejected (%d bytes). You are now on the SUSPICIOUS list. %d more and you will be blocked.\n",
				size, cfg.BlockAfterAttempts-rejectedCount)
		} else {
			fmt.Printf("\a WARNING: input rejected, exceeds %d bytes. Try again.\n", cfg.MaxInputBytes)
		}
	}

	if !success {
		fmt.Println("\nSession ended without a safe input.")
	}

	fmt.Println("\nFull history is saved in", cfg.DatabaseFile)
	fmt.Println("A readable log is saved in", cfg.LogFile)
}

