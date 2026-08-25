package main
import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Config struct {
	UrlsFile                  string `json:"urls_file"`
	TimeoutSeconds            int    `json:"timeout_seconds"`
	MaxRetries                int    `json:"max_retries"`
	RetryDelaySeconds         int    `json:"retry_delay_seconds"`
	HealthyStatusMin          int    `json:"healthy_status_min"`
	HealthyStatusMax          int    `json:"healthy_status_max"`
	ConsecutiveFailuresForAlert int  `json:"consecutive_failures_for_alert"`
	LogFile                   string `json:"log_file"`
	OutputFile                string `json:"output_file"`
	DatabaseFile              string `json:"database_file"`
	MaxRecordsBeforeCleanup   int    `json:"max_records_before_cleanup"`
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

func writeOutput(path string, targetUrl string, healthy bool, statusCode int, responseTime time.Duration, attempts int) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Could not open output file:", err)
		return
	}
	defer file.Close()

	status := "HEALTHY"
	if !healthy {
		status = "DOWN"
	}
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	report := fmt.Sprintf(
		"---------------------------------------\nCheck time    : %s\nURL           : %s\nStatus        : %s\nStatus code   : %d\nResponse time : %s\nAttempts used : %d\n",
		timestamp, targetUrl, status, statusCode, responseTime, attempts,
	)
	file.WriteString(report)
}

func openDatabase(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	createTable := `
	CREATE TABLE IF NOT EXISTS health_checks (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target_url TEXT,
		result TEXT,
		status_code INTEGER,
		response_time_ms INTEGER,
		attempts INTEGER,
		checked_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	if _, err := db.Exec(createTable); err != nil {
		return nil, err
	}
	return db, nil
}

func saveCheck(db *sql.DB, targetUrl string, result string, statusCode int, responseTime time.Duration, attempts int) {
	db.Exec(
		"INSERT INTO health_checks (target_url, result, status_code, response_time_ms, attempts) VALUES (?, ?, ?, ?, ?)",
		targetUrl, result, statusCode, responseTime.Milliseconds(), attempts,
	)
}

func cleanupOldChecks(db *sql.DB, maxRecords int) {
	cleanupSQL := `DELETE FROM health_checks WHERE id NOT IN (
		SELECT id FROM health_checks ORDER BY id DESC LIMIT ?
	);`
	db.Exec(cleanupSQL, maxRecords)
}

func readUrls(path string) ([]string, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(file), "\n")
	var urls []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			urls = append(urls, trimmed)
		}
	}

	return urls, nil
}

func countRecentConsecutiveFailures(db *sql.DB, targetUrl string) int {
	rows, err := db.Query(
		"SELECT result FROM health_checks WHERE target_url = ? ORDER BY checked_at DESC",
		targetUrl,
	)
	if err != nil {
		return 0
	}
	defer rows.Close()

	streak := 0
	for rows.Next() {
		var result string
		rows.Scan(&result)

		if result == "DOWN" {
			streak++
		} else {
			break
		}
	}

	return streak
}

func checkHealth(targetUrl string, cfg *Config) (bool, int, time.Duration, int) {
	client := http.Client{
		Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second,
	}

	var lastStatusCode int
	var lastResponseTime time.Duration
	attempt := 0

	for attempt < cfg.MaxRetries {
		attempt++
		start := time.Now()
		response, err := client.Get(targetUrl)
		lastResponseTime = time.Since(start)

		if err == nil {
			lastStatusCode = response.StatusCode
			response.Body.Close()

			if lastStatusCode >= cfg.HealthyStatusMin && lastStatusCode <= cfg.HealthyStatusMax {
				return true, lastStatusCode, lastResponseTime, attempt
			}
		}

		if attempt < cfg.MaxRetries {
			time.Sleep(time.Duration(cfg.RetryDelaySeconds) * time.Second)
		}
	}

	return false, lastStatusCode, lastResponseTime, attempt
}

func main() {
	cfg, err := loadConfig("cloud-site-checker-config.json")
	if err != nil {
		fmt.Println("Could not load cloud-site-checker-config.json:", err)
		return
	}

	db, err := openDatabase(cfg.DatabaseFile)
	if err != nil {
		fmt.Println("Could not open database:", err)
		return
	}
	defer db.Close()

	urls, err := readUrls(cfg.UrlsFile)
	if err != nil {
		fmt.Println("Could not read", cfg.UrlsFile, ":", err)
		return
	}

	fmt.Println("\t\t\tALINA'S LIVE CONTAINER HEALTH PROBE\t\t\t")
	fmt.Printf("Checking %d site(s) from %s\n\n", len(urls), cfg.UrlsFile)

	for _, targetUrl := range urls {
		fmt.Println("Checking:", targetUrl)

		healthy, statusCode, responseTime, attempts := checkHealth(targetUrl, cfg)

		result := "HEALTHY"
		if !healthy {
			result = "DOWN"
		}

		saveCheck(db, targetUrl, result, statusCode, responseTime, attempts)

		if healthy {
			fmt.Printf("success: Healthy (Status %d, %s, %d attempt(s))\n\n", statusCode, responseTime, attempts)
			writeLog(cfg.LogFile, fmt.Sprintf("%s -> HEALTHY (status %d, %d attempt(s))", targetUrl, statusCode, attempts))
		} else {
			streak := countRecentConsecutiveFailures(db, targetUrl)

			if streak >= cfg.ConsecutiveFailuresForAlert {
				fmt.Printf("alert\a: CONFIRMED DOWN — failed %d checks in a row (status %d)\n\n", streak, statusCode)
				writeLog(cfg.LogFile, fmt.Sprintf("%s -> CONFIRMED DOWN (%d consecutive failures, status %d)", targetUrl, streak, statusCode))
			} else {
				fmt.Printf("warning: possible outage — %d failure(s) in a row so far (status %d)\n\n", streak, statusCode)
				writeLog(cfg.LogFile, fmt.Sprintf("%s -> WARNING (%d consecutive failure(s), status %d)", targetUrl, streak, statusCode))
			}
		}

		writeOutput(cfg.OutputFile, targetUrl, healthy, statusCode, responseTime, attempts)
	}

	cleanupOldChecks(db, cfg.MaxRecordsBeforeCleanup)

	fmt.Println("Full results saved in", cfg.DatabaseFile, ",", cfg.LogFile, "and", cfg.OutputFile)
}
