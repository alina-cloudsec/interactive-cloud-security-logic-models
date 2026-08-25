package main
import (
	"bufio"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Config struct {
	MaskOutput               string   `json:"mask_output"`
	SensitiveKeywords        []string `json:"sensitive_keywords"`
	LogFile                  string   `json:"log_file"`
	OutputFile               string   `json:"output_file"`
	ScanInputFile             string  `json:"scan_input_file"`
	RedactedOutputFile        string  `json:"redacted_output_file"`
	DatabaseFile              string  `json:"database_file"`
	MaxRecordsBeforeCleanup   int     `json:"max_records_before_cleanup"`
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

func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
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

func writeOutput(path string, maskedValue string, hash string) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Could not open output file:", err)
		return
	}
	defer file.Close()
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	report := fmt.Sprintf(
		"---------------------------------------\nCheck time    : %s\nSaved value   : %s\nSecret hash   : %s\n",
		timestamp, maskedValue, hash,
	)
	file.WriteString(report)
}

func openDatabase(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	createTable := `
	CREATE TABLE IF NOT EXISTS redacted_secrets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		masked_value TEXT,
		secret_hash TEXT,
		source TEXT,
		logged_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	if _, err := db.Exec(createTable); err != nil {
		return nil, err
	}
	return db, nil
}

func saveRedactedSecret(db *sql.DB, maskedValue string, hash string, source string) {
	db.Exec(
		"INSERT INTO redacted_secrets (masked_value, secret_hash, source) VALUES (?, ?, ?)",
		maskedValue, hash, source,
	)
}

func cleanupOldSecrets(db *sql.DB, maxRecords int) {
	cleanupSQL := `DELETE FROM redacted_secrets WHERE id NOT IN (
		SELECT id FROM redacted_secrets ORDER BY id DESC LIMIT ?
	);`
	db.Exec(cleanupSQL, maxRecords)
}

func buildKeywordPattern(keywords []string) *regexp.Regexp {
	joined := strings.Join(keywords, "|")
	pattern := `(?i)(` + joined + `)\s*[:=]\s*(\S+)`
	return regexp.MustCompile(pattern)
}

func redactLogFile(cfg *Config, db *sql.DB, pattern *regexp.Regexp) (int, error) {
	inputFile, err := os.Open(cfg.ScanInputFile)
	if err != nil {
		return 0, err
	}
	defer inputFile.Close()

	outputFile, err := os.OpenFile(cfg.RedactedOutputFile, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return 0, err
	}
	defer outputFile.Close()

	scanner := bufio.NewScanner(inputFile)
	redactedCount := 0

	for scanner.Scan() {
		line := scanner.Text()

		matches := pattern.FindAllStringSubmatch(line, -1)

		for _, match := range matches {
			originalValue := match[2]
			hash := hashSecret(originalValue)
			maskedValue := cfg.MaskOutput

			line = strings.Replace(line, originalValue, maskedValue, 1)

			saveRedactedSecret(db, maskedValue, hash, cfg.ScanInputFile)
			redactedCount++
		}

		outputFile.WriteString(line + "\n")
	}

	return redactedCount, scanner.Err()
}

func main() {
	cfg, err := loadConfig("data-encryptor-config.json")
	if err != nil {
		fmt.Println("Could not load data-encryptor-config.json:", err)
		return
	}

	db, err := openDatabase(cfg.DatabaseFile)
	if err != nil {
		fmt.Println("Could not open database:", err)
		return
	}
	defer db.Close()

	fmt.Println("\t\t\tALINA'S LIVE SECURITY LOG REDACTOR\t\t\t")
	fmt.Println()
	fmt.Println("1. Redact one secret I type in")
	fmt.Println("2. Scan and redact a whole log file")
	fmt.Print("Choose 1 or 2: ")

	reader := bufio.NewReader(os.Stdin)
	choiceInput, _ := reader.ReadString('\n')
	choice := strings.TrimSpace(choiceInput)

	if choice == "1" {
		fmt.Print("Enter your private API token/password: ")
		rawInput, _ := reader.ReadString('\n')
		userSecret := strings.TrimSpace(rawInput)

		if userSecret == "" {
			fmt.Println("Error:\a No token input detected.")
			writeLog(cfg.LogFile, "No token input detected.")
			return
		}

		maskedValue := cfg.MaskOutput
		hash := hashSecret(userSecret)

		fmt.Println("Sanitized Log File Output Saved:", maskedValue)

		writeLog(cfg.LogFile, fmt.Sprintf("Secret redacted. Masked value: %s | hash: %s", maskedValue, hash))
		writeOutput(cfg.OutputFile, maskedValue, hash)
		saveRedactedSecret(db, maskedValue, hash, "manual entry")
		cleanupOldSecrets(db, cfg.MaxRecordsBeforeCleanup)

	} else if choice == "2" {
		pattern := buildKeywordPattern(cfg.SensitiveKeywords)

		count, err := redactLogFile(cfg, db, pattern)
		if err != nil {
			fmt.Println("Could not scan log file:", err)
			return
		}

		fmt.Printf("Scanned %s — found and redacted %d secret(s).\n", cfg.ScanInputFile, count)
		fmt.Println("Clean version saved to", cfg.RedactedOutputFile)

		writeLog(cfg.LogFile, fmt.Sprintf("Scanned %s, redacted %d secret(s).", cfg.ScanInputFile, count))
		cleanupOldSecrets(db, cfg.MaxRecordsBeforeCleanup)

	} else {
		fmt.Println("Not a valid choice, please enter 1 or 2.")
		return
	}

	fmt.Println("\nFull results saved in", cfg.DatabaseFile, "and", cfg.LogFile)
}
