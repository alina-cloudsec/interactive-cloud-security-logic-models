package main
import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"time"

	_ "modernc.org/sqlite"
)

type UserProfile struct {
	UserName    string `json:"user_name"`
	UserRole    string `json:"user_role"`
	Environment string `json:"environment"`
}

type Policy struct {
	Role        string `json:"role"`
	Environment string `json:"environment"` 
	Allowed     bool   `json:"allowed"`
	Reason      string `json:"reason"`
}

type Config struct {
	Policies     []Policy      `json:"policies"`
	Users        []UserProfile `json:"users"`
	LogFile      string        `json:"log_file"`
	OutputFile   string        `json:"output_file"`
	DatabaseFile string        `json:"database_file"`
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

func writeOutput(path string, user UserProfile, allowed bool, reason string) {
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
		"---------------------------------------\nCheck time  : %s\nUser        : %s\nRole        : %s\nEnvironment : %s\nResult      : %s\nReason      : %s\n",
		timestamp, user.UserName, user.UserRole, user.Environment, status, reason,
	)
	file.WriteString(report)
}

func openDatabase(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	createTable := `
	CREATE TABLE IF NOT EXISTS access_matrix (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_name TEXT,
		user_role TEXT,
		environment TEXT,
		result TEXT,
		reason TEXT,
		checked_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	if _, err := db.Exec(createTable); err != nil {
		return nil, err
	}
	return db, nil
}

func saveAccessCheck(db *sql.DB, user UserProfile, result string, reason string) {
	db.Exec(
		"INSERT INTO access_matrix (user_name, user_role, environment, result, reason) VALUES (?, ?, ?, ?, ?)",
		user.UserName, user.UserRole, user.Environment, result, reason,
	)
}

func checkAccess(user UserProfile, policies []Policy) (bool, string) {
	for _, policy := range policies {
		roleMatches := policy.Role == user.UserRole
		envMatches := policy.Environment == user.Environment || policy.Environment == "*"

		if roleMatches && envMatches {
			return policy.Allowed, policy.Reason
		}
	}
	return false, "No matching policy found — access denied by default."
}

func main() {
	cfg, err := loadConfig("kubernetes-access-simulation-config.json")
	if err != nil {
		fmt.Println("Could not load kubernetes-access-simulation-config.json:", err)
		return
	}

	db, err := openDatabase(cfg.DatabaseFile)
	if err != nil {
		fmt.Println("Could not open database:", err)
		return
	}
	defer db.Close()

	fmt.Println("\t\t\tVerifying Cloud Infrastructure Access Matrix\t\t\t")
	fmt.Println()

	for _, singleUser := range cfg.Users {
		fmt.Printf("Checking access tokens for: %s\n", singleUser.UserName)

		allowed, reason := checkAccess(singleUser, cfg.Policies)

		status := "ALLOWED"
		if !allowed {
			status = "DENIED"
			fmt.Printf("\a %s\n", reason)
		} else {
			fmt.Printf(" %s\n", reason)
		}

		writeLog(cfg.LogFile, fmt.Sprintf("%s (%s / %s): %s — %s",
			singleUser.UserName, singleUser.UserRole, singleUser.Environment, status, reason))
		writeOutput(cfg.OutputFile, singleUser, allowed, reason)
		saveAccessCheck(db, singleUser, status, reason)
	}

	fmt.Println("\nFull results saved in", cfg.DatabaseFile, ",", cfg.LogFile, "and", cfg.OutputFile)
}
