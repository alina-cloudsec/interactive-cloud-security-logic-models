package main
import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

func main() {
	db, err := sql.Open("sqlite", "cloud-site-checker.db")
	if err != nil {
		fmt.Println("Could not open database:", err)
		return
	}
	defer db.Close()

	fmt.Println("========================================")
	fmt.Println(" CLOUD SITE CHECKER — HEALTH HISTORY")
	fmt.Println("========================================")

	printByResult(db, "DOWN")
	printByResult(db, "HEALTHY")
}

func printByResult(db *sql.DB, result string) {
	fmt.Printf("\n--- %s ---\n", result)

	rows, err := db.Query(
		"SELECT target_url, status_code, response_time_ms, attempts, checked_at FROM health_checks WHERE result = ? ORDER BY checked_at DESC",
		result,
	)
	if err != nil {
		fmt.Println("Could not read health_checks table:", err)
		return
	}
	defer rows.Close()

	found := false
	for rows.Next() {
		var url string
		var statusCode, responseTimeMs, attempts int
		var checkedAt string
		rows.Scan(&url, &statusCode, &responseTimeMs, &attempts, &checkedAt)
		fmt.Printf("  %s   status: %d   response: %dms   attempts: %d   at: %s\n",
			url, statusCode, responseTimeMs, attempts, checkedAt)
		found = true
	}

	if !found {
		fmt.Printf("  (no %s entries yet)\n", result)
	}
}
