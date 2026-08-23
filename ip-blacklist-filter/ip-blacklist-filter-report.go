package main
import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

func main() {

	db, err := sql.Open("sqlite", "ip-blacklist-filter.db")
	if err != nil {
		fmt.Println("Could not open database:", err)
		return
	}
	defer db.Close()

	fmt.Println("========================================")
	fmt.Println(" IP BLACKLIST FILTER — ACCESS REPORT")
	fmt.Println("========================================")

	printByResult(db, "DENIED")
	printByResult(db, "ALLOWED")
	printByResult(db, "INVALID")
}

func printByResult(db *sql.DB, result string) {
	fmt.Printf("\n--- %s ---\n", result)

	rows, err := db.Query(
		"SELECT visitor_ip, matched_rule, checked_at FROM access_log WHERE result = ? ORDER BY checked_at DESC",
		result,
	)
	if err != nil {
		fmt.Println("Could not read access_log table:", err)
		return
	}
	defer rows.Close()

	found := false
	for rows.Next() {
		var ip, rule, checkedAt string
		rows.Scan(&ip, &rule, &checkedAt)
		fmt.Printf("  %s   rule: %s   checked at: %s\n", ip, rule, checkedAt)
		found = true
	}

	if !found {
		fmt.Printf("  (no %s entries yet)\n", result)
	}
}
