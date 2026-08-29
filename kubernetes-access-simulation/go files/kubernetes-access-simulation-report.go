package main
import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

func main() {
	db, err := sql.Open("sqlite", "kubernetes-access-simulation.db")
	if err != nil {
		fmt.Println("Could not open database:", err)
		return
	}
	defer db.Close()

	fmt.Println("========================================")
	fmt.Println(" ACCESS MATRIX — AUDIT REPORT")
	fmt.Println("========================================")

	printByResult(db, "DENIED")
	printByResult(db, "ALLOWED")
}

func printByResult(db *sql.DB, result string) {
	fmt.Printf("\n--- %s ---\n", result)

	rows, err := db.Query(
		"SELECT user_name, user_role, environment, reason, checked_at FROM access_matrix WHERE result = ? ORDER BY checked_at DESC",
		result,
	)
	if err != nil {
		fmt.Println("Could not read access_matrix table:", err)
		return
	}
	defer rows.Close()

	found := false
	for rows.Next() {
		var userName, role, env, reason, checkedAt string
		rows.Scan(&userName, &role, &env, &reason, &checkedAt)
		fmt.Printf("  %s (%s / %s) — %s — checked at: %s\n", userName, role, env, reason, checkedAt)
		found = true
	}

	if !found {
		fmt.Printf("  (no %s entries yet)\n", result)
	}
}
