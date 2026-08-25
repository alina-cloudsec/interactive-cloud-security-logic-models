package main
import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

func main() {
	db, err := sql.Open("sqlite", "data-encryptor.db")
	if err != nil {
		fmt.Println("Could not open database:", err)
		return
	}
	defer db.Close()

	fmt.Println("========================================")
	fmt.Println(" DATA ENCRYPTOR — REDACTION HISTORY")
	fmt.Println("========================================")

	rows, err := db.Query("SELECT masked_value, secret_hash, source, logged_at FROM redacted_secrets ORDER BY logged_at DESC")
	if err != nil {
		fmt.Println("Could not read redacted_secrets table:", err)
		return
	}
	defer rows.Close()

	found := false
	for rows.Next() {
		var maskedValue, hash, source, loggedAt string
		rows.Scan(&maskedValue, &hash, &source, &loggedAt)
		fmt.Printf("  %s   hash: %s   source: %s   at: %s\n", maskedValue, hash, source, loggedAt)
		found = true
	}

	if !found {
		fmt.Println("  (no redacted secrets logged yet)")
	}
}
