package main
import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

func main() {
	db, err := sql.Open("sqlite", "firewall-threats.db") 
	if err != nil {
		fmt.Println("Could not open database:", err)
		return
	}
	defer db.Close()

	fmt.Println("========================================")
	fmt.Println(" ALINA'S THREAT STATUS REPORT")
	fmt.Println("========================================")

	printSuspicious(db)
	printBlocked(db)
}

func printSuspicious(db *sql.DB) {
	fmt.Println("\n--- SUSPICIOUS IPs ---")

	rows, err := db.Query("SELECT ip_address, attempts_count, flagged_at FROM suspicious_ips ORDER BY flagged_at DESC")
	if err != nil {
		fmt.Println("Could not read suspicious_ips table:", err)
		return
	}
	defer rows.Close()

	found := false
	for rows.Next() {
		var ip, flaggedAt string
		var attempts int
		rows.Scan(&ip, &attempts, &flaggedAt)
		fmt.Printf("  %s   attempts: %d   flagged at: %s\n", ip, attempts, flaggedAt)
		found = true
	}

	if !found {
		fmt.Println("  (no suspicious IPs right now)")
	}
}

func printBlocked(db *sql.DB) {
	fmt.Println("\n--- BLOCKED IPs ---")

	rows, err := db.Query("SELECT ip_address, attempts_count, blocked_at FROM blocked_ips ORDER BY blocked_at DESC")
	if err != nil {
		fmt.Println("Could not read blocked_ips table:", err)
		return
	}
	defer rows.Close()

	found := false
	for rows.Next() {
		var ip, blockedAt string
		var attempts int
		rows.Scan(&ip, &attempts, &blockedAt)
		fmt.Printf("  %s   attempts: %d   blocked at: %s\n", ip, attempts, blockedAt)
		found = true
	}

	if !found {
		fmt.Println("  (no blocked IPs right now)")
	}
}