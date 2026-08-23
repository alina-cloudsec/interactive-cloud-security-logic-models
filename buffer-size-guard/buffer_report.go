package main         
import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

func main() {
	
	db, err := sql.Open("sqlite", "buffer-guard-history.db")
	if err != nil {
		fmt.Println("Could not open database:", err)
		return
	}
	defer db.Close()

	fmt.Println("========================================")
	fmt.Println(" ALINA'S SECURITY STATUS REPORT ")
	fmt.Println("========================================")

	printSuspicious(db)
	printBlocked(db)
}

func printSuspicious(db *sql.DB) {
	fmt.Println("\n--- SUSPICIOUS IPs ---")

	rows, err := db.Query("SELECT ip, flagged_at FROM suspicious_ips ORDER BY flagged_at DESC")
	if err != nil {
		fmt.Println("Could not read suspicious list:", err)
		return
	}
	defer rows.Close()

	found := false
	for rows.Next() {
		var ip string
		var flaggedAt string
		rows.Scan(&ip, &flaggedAt)
		fmt.Printf("  %s   flagged at: %s\n", ip, flaggedAt)
		found = true
	}

	if !found {
		fmt.Println("  (no suspicious IPs right now)")
	}
}

func printBlocked(db *sql.DB) {
	fmt.Println("\n--- BLOCKED IPs ---")

	rows, err := db.Query("SELECT ip, blocked_at FROM blocked_ips ORDER BY blocked_at DESC")
	if err != nil {
		fmt.Println("Could not read blocked list:", err)
		return
	}
	defer rows.Close()

	found := false
	for rows.Next() {
		var ip string
		var blockedAt string
		rows.Scan(&ip, &blockedAt)
		fmt.Printf("  %s   blocked at: %s\n", ip, blockedAt)
		found = true
	}

	if !found {
		fmt.Println("  (no blocked IPs right now)")
	}
} 
