package main
import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

func main() {
	db, err := sql.Open("sqlite", "firewall_threats.db")
	if err != nil {
		fmt.Println("Could not open database:", err)
		return
	}
	defer db.Close()

	fmt.Println("========================================")
	fmt.Println(" PORT FIREWALL ATTACK REPORT")
	fmt.Println("========================================")

	printPortSuspicious(db)
	printPortBlocked(db)
}

func printPortSuspicious(db *sql.DB) {
	fmt.Println("\n--- SUSPICIOUS NETWORK IPs ---")

	rows, err := db.Query("SELECT DISTINCT source_ip, event_time FROM firewall_events WHERE event_type IN ('port_scan', 'blocked_port') ORDER BY event_time DESC")
	if err != nil {
		fmt.Println("  (No activity records tracked or firewall table is still empty)")
		return
	}
	defer rows.Close()

	found := false
	for rows.Next() {
		var ip string
		var eventTime string
		rows.Scan(&ip, &eventTime)
		fmt.Printf("  %s   flagged under watch at: %s\n", ip, eventTime)
		found = true
	}

	if !found {
		fmt.Println("  (no suspicious scanning nodes under watch right now)")
	}
}

func printPortBlocked(db *sql.DB) {
	fmt.Println("\n--- BLOCKED NETWORK IPs ---")

	rows, err := db.Query("SELECT DISTINCT source_ip, event_time FROM firewall_events WHERE event_type = 'ip_blocked' ORDER BY event_time DESC")
	if err != nil {
		return
	}
	defer rows.Close()

	found := false
	for rows.Next() {
		var ip string
		var eventTime string
		rows.Scan(&ip, &eventTime)
		fmt.Printf("  %s   completely blocked at: %s\n", ip, eventTime)
		found = true
	}

	if !found {
		fmt.Println("  (no network IPs permanently blocked right now)")
	}
}
