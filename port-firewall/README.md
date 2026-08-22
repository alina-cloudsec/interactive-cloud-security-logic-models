# Port Firewall Security Tool
 
## What This Code Does
 
This is a Go program that reads a file full of network connection logs and checks every line for signs of an attack, like someone trying closed ports over and over. If it finds an IP hitting dangerous ports, it flags it as suspicious on 2 attempts and completely blocks it if it crosses 4 attempts within a 2-minute rolling window. It also spots if an IP tries 4 different unique ports quickly to raise a port scan alert. It saves every threat into a small database, writes a full report to a text file, and automatically keeps the database from growing forever.
 
## Why I Built This
 
I wanted to actually understand how real firewall filtering and network security monitoring tools work, instead of just reading about them. So I built a small version myself, starting simple, and kept adding pieces one at a time, like a real product would grow over time: first just reading connections, then tracking unique port scanners, then saving data properly, then making it configurable.
 
## How This Relates to Cybersecurity
 
This program is a small, working example of a core cybersecurity idea: watching activity closely and catching patterns that look like an attack. Real attackers usually scan a system first to find open doors. This program specifically looks for that pattern: not just "did someone connect to a port," but "did the same IP touch multiple unapproved ports or hit dangerous ones quickly," which is what actually separates a real attack from one honest mistake.
 
## How This Relates to the Real World
 
Real companies run tools like Fail2Ban or hardware firewalls that do exactly this, just at a much bigger scale. They watch thousands of servers, collect logs into one place, and automatically drop bad connections instantly so the system CPU does not get overloaded. This project follows the same basic shape: read logs, detect a pattern, store the result, and take an action (blocking). The settings file (`firewall_config.json`) allows the rules to be changed without touching the code itself.
 
---
 
## What I Learned Researching Real Attacks
 
Before finishing this project, I looked into how real network attackers actually try to scan systems, so I could check if my program's approach made real sense, not just look right on the surface.
 
**Vertical and horizontal port scanning.** The basic version is one attacker checking multiple different ports on one single server to find an open door, which is what my program watches for. But I learned attackers also do horizontal scanning: searching for just one single open port (like port 22) across thousands of different servers at once. Catching this would need me to track attempts across multiple destinations.
 
**High traffic flooding after blocks.** A big thing I learned is that once an IP is blocked, it might still send thousands of quick requests to crash the program. That is why adding an early-drop check right at the top of the function is critical. If the IP matches the blocklist map, the program stops processing it instantly, saving massive CPU power.
 
**Inconsistent log time formats.** In the real world, different servers write timestamps using different symbols (some use dashes like `2026-08-22`, others use slashes like `2026/08/22`). If a program only reads one strict format, it goes blind and skips real threats. Building a fallback time parser ensures no log line gets dropped by accident.
 
**Why a warning stage before blocking helps.** Real tools often flag an IP as suspicious before fully blocking it, instead of jumping straight from nothing to blocked. This gives a chance to notice a pattern early and avoids accidentally blocking a real user who just mistyped a port number. That is why I added the 2-attempt suspicious warning stage before the 4-attempt block.
 
**Buffered data loss.** I learned that tracking tools that hold data inside RAM memory until the file finishes can lose critical logs if the server suddenly crashes or loses power. Real security apps execute direct flushes onto the physical text report immediately after an incident is found so evidence stays safe.
 
**Where I Could Make This Stronger Next**, based on what I read:
- Integrate real system firewall commands to drop actual network packets.
- Add temporary blocking so honest users are unbanned automatically after 15-30 minutes.
- Build a simple web page to view network alert streams live in a browser.
 
---
 
## How to Run This Code, Step by Step
 
1. **Open VS Code:** Open the specific local folder where your code files (`port_firewall.go`, `firewall_config.json`, and `firewall_logs.txt`) are stored.
2. **Set up the Go project:** Open your VS Code built-in terminal and set up the project environment:
```bash
   go mod init port-firewall
   go get modernc.org/sqlite
```
 
3. **Run the program:** Press the **Code Runner Play Button (▶️)** on the top right, or run this command in the terminal:
```bash
   go run port_firewall.go
```
 
4. **Check the results.** Three new files appear inside the folder:
   - `output.txt` — the full written report and live stats summary.
   - `blocked_source_ips.txt` — text list tracking any source IPs that got auto-blocked.
   - `firewall_threats.db` — a small database with every threat saved securely in it.
 
---
 
## Files in This Folder
 
- `port_firewall.go` — the actual firewall processing program.
- `firewall_config.json` — settings the program reads, like the blocked ports and time limits.
- `go.mod` and `go.sum` — configuration files Go creates to handle external database libraries.
- `firewall_logs.txt` — the sample log file containing network traffic histories.
- `output.txt` — a saved copy of what the program printed when I ran it.
 
---
 
## Coming Up in the Future
 
- Making the live tail actually run forever, instead of stopping at the end of the file, by adding a short wait and re-checking loop.
- Sending a real alert (like an email) when an IP gets blocked, instead of just writing it to a file.
- Designing a clear sandbox topology architecture map for this port firewall on the Meshery Playground canvas interface to visually show the network traffic flow.



---

## Code Explained, Block by Block

## Code Explained, Block by Block

**This part lets Go know which tool packages this program needs to read files, talk to the database, and handle time rules.**
```bash
package main

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)
```
- `package main`: Tells Go that this is a main program that runs on its own.
- `import (...)`: Loads standard helper tools. For example, `os` opens files, `strconv` changes words into numbers, and `time` counts minutes.
- `_ "modernc.org/sqlite"`: Loads the secret driver background engine so our SQL code can talk to the database file cleanly.

**This part sets up two storage boxes, called structs, to hold our firewall configurations and global packet counters.**
```bash
type FirewallConfig struct {
	BlockedPorts                  []int  `json:"blocked_ports"`
	ConnectionLogPath             string `json:"connection_log_path"`
	DatabaseName                  string `json:"database_name"`
	PortScanThreshold             int    `json:"port_scan_threshold"`
	PortScanWindowMinutes         int    `json:"port_scan_window_minutes"`
	RepeatOffenderSuspiciousCount int    `json:"repeat_offender_suspicious_count"`
	RepeatOffenderBlockCount      int    `json:"repeat_offender_block_count"`
	MaxRecordsBeforeCleanup       int    `json:"max_records_before_cleanup"`
}

type FirewallCounts struct {
	Allowed   int
	Blocked   int
	PortScans int
}
```
- `FirewallConfig`: A custom configuration card template. The text inside the backticks matches the settings keys in our JSON file so Go can automatically map them.
- `FirewallCounts`: Holds our global counters for how many lines were allowed, how many were blocked, and total scan alerts triggered during this session.

**This part creates a tiny tracking package that stores a single port number alongside its exact time snapshot.**
```bash
type PortAttempt struct {
	Port int
	Time time.Time
}
```
- `Port int`: Stores the numeric identity number of the port connection.
- `Time time.Time`: Records the exact clock stamp when that specific port was touched. Putting them together allows us to check time windows easily later.

**This part starts the program, greets the user, and triggers the configuration loader function.**
```bash
func main() {
	fmt.Println("--- ALINA'S LIVE PORT SECURITY SYSTEM ---")
	fmt.Println()

	config, err := loadFirewallConfig("firewall_config.json")
	if err != nil {
		fmt.Println("Error loading config:", err)
		return
	}
```
- `func main()`: The starting door where the program begins executing.
- `loadFirewallConfig(...)`: Reads our external settings sheet.
- `if err != nil`: Checks if something went wrong (like the file is missing). If there is an error, it prints a warning on the console and hits `return` to stop the script right away before it crashes.

**This part opens our traffic log file safely and sets up a memory reminder to close it later.**
```bash
	logFile, err := os.Open(config.ConnectionLogPath)
	if err != nil {
		fmt.Println("Error: could not open", config.ConnectionLogPath)
		return
	}
	defer logFile.Close()
```
- `os.Open(...)`: Opens our `firewall_logs.txt` data file.
- `defer logFile.Close()`: A very safe rule. It keeps the log file active right now but tells Go: *"Do not forget to lock and close this file the exact millisecond the main function finishes running."*

**This part creates the outbound text report sheets and the bad actor blocklists on our hard drive.**
```bash
	reportFile, err := os.Create("output.txt")
	if err != nil {
		fmt.Println("Error creating output report file")
		return
	}
	defer reportFile.Close()
	reportWriter := bufio.NewWriter(reportFile)

	blocklistFile, err := os.Create("blocked_source_ips.txt")
	if err != nil {
		fmt.Println("Error creating blocklist file")
		return
	}
	defer blocklistFile.Close()
	blocklistWriter := bufio.NewWriter(blocklistFile)
```
- `os.Create("output.txt")`: Makes a fresh text sheet to write our firewall report.
- `bufio.NewWriter(...)`: Instead of wasting system speed writing to the disk line by line, this collects text chunks inside RAM to save them faster in bigger bundles later.

**This part opens the SQLite database connection and runs a script to build the logging table layout.**
```bash
	db, err := sql.Open("sqlite", config.DatabaseName)
	if err != nil {
		fmt.Println("Error opening database:", err)
		return
	}
	defer db.Close()

	createTableSQL := `
	CREATE TABLE IF NOT EXISTS firewall_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		event_type TEXT,
		source_ip TEXT,
		port INTEGER,
		event_time TEXT
	);`
	_, err = db.Exec(createTableSQL)
	if err != nil {
		fmt.Println("Error creating table:", err)
		return
	}
```
- `sql.Open(...)`: Spawns our local database engine link.
- `CREATE TABLE IF NOT EXISTS`: A non-destructive database query statement. If the table is missing, it sets up our structured tracking columns; if it is already there, it leaves the old stored logs completely safe.

**This part creates tracking maps inside our active RAM to remember attack logs, suspicious users, and blocks.**
```bash
	counts := FirewallCounts{}
	ipPortAttempts := make(map[string][]PortAttempt)
	flaggedScanIPs := make(map[string]bool)
	ipBlockedAttemptTimes := make(map[string][]time.Time)
	suspiciousIPs := make(map[string]bool)
	blockedSourceIPs := make(map[string]bool)

	loadPreviouslyBlockedIPs(db, blockedSourceIPs)
```
- `make(map[string]...)`: Spawns dynamic memory ledger sheets. For example, `blockedSourceIPs` maps an IP string directly to a `true` or `false` flag.
- `loadPreviouslyBlockedIPs(...)`: Automatically looks into the database file right at startup. It moves previously banned actors into our fast RAM map so the firewall remembers who was blocked even if the server restarts.

**This part reads our traffic logs line by line until it hits the absolute end of the file.**
```bash
	reader := bufio.NewReader(logFile)
	for {
		line, err := reader.ReadString('\n')

		if len(line) > 0 {
			cleanLine := strings.TrimRight(line, "\r\n")
			if strings.TrimSpace(cleanLine) != "" {
				processConnectionLine(cleanLine, config, &counts, db,
					reportWriter, blocklistWriter,
					ipPortAttempts, flaggedScanIPs,
					ipBlockedAttemptTimes, suspiciousIPs, blockedSourceIPs)

				cleanupOldFirewallRecords(db, config.MaxRecordsBeforeCleanup)
			}
		}

		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Println("Error reading file:", err)
			break
		}
	}
```
- `for { ... }`: An infinite looping track.
- `reader.ReadString('\n')`: Reads text characters until it hits an enter/newline space.
- `strings.TrimRight(..., "\r\n")`: Erases invisible system line breaks so spacing bugs do not happen.
- `io.EOF`: Stands for *End of File*. When the scanner reaches the very last line of logs data, it gracefully hits `break` to leave the loop and proceed.

**This part prints the final session metrics onto the console screen and streams summaries into the report file.**
```bash
	fmt.Println()
	fmt.Println("\t\t\t---------- Firewall Summary ----------")
	fmt.Printf("Allowed connections: %d\n", counts.Allowed)
	fmt.Printf("Blocked connections: %d\n", counts.Blocked)
	fmt.Printf("Port scans detected: %d\n", counts.PortScans)

	reportWriter.WriteString("\n\t\t\t---------- Firewall Summary ----------\n")
	...
	for ip := range suspiciousIPs {
		reportWriter.WriteString(ip + "\n")
	}
	...
	reportWriter.Flush()
	blocklistWriter.Flush()
```
- `fmt.Printf`: Renders our counted metric balances clearly on the local screen interface.
- `reportWriter.WriteString(...)`: Dumps separated summary data into our report sheet.
- `reportWriter.Flush()`: Manually pushes out any last remaining bits of text lines from the RAM buffer straight onto our physical file disk so no proof gets lost.

**This part begins the line filtering function and splits the incoming text spaces into separate variable chunks.**
```bash
func processConnectionLine(
	line string,
	config FirewallConfig,
	counts *FirewallCounts,
	db *sql.DB,
	reportWriter *bufio.Writer,
	blocklistWriter *bufio.Writer,
	ipPortAttempts map[string][]PortAttempt,
	flaggedScanIPs map[string]bool,
	ipBlockedAttemptTimes map[string][]time.Time,
	suspiciousIPs map[string]bool,
	blockedSourceIPs map[string]bool,
) {
	parts := strings.Split(line, " ")
	if len(parts) < 4 {
		return
	}

	timestampText := parts[0] + " " + parts[1]
	sourceIP := parts[2]
```
- `strings.Split(line, " ")`: Chops a log string into separate pieces whenever a blank space occurs.
- `parts[0] + " " + parts[1]`: Combines the first two pieces to get a clean Date and Time string.
- `parts[2]`: Grabs the third piece, which holds the attacker's source IP address.

**This part runs an Early Drop security check to instantly ignore packet data coming from an already banned IP.**
```bash
	if blockedSourceIPs[sourceIP] {
		return
	}

	port, convErr := strconv.Atoi(parts[3])
	if convErr != nil {
		return
	}
```
- `if blockedSourceIPs[sourceIP]`: A main checkpoint. If the sender IP is already on our block list, the program stops right here. It drops the line instantly to save CPU power.
- `strconv.Atoi(parts[3])`: Converts the fourth text piece (destination port) from text into an actual number so we can check it.

**This part deploys a smart multi-format time parser framework to avoid parsing crashes.**
```bash
This part deploys a smart multi-format time parser fallback framework to avoid parsing crashes.
```bash
eventTime, parseErr := time.Parse("2006-01-02 15:04:05", timestampText)
if parseErr != nil {
	eventTime, parseErr = time.Parse("2006/01/02 15:04:05", timestampText)
	if parseErr != nil {
		fmt.Println("WARNING: could not read timestamp format, skipping entry line:", line)
		return
	}
}
```
- `time.Parse(...)`: Standard Go time reader template.
- `if parseErr != nil`: Fallback check. If the log uses dashes (-) and fails, the program instantly tries a second check using slashes (/). If both fail, it skips the line safely instead of freezing.

This part triggers the port validation check. If a dangerous port is touched, it logs an alert and triggers immediate flushes.
```bash
isBlocked := checkPort(port, config.BlockedPorts, counts)

if isBlocked {
	fmt.Printf("\a WARNING: Connection to port %d from %s is BLOCKED! (dangerous port)\n", port, sourceIP)
	reportWriter.WriteString(fmt.Sprintf("BLOCKED: %s tried port %d at %s\n", sourceIP, port, timestampText))
	reportWriter.Flush()
	saveFirewallEvent(db, "blocked_port", sourceIP, port, timestampText)
```
- `checkPort(...)`: Checks the destination port number against our blocked ports list.
- `reportWriter.Flush()`: Forces the text line onto the disk immediately on every single block, ensuring our logs stay safe even if a sudden crash happens.

This part tracks repeat offenses on unapproved ports across short sliding time windows.
```bash
windowDuration := time.Duration(config.PortScanWindowMinutes) * time.Minute
validTimes := []time.Time{}
for _, t := range ipBlockedAttemptTimes[sourceIP] {
	if eventTime.Sub(t) <= windowDuration {
		validTimes = append(validTimes, t)
	}
}
validTimes = append(validTimes, eventTime)
ipBlockedAttemptTimes[sourceIP] = validTimes
```
- `for _, t := range ...`: Loops through this specific IP's old attack timestamp history.
- `eventTime.Sub(t) <= windowDuration`: Wipes out old attack records that happened too long ago. Only active, rapid incidents are saved into the list.

This part executes our Two-Tier defense system, sorting incidents cleanly into watch lists or hard blocks.
```bash
if len(validTimes) >= config.RepeatOffenderBlockCount {
	if !blockedSourceIPs[sourceIP] {
		blockedSourceIPs[sourceIP] = true
		fmt.Printf("\a SOURCE IP BLOCKED: %s hit dangerous ports %d times...\n", sourceIP, len(validTimes))
		blocklistWriter.WriteString(sourceIP + "\n")
		blocklistWriter.Flush()
		saveFirewallEvent(db, "ip_blocked", sourceIP, 0, timestampText)
	}
} else if len(validTimes) >= config.RepeatOffenderSuspiciousCount {
	if !suspiciousIPs[sourceIP] {
		suspiciousIPs[sourceIP] = true
		fmt.Printf("\a SUSPICIOUS: %s hit dangerous ports %d times...\n", sourceIP, len(validTimes))
	}
}
```
- `len(validTimes) >= BlockCount`: If the rapid attack count hits the limit (4), it triggers a hard ban flag, writes to our banned text file, and logs it inside our database.
- `else if ... SuspiciousCount`: If it hits 2 attempts, it triggers a warning flag to put the IP under observation instead of jumping straight to a full block.

This part runs the logic loop for tracking unique port scanner attacks across our true sliding window.
```bash
windowDuration := time.Duration(config.PortScanWindowMinutes) * time.Minute
validAttempts := []PortAttempt{}
for _, attempt := range ipPortAttempts[sourceIP] {
	if eventTime.Sub(attempt.Time) <= windowDuration {
		validAttempts = append(validAttempts, attempt)
	}
}

alreadyTried := false
for _, attempt := range validAttempts {
	if attempt.Port == port {
		alreadyTried = true
	}
}
if alreadyTried == false {
	validAttempts = append(validAttempts, PortAttempt{Port: port, Time: eventTime})
}
ipPortAttempts[sourceIP] = validAttempts
```
- `for _, attempt := range ...`: Clears out old port logs that have outlived the window time boundary settings.
- `if attempt.Port == port`: If a scanner hits the same port repeatedly, it sets `alreadyTried` to `true`.
- `if alreadyTried == false`: If the packet targets a new, different port, the firewall adds it to our list, allowing us to accurately track real port scanner footprints.

This part triggers a Port Scan Alert if an IP touches too many different doors within the set time limit.
```bash
if len(validAttempts) >= config.PortScanThreshold {
	if !flaggedScanIPs[sourceIP] {
		flaggedScanIPs[sourceIP] = true
		counts.PortScans++
		fmt.Printf("\a PORT SCAN DETECTED: %s tried %d different ports...\n", sourceIP, len(validAttempts))
		saveFirewallEvent(db, "port_scan", sourceIP, 0, timestampText)
	}
}
```
- `len(validAttempts) >= PortScanThreshold`: Checks if different target fields cross our threshold limit (4). If yes, it adds a scan alert flag count and saves a permanent `port_scan` entry row inside our SQL table ledger.

This part handles our dynamic configuration parsing from the setting sheet.
```bash
func loadFirewallConfig(path string) (FirewallConfig, error) {
	var config FirewallConfig
	data, err := os.ReadFile(path)
	if err != nil {
		return config, err
	}
	err = json.Unmarshal(data, &config)
	return config, err
}
```
- `os.ReadFile(path)`: Grabs raw configuration data from our `firewall_config.json` sheet.
- `json.Unmarshal(...)`: Automatically maps the text content into our variables instantly so we can change settings without touching the code.

This part loops inside the unapproved list array to see if the target port connection is allowed or dangerous.
```bash
func checkPort(port int, blockedPorts []int, counts *FirewallCounts) bool {
	for _, blocked := range blockedPorts {
		if port == blocked {
			counts.Blocked++
			return true
		}
	}
	counts.Allowed++
	return false
}
```
- `for _, blocked := range blockedPorts`: Loops through your banned configuration numbers arrays. If a match occurs, it updates the `Blocked` counter reference address and returns `true`. If the loop finishes cleanly without a match, it adds 1 to `Allowed` and returns `false`.

This part inserts structured threat metrics into our local database ledger rows.
```bash
func saveFirewallEvent(db *sql.DB, eventType string, ip string, port int, timestamp string) {
	insertSQL := `INSERT INTO firewall_events (event_type, source_ip, port, event_time) VALUES (?, ?, ?, ?);`
	_, err := db.Exec(insertSQL, eventType, ip, port, timestamp)
}
```
- `INSERT INTO firewall_events (...)`: Relational database storage command.
- `db.Exec(...)`: Commits data metrics cleanly into rows without any code injection bugs.

This part runs an automated data lifecycle routine to prevent our database file from growing too large.
```bash
func cleanupOldFirewallRecords(db *sql.DB, maxRecords int) {
	cleanupSQL := `
	DELETE FROM firewall_events WHERE id NOT IN (
		SELECT id FROM firewall_events ORDER BY id DESC LIMIT ?
	);`
	_, err := db.Exec(cleanupSQL, maxRecords)
}
```
- `DELETE FROM ... id NOT IN`: A smart subquery command. It checks the absolute newest entries up to your configuration limit (100) and safely deletes anything older from the hard disk to keep storage size light and clean.

This part automatically loads previously blocked IPs from the database into our RAM maps on startup.
```bash
func loadPreviouslyBlockedIPs(db *sql.DB, blockedSourceIPs map[string]bool) {
	rows, err := db.Query("SELECT DISTINCT source_ip FROM firewall_events WHERE event_type = 'ip_blocked';")
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var ip string
		if scanErr := rows.Scan(&ip); scanErr == nil {
			blockedSourceIPs[ip] = true
		}
	}
}
```
- `db.Query(...)`: Searches the database for all unique IPs marked with the `ip_blocked` threat status.
- `blockedSourceIPs[ip] = true`: Loads those historical bad actors back into our active memory map so the firewall never forgets old blocks even after a script reboot.


---

## Sandbox expalination line by line:
```bash
upcoming in future
```
