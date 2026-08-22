# Port Firewall Security Tool

## What This Code Does

This is a Go program that reads a file full of network connection
logs and checks every line for signs of an attack, like someone
trying closed ports over and over. If it finds an IP hitting
dangerous ports, it flags it as suspicious after 2 attempts and
fully blocks it after 4 attempts, within a 2 minute rolling window.
It also catches an IP if it tries 4 different unique ports quickly,
which is called a port scan. It saves every threat into a small
database, writes a full report to a text file, and keeps that
database from growing forever on its own.

## Why I Built This

I wanted to actually understand how real firewall tools work,
instead of just reading about them. So I built a small version
myself, starting simple, and kept adding pieces one at a time, the
same way a real product grows over time: first just reading
connections, then tracking port scanners, then saving data properly,
then making it configurable.

## How This Relates to Cybersecurity

This program is a small, working example of a core cybersecurity
idea: watching activity closely and catching patterns that look like
an attack. Real attackers usually scan a system first to find open
doors before trying to break in. This program looks for exactly
that: not just "did someone connect to a port," but "did the same IP
touch several different unapproved ports, or hit dangerous ones
quickly," which is what actually separates a real attack from one
honest mistake.

## How This Relates to the Real World

Real companies run tools like Fail2Ban, or real hardware firewalls,
that do exactly this, just at a much bigger scale. They watch
thousands of servers, collect logs in one place, and automatically
drop bad connections right away so the system doesn't get
overloaded. This project follows the same basic shape: read logs,
detect a pattern, save the result, and take an action (blocking).
The settings file (`firewall_config.json`) lets the rules change
without touching the code itself.

---

## What I Learned Researching Real Attacks

Before finishing this project, I looked into how real attackers
actually scan networks, so I could check if my program's approach
made real sense, not just look right on the surface.

**Vertical and horizontal port scanning.** The basic version is one
attacker checking many different ports on one server to find an open
door, which is what my program watches for. I also learned attackers
do horizontal scanning: checking just one single port, like port 22,
across thousands of different servers at once. Catching that would
need tracking attempts across many destinations, not just one.

**Flooding a system even after it's blocked.** I learned that once an
IP is blocked, it can still send thousands of fake requests trying to
overload the program. That's why I added an early-drop check right
at the top of the function. If the IP is already on the blocklist,
the program stops processing it instantly, instead of wasting time
checking it again and again.

**Log time formats aren't always the same.** In the real world,
different servers write timestamps differently, some use dashes like
`2026-08-22`, others use slashes like `2026/08/22`. If a program only
understands one format, it silently skips real logs it can't read.
That's why I added a fallback: if the first format fails, it tries a
second one before giving up.

**Why a warning stage before blocking helps.** Real tools usually
flag an IP as suspicious before fully blocking it, instead of jumping
straight from nothing to blocked. This gives a chance to catch a
pattern early, and avoids blocking a real person who just typed the
wrong port by mistake. That's why I added a 2-attempt "suspicious"
warning before the 4-attempt full block.

**Buffered data can get lost.** I learned that programs which hold
report data in memory before saving can lose that data if the
program suddenly crashes or the power goes out. That's why I made
the report file save immediately after every important event,
instead of waiting until the very end.

**Where I could make this stronger next**, based on what I read:
- Actually use real system firewall commands to drop network traffic,
  not just write blocked IPs to a file.
- Add temporary blocking, so a real user who made an honest mistake
  gets unblocked automatically after 15-30 minutes.
- Build a simple web page to watch alerts live in a browser.

---

## How to Run This Code, Step by Step

1. **Open VS Code**, in the folder where `port_firewall.go`,
   `firewall_config.json`, and `firewall_logs.txt` are saved.

2. **Set up the Go project** in the built-in terminal:
   ```bash
   go mod init port-firewall
   go get modernc.org/sqlite
   ```

3. **Run the program:**
   ```bash
   go run port_firewall.go
   ```

4. **Check the results.** Three new files show up:
   - `output.txt` — the full written report and summary.
   - `blocked_source_ips.txt` — any source IPs that got auto-blocked.
   - `firewall_threats.db` — a small database with every threat saved
     in it.

---

## Files in This Folder

- `port_firewall.go` — the actual firewall program.
- `firewall_config.json` — settings the program reads, like blocked
  ports and time limits.
- `go.mod` and `go.sum` — files Go creates automatically to manage
  the database library this project uses.
- `firewall_logs.txt` — the sample log file with network traffic.
- `output.txt` — a saved copy of what the program printed when I ran
  it.

---

## Code Explained, Block by Block

**This part tells Go which tools it needs, to read files, talk to
the database, and work with time.**
```go
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
`os` is for opening files, `strconv` turns text into numbers, `time`
handles dates and minutes, and the last import loads the actual
database driver, so my SQL code has something to actually talk to.

**This part sets up two boxes to hold settings and counters.**
```go
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
`FirewallConfig` matches the settings in my JSON file, so Go can load
them straight into these fields. `FirewallCounts` just holds three
running totals for the whole session.

**This part stores a port together with the exact time it was tried.**
```go
type PortAttempt struct {
	Port int
	Time time.Time
}
```
I needed this because earlier I was only storing the port number by
itself, which made it impossible to correctly check if that specific
attempt was still inside the time window or not. Now each port
remembers its own timestamp.

**This part starts the program and loads the settings file.**
```go
func main() {
	fmt.Println("--- ALINA'S LIVE PORT SECURITY SYSTEM ---")
	fmt.Println()

	config, err := loadFirewallConfig("firewall_config.json")
	if err != nil {
		fmt.Println("Error loading config:", err)
		return
	}
```
If the settings file is missing or broken, the program prints an
error and stops right here, instead of continuing and crashing
somewhere confusing later.

**This part opens the log file and makes sure it gets closed properly
later.**
```go
	logFile, err := os.Open(config.ConnectionLogPath)
	if err != nil {
		fmt.Println("Error: could not open", config.ConnectionLogPath)
		return
	}
	defer logFile.Close()
```
`defer` means "do this automatically once the function is done,"
so I don't have to remember to close the file myself at every
possible exit point.

**This part creates the report file and the blocklist file.**
```go
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
`bufio.NewWriter` collects text in memory first, instead of writing
to disk one tiny piece at a time, which is faster.

**This part opens the database and builds the table if it doesn't
exist yet.**
```go
	db, err := sql.Open("sqlite", config.DatabaseName)
	...
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS firewall_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		event_type TEXT,
		source_ip TEXT,
		port INTEGER,
		event_time TEXT
	);`
	_, err = db.Exec(createTableSQL)
```
`IF NOT EXISTS` means this is safe to run every time the program
starts. If the table is already there from a previous run, this line
does nothing and leaves the old saved data untouched.

**This part sets up the tracking maps the program needs while it
runs.**
```go
	counts := FirewallCounts{}
	ipPortAttempts := make(map[string][]PortAttempt)
	flaggedScanIPs := make(map[string]bool)
	ipBlockedAttemptTimes := make(map[string][]time.Time)
	suspiciousIPs := make(map[string]bool)
	blockedSourceIPs := make(map[string]bool)

	loadPreviouslyBlockedIPs(db, blockedSourceIPs)
```
`loadPreviouslyBlockedIPs` checks the database right when the
program starts, and loads any IPs that were already blocked in a
past run. This means if the program is stopped and started again,
it doesn't forget who was already blocked, since that memory now
comes from the database, not just from RAM.

**This part reads the log file line by line, and could keep watching
for new lines forever.**
```go
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
This reads one line at a time, cleans up any leftover line-break
characters, and stops once it reaches `io.EOF`, meaning the end of
the file. A real, always-running version would wait a couple seconds
here instead of stopping, and check again for new lines, but this
version is a demo running on a fixed log file, so it stops once it's
read everything.

**This part prints and saves the final summary, split into clear
sections.**
```go
	fmt.Println("\t\t\t---------- Firewall Summary ----------")
	fmt.Printf("Allowed connections: %d\n", counts.Allowed)
	fmt.Printf("Blocked connections: %d\n", counts.Blocked)
	fmt.Printf("Port scans detected: %d\n", counts.PortScans)
	...
	reportWriter.WriteString("\n\t\t\t---------- Suspicious IPs ----------\n")
	for ip := range suspiciousIPs {
		reportWriter.WriteString(ip + "\n")
	}
	reportWriter.WriteString("\n\t\t\t---------- Blocked IPs ----------\n")
	for ip := range blockedSourceIPs {
		reportWriter.WriteString(ip + "\n")
	}
	reportWriter.Flush()
```
I split Suspicious IPs and Blocked IPs into their own separate
sections in the report, instead of mixing them together, so the
report is easier to actually read and make sense of.

**This part checks each line, but drops it instantly if the IP is
already blocked.**
```go
func processConnectionLine(...) {
	parts := strings.Split(line, " ")
	if len(parts) < 4 {
		return
	}
	timestampText := parts[0] + " " + parts[1]
	sourceIP := parts[2]

	if blockedSourceIPs[sourceIP] {
		return
	}

	port, convErr := strconv.Atoi(parts[3])
	if convErr != nil {
		return
	}
```
This early check matters a lot. Without it, an attacker could keep
sending thousands of requests even after being blocked, and the
program would still waste time checking every single one. This way,
a blocked IP's data gets dropped immediately, before any real work
happens.

**This part tries two different timestamp formats before giving up
on a line.**
```go
	eventTime, parseErr := time.Parse("2006-01-02 15:04:05", timestampText)
	if parseErr != nil {
		eventTime, parseErr = time.Parse("2006/01/02 15:04:05", timestampText)
		if parseErr != nil {
			fmt.Println("WARNING: could not read timestamp, skipping line:", line)
			return
		}
	}
```
Real logs don't always use the same date format. If the first format
doesn't match, it tries a second common one before finally giving up
and skipping that one line, instead of silently ignoring lines it
could have actually understood.

**This part checks if the port is dangerous, and saves the result
immediately.**
```go
	isBlocked := checkPort(port, config.BlockedPorts, counts)

	if isBlocked {
		fmt.Printf("\a WARNING: Connection to port %d from %s is BLOCKED! (dangerous port)\n", port, sourceIP)
		reportWriter.WriteString(fmt.Sprintf("BLOCKED: %s tried port %d at %s\n", sourceIP, port, timestampText))
		reportWriter.Flush()
		saveFirewallEvent(db, "blocked_port", sourceIP, port, timestampText)
```
`reportWriter.Flush()` right here means this line gets written to
disk immediately, not saved up in memory. If the program crashed a
second later, this specific threat would already be safely saved.

**This part keeps a rolling list of an IP's dangerous attempts,
dropping the old ones.**
```go
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
This goes through every past attempt time for this IP, and only
keeps the ones that are still within the time window. This matters,
because if I only compared each new event to the last one, a slow
attacker spacing out attempts every couple minutes could sneak past
the check, even though their total time span was way past the
window. Checking every stored time individually fixes that.

**This part decides between a warning and a full block.**
```go
		if len(validTimes) >= config.RepeatOffenderBlockCount && !blockedSourceIPs[sourceIP] {
			blockedSourceIPs[sourceIP] = true
			...
			blocklistWriter.WriteString(sourceIP + "\n")
			blocklistWriter.Flush()
			saveFirewallEvent(db, "ip_blocked", sourceIP, 0, timestampText)
		} else if len(validTimes) >= config.RepeatOffenderSuspiciousCount && !suspiciousIPs[sourceIP] {
			suspiciousIPs[sourceIP] = true
			...
		}
```
At 2 dangerous attempts, the IP just gets flagged as suspicious. At
4, it gets fully blocked, written to the blocklist file, and saved
to the database with the type `ip_blocked`, which is exactly what
`loadPreviouslyBlockedIPs` looks for when the program starts again.

**This part tracks unique ports touched by an IP, using the same
sliding window idea.**
```go
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
	if !alreadyTried {
		validAttempts = append(validAttempts, PortAttempt{Port: port, Time: eventTime})
	}
	ipPortAttempts[sourceIP] = validAttempts
```
Same fix as before, applied here too. Old port attempts outside the
window get dropped, and a port only gets added once, so trying the
same port five times doesn't count as five different ports.

**This part raises a port scan alert once enough different ports have
been touched.**
```go
	if len(validAttempts) >= config.PortScanThreshold && !flaggedScanIPs[sourceIP] {
		flaggedScanIPs[sourceIP] = true
		counts.PortScans++
		fmt.Printf("\a PORT SCAN DETECTED: %s tried %d different ports within %d minutes!\n",
			sourceIP, len(validAttempts), config.PortScanWindowMinutes)
		saveFirewallEvent(db, "port_scan", sourceIP, 0, timestampText)
	}
```
This is separate from the blocked-port logic. An IP could trigger a
port scan alert even by touching normal, non-dangerous ports, if it
touches enough different ones quickly, since that pattern itself is
suspicious.

**This part reads the settings file and turns it into something the
program can use.**
```go
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

**This part checks one port against the blocked list.**
```go
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
`counts` here is a pointer, so this function updates the real
counters in `main`, not a copy of them.

**This part saves one event into the database.**
```go
func saveFirewallEvent(db *sql.DB, eventType string, ip string, port int, timestamp string) {
	insertSQL := `INSERT INTO firewall_events (event_type, source_ip, port, event_time) VALUES (?, ?, ?, ?);`
	_, err := db.Exec(insertSQL, eventType, ip, port, timestamp)
}
```

**This part keeps the database from growing forever.**
```go
func cleanupOldFirewallRecords(db *sql.DB, maxRecords int) {
	cleanupSQL := `
	DELETE FROM firewall_events WHERE id NOT IN (
		SELECT id FROM firewall_events ORDER BY id DESC LIMIT ?
	);`
	_, err := db.Exec(cleanupSQL, maxRecords)
}
```
Once the row count passes the limit set in the config file, this
deletes the oldest rows and keeps only the most recent batch.

**This part loads previously blocked IPs back into memory when the
program starts.**
```go
func loadPreviouslyBlockedIPs(db *sql.DB, blockedSourceIPs map[string]bool) {
	rows, err := db.Query(`SELECT DISTINCT source_ip FROM firewall_events WHERE event_type = 'ip_blocked';`)
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
This is what makes blocking survive a restart. Without this, closing
and reopening the program would wipe every blocked IP from memory,
even though the attack history is still sitting safely in the
database.

---

## Coming Up in the Future

- Making the log reading actually run forever, instead of stopping
  at the end of the file, by adding a short wait and re-checking loop.
- Sending a real alert, like an email, when an IP gets blocked,
  instead of just writing it to a file.
- Adding temporary blocks instead of permanent ones, so an honest
  user isn't locked out forever by mistake.
- Designing a sandbox diagram for this project in Meshery's Kanvas
  tool, the same way I did for my auth log monitoring project.


