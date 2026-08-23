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

**Vertical and horizontal port scanning.** The basic version is one
attacker checking many different ports on one server to find an open
door, which is what my program watches for. I also learned attackers
do horizontal scanning: checking just one single port, like port 22,
across thousands of different servers at once. Catching that would
need tracking attempts across many destinations, not just one.

**Flooding a system even after it's blocked.** I learned that once
an IP is blocked, it can still send thousands of fake requests trying
to overload the program. That's why I added an early-drop check
right at the top of the function. If the IP is already on the
blocklist, the program stops processing it instantly, instead of
wasting time checking it again and again.

**Log time formats aren't always the same.** In the real world,
different servers write timestamps differently, some use dashes like
`2026-08-22`, others use slashes like `2026/08/22`. If a program
only understands one format, it silently skips real logs it can't
read. That's why I added a fallback: if the first format fails, it
tries a second one before giving up.

**Why a warning stage before blocking helps.** Real tools usually
flag an IP as suspicious before fully blocking it, instead of
jumping straight from nothing to blocked. This gives a chance to
catch a pattern early, and avoids blocking a real person who just
typed the wrong port by mistake. That's why I added a 2-attempt
"suspicious" warning before the 4-attempt full block.

**Buffered data can get lost.** I learned that programs which hold
report data in memory before saving can lose that data if the
program suddenly crashes or the power goes out. That's why I made
the report file save immediately after every important event,
instead of waiting until the very end.

**Where I could make this stronger next**, based on what I read:
- Actually use real system firewall commands to drop network
  traffic, not just write blocked IPs to a file.
- Add temporary blocking, so a real user who made an honest mistake
  gets unblocked automatically after 15-30 minutes.
- Build a simple web page to watch alerts live in a browser.

---

## How to Run This Code, Step by Step

### `go run` vs `go build`

`go run` compiles the code and runs it in one step, but doesn't save
anything afterward. `go build` compiles it into a real `.exe` file
that stays in the folder, so it can be run again anytime without
rebuilding, unless the code changes.

### Setup

1. **Download** `port_firewall.go`, `port_report.go`, and
   `firewall_config.json`, and put them all in the same folder,
   along with `firewall_logs.txt`.
2. **Open that folder in VS Code**, and open a terminal inside it.
3. **Set up the Go project:**
   ```bash
   go mod init port-firewall
   go get modernc.org/sqlite
   ```

### Running the Firewall Program

**Option A — `go run` (quick, one-time run):**
```bash
go run port_firewall.go
```

**Option B — `go build` (creates a reusable `.exe`):**
```bash
go build -o firewall.exe port_firewall.go
.\firewall.exe
```
After this, `firewall.exe` can be run again anytime with just
`.\firewall.exe`, without building it again.

**Check the results.** Three new files show up:
- `output.txt` — the full written report and summary.
- `blocked_source_ips.txt` — any source IPs that got auto-blocked.
- `firewall_threats.db` — a small database with every threat saved
  in it.

### Running the Report Tool

`port_report.go` sits in the same folder as the main program, and
just reads the same database, so it doesn't need its own separate
setup.

**Option A — `go run`:**
```bash
go run port_report.go
```

**Option B — `go build`:**
```bash
go build -o report.exe port_report.go
.\report.exe
```

---

## Files in This Folder

- `port_firewall.go` — the actual firewall program.
- `port_report.go` — a second, separate program that reads the same
  database and prints a clean status report.
- `firewall_config.json` — settings the program reads, like blocked
  ports and time limits.
- `go.mod` and `go.sum` — files Go creates automatically to manage
  the database library this project uses.
- `firewall_logs.txt` — the sample log file with network traffic.
- `output.txt` — a saved copy of what the program printed when I ran
  it.
- `firewall-demo.png` - the terminal screenshot aftering r=unning the code.

---

## Coming Up in the Future

- Making the log reading actually run forever, instead of stopping
  at the end of the file, by adding a short wait and re-checking
  loop.
- Sending a real alert, like an email, when an IP gets blocked,
  instead of just writing it to a file.
- Adding temporary blocks instead of permanent ones, so an honest
  user isn't locked out forever by mistake.
- Designing a sandbox diagram for this project in Meshery's Kanvas
  tool, the same way I did for my auth log monitoring project.
- Building separate blocked/suspicious tables in the database, like
  I did in my auth log project, instead of figuring out status from
  raw event types every time the report runs.

---

## Code Explained, Block by Block

**This part tells Go which tools it needs, to read files, talk to
the database, and work with time.**
```go
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

**This part stores a port together with the exact time it was
tried.**
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
config, err := loadFirewallConfig("firewall_config.json")
if err != nil {
	fmt.Println("Error loading config:", err)
	return
}
```
If the settings file is missing or broken, the program prints an
error and stops right here, instead of continuing and crashing
somewhere confusing later.

**This part opens the log file, and creates the report and blocklist
files.**
```go
logFile, err := os.Open(config.ConnectionLogPath)
...
reportFile, err := os.Create("output.txt")
...
blocklistFile, err := os.Create("blocked_source_ips.txt")
```
`defer logFile.Close()` means the file gets closed automatically
once the function finishes, so I don't have to remember to close it
myself at every exit point.

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
```
`IF NOT EXISTS` means this is safe to run every time the program
starts. If the table already exists from a previous run, this line
does nothing and leaves the old data untouched.

**This part sets up the tracking maps the program needs while it
runs, and loads old blocked IPs back in.**
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
past run. This means if the program is stopped and started again, it
doesn't forget who was already blocked, since that memory now comes
from the database, not just from RAM.

**This part reads the log file line by line, and could keep watching
for new lines forever.**
```go
reader := bufio.NewReader(logFile)
for {
	line, err := reader.ReadString('\n')
	...
	if err == io.EOF {
		break
	}
}
```
This reads one line at a time and stops once it reaches `io.EOF`,
the end of the file. A real, always-running version would wait a
couple seconds here instead of stopping, and check again for new
lines. This version stops once it's read everything, since it's a
demo running on a fixed log file.

**This part prints and saves the final summary, split into clear
sections.**
```go
fmt.Println("\t\t\t---------- Firewall Summary ----------")
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
I split Suspicious IPs and Blocked IPs into their own sections in
the report, instead of mixing them together, so the report is
easier to actually read.

**This part checks each line, but drops it instantly if the IP is
already blocked.**
```go
if blockedSourceIPs[sourceIP] {
	return
}
```
This early check matters a lot. Without it, an attacker could keep
sending thousands of requests even after being blocked, and the
program would still waste time checking every single one.

**This part tries two different timestamp formats before giving up
on a line.**
```go
eventTime, parseErr := time.Parse("2006-01-02 15:04:05", timestampText)
if parseErr != nil {
	eventTime, parseErr = time.Parse("2006/01/02 15:04:05", timestampText)
	if parseErr != nil {
		fmt.Println("WARNING: could not read timestamp format, skipping entry line:", line)
		return
	}
}
```
Real logs don't always use the same date format. If the first
format doesn't match, it tries a second common one before giving up
and skipping that line.

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
`reportWriter.Flush()` right here writes this line to disk
immediately, instead of holding it in memory. If the program crashed
a second later, this threat would already be safely saved.

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
keeps the ones still inside the time window. This matters, because
comparing only to the last event would let a slow attacker, spacing
out attempts every couple minutes, sneak past the check, even though
their total time span was way past the window. Checking every stored
time individually fixes that.

**This part decides between a warning and a full block.**
```go
if len(validTimes) >= config.RepeatOffenderBlockCount {
	if !blockedSourceIPs[sourceIP] {
		blockedSourceIPs[sourceIP] = true
		...
		blocklistWriter.WriteString(sourceIP + "\n")
		blocklistWriter.Flush()
		saveFirewallEvent(db, "ip_blocked", sourceIP, 0, timestampText)
	}
} else if len(validTimes) >= config.RepeatOffenderSuspiciousCount {
	if !suspiciousIPs[sourceIP] {
		suspiciousIPs[sourceIP] = true
		...
	}
}
```
At 2 dangerous attempts, the IP gets flagged as suspicious. At 4, it
gets fully blocked, written to the blocklist file, and saved to the
database with the type `ip_blocked`, which is exactly what
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
```
Same fix as before, applied here too. Old port attempts outside the
window get dropped, and a port only gets added once, so trying the
same port five times doesn't count as five different ports.

**This part raises a port scan alert once enough different ports
have been touched.**
```go
if len(validAttempts) >= config.PortScanThreshold {
	if !flaggedScanIPs[sourceIP] {
		flaggedScanIPs[sourceIP] = true
		counts.PortScans++
		fmt.Printf("\a PORT SCAN DETECTED: %s tried %d different ports within %d minutes!\n",
			sourceIP, len(validAttempts), config.PortScanWindowMinutes)
		saveFirewallEvent(db, "port_scan", sourceIP, 0, timestampText)
	}
}
```
This is separate from the blocked-port logic. An IP could trigger a
port scan alert even by touching normal, non-dangerous ports, if it
touches enough different ones quickly, since that pattern itself is
suspicious.

**This part reads the settings file, checks one port, saves an
event, and cleans up old records.**
```go
func loadFirewallConfig(path string) (FirewallConfig, error) { ... }
func checkPort(port int, blockedPorts []int, counts *FirewallCounts) bool { ... }
func saveFirewallEvent(db *sql.DB, eventType string, ip string, port int, timestamp string) { ... }
func cleanupOldFirewallRecords(db *sql.DB, maxRecords int) { ... }
```
`checkPort` takes `counts` as a pointer, so it updates the real
counters in `main`, not a copy of them. `cleanupOldFirewallRecords`
deletes the oldest rows once the count passes the config limit, and
keeps only the most recent batch, so the database doesn't grow
forever.

**This part loads previously blocked IPs back into memory when the
program starts.**
```go
func loadPreviouslyBlockedIPs(db *sql.DB, blockedSourceIPs map[string]bool) {
	rows, err := db.Query(`SELECT DISTINCT source_ip FROM firewall_events WHERE event_type = 'ip_blocked';`)
	...
}
```
This is what makes blocking survive a restart. Without it, closing
and reopening the program would wipe every blocked IP from memory,
even though the attack history is still sitting safely in the
database.

---

## Report Tool (`port_report.go`)

### What This Code Does

This is a second, separate program in the same folder. It doesn't
read the log file at all, it just opens the same database the main
program writes to, and prints which IPs have shown suspicious
activity and which ones are fully blocked.

### Why I Built This

Once the main program was saving everything into the database, I
wanted a quick way to check current status without opening the
database file by hand or scrolling through the whole `output.txt`
report.

### An Honest Note About How "Suspicious" Works Here

Unlike my auth log project, this program doesn't have separate
`suspicious_ips` and `blocked_ips` tables. It only has one
`firewall_events` table that logs every event type. So this report
tool figures out "suspicious" by just looking for any IP that ever
had a `port_scan` or `blocked_port` event. That means an IP that
eventually got fully blocked can still show up in the "suspicious"
list too, since it had those events on its way to being blocked.
It's not wrong, it's just a simpler way of showing activity, and
it's one of the things I'd want to clean up by adding proper status
tables like I did in my other project.

### Code Explained, Block by Block

**This part opens the same database the main program already wrote
to.**
```go
db, err := sql.Open("sqlite", "firewall_threats.db")
```

**This part prints any IP that ever showed suspicious activity.**
```go
func printPortSuspicious(db *sql.DB) {
	rows, err := db.Query("SELECT DISTINCT source_ip, event_time FROM firewall_events WHERE event_type IN ('port_scan', 'blocked_port') ORDER BY event_time DESC")
	...
	for rows.Next() {
		var ip string
		var eventTime string
		rows.Scan(&ip, &eventTime)
		fmt.Printf("  %s   flagged under watch at: %s\n", ip, eventTime)
		found = true
	}
}
```
`DISTINCT` means each IP only shows up once, even if it triggered
multiple port scans or blocked-port hits. `rows.Scan` pulls each
column from a row into a variable I can actually print.

**This part prints any IP that got fully blocked.**
```go
func printPortBlocked(db *sql.DB) {
	rows, err := db.Query("SELECT DISTINCT source_ip, event_time FROM firewall_events WHERE event_type = 'ip_blocked' ORDER BY event_time DESC")
	...
}
```
Same idea as above, just filtered to only the `ip_blocked` event
type instead.
