# Auth Log Monitoring

## What This Code Does

This is a Go program that reads a file full of security logs and
checks every line for signs of an attack, like someone trying wrong
passwords over and over. If it finds enough attempts from the same
IP address in a short time, it flags the IP as suspicious on 5
attempts and completely blocks it if it crosses 7 attempts within a
3-minute rolling window. It also saves every threat it finds into a
small database, writes a full report to a text file, and keeps that
database from growing forever by deleting old records automatically.

## Why I Built This

I wanted to actually understand how real security monitoring tools
work, instead of just reading about them. So I built a small version
myself, starting simple, and kept adding pieces one at a time, like a
real product would grow over time: first just reading logs, then
tracking repeat attackers, then saving data properly, then making it
configurable.

## How This Relates to Cybersecurity

This program is a small, working example of a core cybersecurity
idea: watching activity closely and catching patterns that look like
an attack. Real attackers usually don't try a password once, they try
many times, fast, hoping one guess works. This is called a brute
force attack. This program specifically looks for that pattern: not
just "did a password fail," but "did the same IP fail many times in
a short window," which is what actually separates a real attack from
one honest mistake.

## How This Relates to the Real World

Real companies run tools that do exactly this, just at a much bigger
scale. They watch thousands of servers, collect logs into one place,
and automatically flag or block IP addresses that look dangerous.
This project follows the same basic shape: read logs, detect a
pattern, store the result, and take an action (blocking). The
settings file (`config.json`) is also something real software always
has, so the rules can be changed without touching the code itself.

---

## What I Learned Researching Real Attacks

Before finishing this project, I looked into how real attackers
actually try to break into accounts, so I could check if my program's
approach made real sense, not just look right on the surface.

**Brute force and password spraying.** The most basic version is one
attacker trying many passwords against one account, which is exactly
what my program watches for. But I learned attackers also do the
opposite, called password spraying: trying one common password (like
"password123") against thousands of different accounts. This slips
past a system like mine, since no single account gets many failed
attempts, so I know that catching this would need me to track failed
attempts across accounts too, not just per IP.

**Attackers spread out across many IPs.** A big thing I learned is
that real attacks today rarely come from one IP address anymore.
Attackers use botnets and rotating IPs, so each IP only tries once or
twice, staying under any simple threshold. My program's IP-based
blocking works well against a simple, single-source attack, but a
real, well-resourced attacker could get around it by spreading
requests across many machines. Knowing this limitation matters, since
it shows IP blocking is one layer of defense, not a complete answer
by itself.

**Low and slow attacks.** Some attackers deliberately try very
slowly, like one login attempt every hour, specifically to stay under
detection thresholds. My program's time window (7 attempts in 3
minutes) would completely miss an attack like this. A stronger
version would need to also watch for smaller numbers of attempts over
a much longer period, not just short bursts.

**Why a warning stage before blocking helps.** Real tools often flag
an IP as suspicious before fully blocking it, instead of jumping
straight from "nothing" to "blocked." This gives a chance to review
what's happening before taking a stricter action, and avoids
accidentally blocking a real user who just mistyped their password a
few times. That's why I added the 5-attempt "suspicious" warning
stage before the 7-attempt block in this version, instead of only
having one single threshold.

**Temporary blocking matters too.** I also learned that real systems
usually block an IP temporarily (like for 15-30 minutes), not
forever. This matters because a real, honest user could mistype their
password a few times by accident. My program currently blocks
permanently once triggered, which is a simplification I'd want to fix
in a stronger version, by unblocking an IP automatically after a set
time has passed.

**Where I could make this stronger next**, based on what I read:
- Track failed attempts per username too, not just per IP, to catch
  password spraying.
- Track attempts over a longer window as well as a short one, to
  catch slow, patient attackers.
- Instead of only blocking, log a wider range of signals together
  (failed logins, unusual access times, unusual endpoints), since
  real detection tools rarely rely on just one signal alone.

---

## How to Run This Code, Step by Step
 
### `go run` vs `go build` — what's the difference
 
`go run` compiles the code and runs it immediately, in one step, but
doesn't save the compiled program anywhere afterward. It's quick and
good for testing while I'm still working on the code.
 
`go build` compiles the code into an actual `.exe` file (on Windows)
that gets saved in the folder. Once that file exists, it can be run
directly, any number of times, without needing Go or the source code
again at that moment. This is closer to how real software actually
gets shared and run, since the person running it doesn't need to
have Go installed or see the code at all.
 
That's also why I kept the report tool in its own separate folder,
with its own `go.mod` file: so it can be built into its own
standalone `.exe`, independent from the main monitoring program.
 
---
 
### Running the Main Monitoring Program
 
1. **Open VS Code**, in the folder where `auth_log_monitoring.go`,
   `config.json`, and `log.txt` are saved.
2. **Set up the Go project** in the built-in terminal:
```bash
   go mod init auth-monitor
   go get modernc.org/sqlite
```
3. **Run it one of two ways:**
   **Option A — `go run` (quick, one-time run):**
```bash
   go run auth_log_monitoring.go
```
 
   **Option B — `go build` (creates a reusable `.exe`):**
```bash
   go build -o monitor.exe auth_log_monitoring.go
   .\monitor.exe
```
   After this, `monitor.exe` can be run again anytime with just
   `.\monitor.exe`, without needing to build it again, unless the
   code changes.
 
4. **Check the results.** Three new files appear:
   - `output.txt` — the full written report
   - `blocked_ips.txt` — any IP addresses that got auto-blocked
   - `firewall_threats.db` — a small database with every threat saved in it
---
 
### Running the Report Tool
 
The report tool lives in its own `report-tool` subfolder, with its
own `go.mod`, so it can be built completely on its own, separate from
the main program.
 
1. **Open a terminal inside the `report-tool` folder** in VS Code.
2. **Set up its own Go project:**
```bash
   go mod init auth-report
   go get modernc.org/sqlite
```
3. **Run it one of two ways:**
   **Option A — `go run` (quick, one-time run):**
```bash
   go run auth_report.go
```
 
   **Option B — `go build` (creates a reusable `.exe`):**
```bash
   go build -o report.exe auth_report.go
   .\report.exe
```
   After this, `report.exe` can be run again anytime, straight from
   this folder, without rebuilding it.
 
This tool needs to run somewhere it can reach `firewall_threats.db`,
since it just reads that same database file the main program already
created.

---

## Files in This Folder

- `auth_log_monitoring.go` — the actual program.
- `config.json` — settings the program reads, like the block
  threshold and file paths.
- `go.mod` and `go.sum` — files Go creates automatically to keep
  track of which libraries this project uses.
- `log.txt` — the sample log file the program reads and checks.
- `output.txt` — a saved copy of what the program printed when I ran
  it.
- `monitor-demo.png` — a screenshot of this program running in the
  terminal.
- `report-tool/` — a subfolder with a second program that reads the
  same database and prints a clean status report. Contains
  `auth_report.go`, its own `go.mod` and `go.sum`, and
  `report-demo.png`, a screenshot of that program's terminal output.

---

## Coming Up in the Future

- Making the live tail actually run forever, instead of stopping at
  the end of the file, by adding a short wait and re-checking loop.
- Sending a real alert (like an email) when an IP gets blocked,
  instead of just writing it to a file.
- A simple web page to view the report live in a browser, instead of
  only in the terminal or a text file.
- Designing a sandbox diagram for this project in Meshery's Kanvas
  tool.

These are all things I plan to learn and add as I keep improving this
project.

---

## Code Explained, Block by Block

**This part lets Go know which external and standard tool libraries
this program needs to work.**
```go
import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)
```
This imports standard tools for reading files, handling text,
reading timestamps, and setting up the database. The underscore
before the SQLite import tells Go to load the database driver in the
background, so the rest of the code can just use `sql.Open` without
calling that package by name directly.

**This part sets up two structs to organize our counters and
settings.**
```go
type ThreatCounts struct {
	FailedPassword     int
	UnauthorizedAccess int
	PortScan           int
}

type Config struct {
	LogFilePath              string `json:"log_file_path"`
	DatabaseName              string `json:"database_name"`
	BlockThreshold            int    `json:"block_threshold"`
	BlockTimeWindowMinutes    int    `json:"block_time_window_minutes"`
	MaxRecordsBeforeCleanup   int    `json:"max_records_before_cleanup"`
}
```
`ThreatCounts` groups all the running totals in one place.
`Config` matches the exact settings inside `config.json`, so Go can
read that file and drop the values straight into these fields.

**This part loads all the settings from `config.json`, instead of
having them hard-coded in the program.**
```go
config, err := loadConfig("config.json")
```
If someone wants to change the threshold from 7 to 10 later, they
just edit the JSON file. No code changes needed.

**This part creates the output report file and sets up the database
connection.**
```go
reportFile, err := os.Create("security_report.txt")
...
db, err := sql.Open("sqlite", config.DatabaseName)
...
createTableSQL := `CREATE TABLE IF NOT EXISTS threats (...)`
```
This opens the file where the written report gets saved, and
connects to the SQLite database. `CREATE TABLE IF NOT EXISTS` means
if the table already exists from an earlier run, this line does
nothing and leaves the old data alone.

**This part creates two extra tables, just for blocked and
suspicious IPs.**
```go
createBlockedTableSQL := `
CREATE TABLE IF NOT EXISTS blocked_ips (
	ip_address TEXT PRIMARY KEY,
	attempts_count INTEGER,
	blocked_at TEXT
);`

createSuspiciousTableSQL := `
CREATE TABLE IF NOT EXISTS suspicious_ips (
	ip_address TEXT PRIMARY KEY,
	attempts_count INTEGER,
	flagged_at TEXT
);`
```
This is one of the changes I added. The `threats` table logs every
single event as its own row, which is great for history, but it
doesn't directly answer "who is currently blocked right now." These
two tables exist just for that: one row per IP, so checking current
status is fast and simple, without having to scan through every
event ever logged.

**This part sets up the maps the program uses while it runs.**
```go
ipAttackTimes := make(map[string][]time.Time)
blockedIPs := make(map[string]bool)
suspiciousIPs := make(map[string]bool)
```
`ipAttackTimes` keeps a list of attack timestamps per IP. The other
two just remember which IPs are already flagged or blocked, so the
program doesn't print the same warning over and over.

**This part finds IP addresses using a pattern, not guesswork.**
```go
var ipRegex = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
```
This searches a line of text for anything shaped like an IP address,
no matter where it appears in the line. Earlier, I was just grabbing
the last word in the line and assuming it was an IP, which broke on
lines that didn't have one at all.

**This part reads the log file one line at a time, in a way that
could keep watching for new lines.**
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
This reads line by line and checks for the end of the file. In a
real, always-running version, instead of stopping at the end, it
would wait a couple of seconds and check again, so it never misses a
new line being added. Right now it stops once it reaches the end,
since this is a demo running on a fixed log file.

**This part checks each line and figures out what kind of threat it
is, if any.**
```go
func processLine(logLine string, counts *ThreatCounts) (bool, string, string) {
```
`*ThreatCounts` here is a pointer. Instead of handing this function a
copy of my counters, I hand it the real counters directly, so when it
adds one to `FailedPassword`, it updates the actual counter, not a
copy that disappears afterward.

**This part pulls the timestamp out from between the square
brackets.**
```go
if strings.HasPrefix(logLine, "[") {
	endBracket := strings.Index(logLine, "]")
	if endBracket != -1 {
		timestamp = logLine[1:endBracket]
	}
}
```
My log format looks like `[2026-08-20 10:00:22] Keycloak - WARN:
...`, so this finds where the brackets start and end, and grabs just
the clean date and time from inside them.

**This part only counts something as a threat if the wording is
specific enough.**
```go
if strings.Contains(logLine, "CRITICAL") && strings.Contains(logLine, "Failed password") {
```
Earlier, I was just checking for words like "Port scan" anywhere in a
line. That's risky, because a totally normal log line could
accidentally get flagged. Checking for the specific level
(`CRITICAL`) together with the exact phrase makes this much less
likely to trigger by mistake.

**This part tracks how many times each IP attacked, but only within
a short time window.**
```go
windowDuration := time.Duration(config.BlockTimeWindowMinutes) * time.Minute
validTimes := []time.Time{}
for _, t := range ipAttackTimes[extractedIP] {
    if eventTime.Sub(t) <= windowDuration {
        validTimes = append(validTimes, t)
    }
}
```
This keeps a list of attack times for each IP. Every time a new
attack comes in, it throws out any old attack times that happened too
long ago, then adds the new one. Someone failing a password once
today and once next week isn't a brute force attack. Someone failing
it seven times in three minutes clearly is.

**This part has two warning levels, not just one, and now also
writes each level into its own table.**
```go
if len(validTimes) >= config.BlockThreshold && !blockedIPs[extractedIP] {
    blockedIPs[extractedIP] = true
    ...
    db.Exec(
        "INSERT OR REPLACE INTO blocked_ips (ip_address, attempts_count, blocked_at) VALUES (?, ?, ?)",
        extractedIP, len(validTimes), timestamp,
    )
} else if len(validTimes) >= 5 && !suspiciousIPs[extractedIP] {
    suspiciousIPs[extractedIP] = true
    ...
    db.Exec(
        "INSERT OR REPLACE INTO suspicious_ips (ip_address, attempts_count, flagged_at) VALUES (?, ?, ?)",
        extractedIP, len(validTimes), timestamp,
    )
}
```
This is the other change I added. At 5 attempts, the IP gets marked
suspicious, and now also gets saved into the `suspicious_ips` table.
At 7, it gets blocked, and gets saved into `blocked_ips` instead.
`INSERT OR REPLACE` means if that IP already has a row (say it was
suspicious before and is now blocked), it just updates that same row
instead of creating a duplicate one.

**This part skips tracking if there's no IP at all.**
```go
if extractedIP != "" {
```
Some log lines, like a blocked guest attempt, don't have an IP
address in them. Without this check, an empty result would have been
treated like a real IP.

**This part saves every threat into the database.**
```go
func saveThreatToDatabase(db *sql.DB, threatType string, ip string, timestamp string) {
    insertSQL := `INSERT INTO threats (threat_type, ip_address, event_time) VALUES (?, ?, ?);`
    db.Exec(insertSQL, threatType, ip, timestamp)
}
```
This adds one new row every time a threat is found, so nothing gets
lost.

**This part keeps the database from growing forever.**
```go
func cleanupOldRecords(db *sql.DB, maxRecords int) {
    cleanupSQL := `DELETE FROM threats WHERE id NOT IN (
        SELECT id FROM threats ORDER BY id DESC LIMIT ?
    );`
    db.Exec(cleanupSQL, maxRecords)
}
```
Once the number of saved threats goes past the limit set in
`config.json`, this deletes the oldest ones and keeps only the most
recent batch.

---

## Report Tool (`report-tool/auth_report.go`)

### What This Code Does

This is a second, separate program. It doesn't read the log file at
all, it just opens the same database that the main program writes
to, and prints a clean, readable report of who is currently
suspicious and who is currently blocked.

### Why I Built This

Once I added the `blocked_ips` and `suspicious_ips` tables to the
main program, I realized I now had a quick way to check current
status without digging through the whole `threats` table by hand. So
I built a tiny second tool whose only job is to read those two tables
and print them nicely.

### Files in This Folder

- `auth_report.go` — the report program.
- `go.mod` and `go.sum` — Go's own files for managing the database
  library this program uses too.
- `report-demo.png` — a screenshot of this program's terminal output.

### How to Run It

In VS Code, open a terminal inside the `report-tool` folder, then:

```bash
go mod init auth-report
go get modernc.org/sqlite
go run auth_report.go
```

This needs to run in a place where it can reach `firewall_threats.db`,
since it just connects to that same database file that the main
program already created and wrote to.

### Code Explained, Block by Block

**This part opens the same database the main program already wrote
to.**
```go
db, err := sql.Open("sqlite", "firewall_threats.db")
```
This tool doesn't create anything new, it just connects to a
database file that should already exist from running the main
program first.

**This part prints the suspicious IPs.**
```go
func printSuspicious(db *sql.DB) {
	rows, err := db.Query("SELECT ip_address, attempts_count, flagged_at FROM suspicious_ips ORDER BY flagged_at DESC")
	...
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
```
This asks the database for every row in `suspicious_ips`, newest
first, and prints each one. `rows.Scan` pulls each column from a row
into a variable I can actually use. If there are no rows at all, it
prints a message saying so, instead of just showing nothing and
looking broken.

**This part prints the blocked IPs.**
```go
func printBlocked(db *sql.DB) {
	rows, err := db.Query("SELECT ip_address, attempts_count, blocked_at FROM blocked_ips ORDER BY blocked_at DESC")
	...
}
```
This works exactly the same way as `printSuspicious`, just reading
from the `blocked_ips` table instead.
 
## Sandbox Explanation

```bash
NOTE: upcoming in future
```
