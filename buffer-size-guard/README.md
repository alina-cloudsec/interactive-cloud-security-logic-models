# Buffer Input Guard
 
## What This Code Does
 
This is a Go program that acts like a security guard for user input.
It asks the user to type a message in the terminal, and checks if
that input is too big (too many bytes) before accepting it. If the
same session keeps sending oversized input, it gets flagged as
suspicious after a few rejected attempts, and fully blocked after
more. Every attempt gets saved into a small database and a readable
log file, and old history gets cleaned up automatically after a set
number of hours.
 
## Why I Built This
 
I started with a very small version of this idea: just check if
input is too long, print a warning, and block after 3 tries. I
wanted to grow it into something closer to how a real system would
actually track this, with settings that can be changed, a real
history saved to a database, and a way to check status later instead
of everything disappearing when the program closes.
 
## How This Relates to Cybersecurity
 
This program is a small, working example of input validation, one of
the most basic and most important ideas in cybersecurity. In real
systems written in languages like C, if a program doesn't check how
big incoming data is before storing it, that oversized data can spill
into memory it was never supposed to touch. This is called a buffer
overflow, and it's one of the oldest, most common ways real software
gets exploited. It can crash a program, or in serious cases, let an
attacker run their own code on the system. This program checks the
size of input before accepting it, which is exactly the kind of
check that prevents that from happening in the first place.
 
## How This Relates to the Real World
 
Real applications validate input length constantly, from web forms
to APIs to login systems, because accepting unchecked input is one of
the easiest ways for something to go wrong, whether that's an
accident or an actual attack. Repeatedly sending oversized input on
purpose is also a basic way attackers try to overwhelm or crash a
system, sometimes just to cause a denial of service. Flagging and
blocking a source that keeps doing this, which is what this program
does, is a small version of the same defense real systems use.
 
---
 
## What I Learned Researching Real Attacks
 
**Buffer overflows are still a real, common problem.** Even though
this is an old vulnerability type, it still shows up in real software
today, especially in lower-level languages like C and C++ where
memory isn't managed automatically. A single missing length check
can be the entire difference between safe code and an exploitable
one.
 
**Oversized input isn't always about overflowing memory.** I learned
attackers also send huge input just to slow a system down or crash
it, without needing to corrupt memory at all. This is a form of
denial of service, so rejecting oversized input protects against more
than just memory corruption specifically.
 
**Tracking history matters more than tracking one session.** My
first version only remembered attempts during a single run. This
version saves everything into a database instead, so a source that
gets blocked stays blocked even if the program restarts. Real
systems don't forget a known bad actor just because they got
restarted.
 
**Where I could make this stronger next:**
- Track oversized attempts within an actual sliding time window
  (like my other two projects do), instead of a total historical
  count, so a slow trickle of old attempts doesn't count the same as
  a fast burst.
- Unblock a source automatically after some time, instead of keeping
  every block permanent.
- Check the actual content of input too, not just its length, since
  a short but malicious input could still get through.
---
 
## How to Run This Code, Step by Step
 
### `go run` vs `go build`
 
`go run` compiles and runs the code in one step, but doesn't save
anything afterward. `go build` compiles it into a real `.exe` file
that can be run again anytime, without rebuilding, unless the code
changes.
 
### Running the Main Guard Program
 
1. **Open VS Code**, in the folder with `buffer-guard.go` and
   `buffer-guard-config.json`.
2. **Set up the Go project:**
```bash
   go mod init buffer-guard
   go get modernc.org/sqlite
```
3. **Run it:**
   **Option A — quick run:**
```bash
   go run buffer-guard.go
```
 
   **Option B — build a reusable program:**
```bash
   go build -o guard.exe buffer-guard.go
   .\guard.exe
```
4. Type a message when prompted. Try something short (safe) and
   something long (rejected) to see both results.
5. **Check the results:**
   - `buffer-guard-log.txt` — a readable log of every attempt
   - `buffer-guard-history.db` — the full database with every
     attempt, suspicious flags, and blocks saved in it
### Running the Report Tool
 
The report tool lives in its own `report-tool` subfolder, with its
own `go.mod`.
 
1. **Open a terminal inside `report-tool`** in VS Code.
2. **Set up its own Go project:**
```bash
   go mod init buffer-report
   go get modernc.org/sqlite
```
3. **Run it:**
```bash
   go run buffer_report.go
```
   or build it the same way as above with `go build`.
 
This needs to run somewhere it can reach `buffer-guard-history.db`,
since it just reads that same database.
 
---
 
## Files in This Folder
 
- `buffer-guard.go` — the actual guard program.
- `buffer-guard-config.json` — settings like the size limit, warning
  and block thresholds, and file paths.
- `go.mod` and `go.sum` — files Go creates automatically for the
  database library.
- `buffer-guard-log.txt` — a saved, readable log of attempts.
- `buffer-report.go` — a second program that reads the
  database and prints a clean status report
- `buffer-guard-demo.png` a screenshot of it running.
---
 
## Coming Up in the Future
 
- Adding a real sliding time window for oversized attempts, instead
  of a total historical count.
- Automatically unblocking a source after a set amount of time.
- Checking input content, not just input length.
---
 
## Code Explained, Block by Block
 
**This part sets up the settings this program reads from
`buffer-guard-config.json`.**
```go
type Config struct {
	MaxInputBytes            int64  `json:"max_input_bytes"`
	WarningAfterAttempts     int    `json:"warning_after_attempts"`
	BlockAfterAttempts       int    `json:"block_after_attempts"`
	LogFile                  string `json:"log_file"`
	DatabaseFile              string `json:"database_file"`
	HistoryCleanupAfterHours int    `json:"history_cleanup_after_hours"`
}
```
This matches the exact fields in the JSON file, so the settings can
be changed without touching the code at all.
 
**This part writes a simple, readable line into a log file every
time something happens.**
```go
func writeLog(path string, message string) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	...
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	line := fmt.Sprintf("[%s] %s\n", timestamp, message)
	file.WriteString(line)
}
```
`os.O_APPEND` means new lines get added to the end of the file
instead of erasing what's already there. This runs every single time
an event happens, so the log always has the full history, even if
the program stops unexpectedly.
 
**This part sets up the database and creates three tables if they
don't already exist.**
```go
createHistory := `CREATE TABLE IF NOT EXISTS attempt_history (...)`
createSuspicious := `CREATE TABLE IF NOT EXISTS suspicious_ips (...)`
createBlocked := `CREATE TABLE IF NOT EXISTS blocked_ips (...)`
```
`attempt_history` logs every single attempt, accepted or rejected.
`suspicious_ips` and `blocked_ips` each hold one row per IP, so
current status can be checked quickly without scanning the whole
history table.
 
**This part checks if an IP is already fully blocked.**
```go
func isBlocked(db *sql.DB, ip string) bool {
	var foundIP string
	row := db.QueryRow("SELECT ip FROM blocked_ips WHERE ip = ?", ip)
	err := row.Scan(&foundIP)
	return err == nil
}
```
If the query finds a matching row, `err` comes back as `nil`
(meaning no error), which means the IP was found, so it's blocked. If
no row matches, `err` won't be `nil`, meaning it's not blocked. This
check happens right at the start of the program, before any input is
even asked for, so an already-blocked IP gets refused immediately.
 
**This part counts how many times this IP's input has been rejected,
based on the database, not memory.**
```go
func countRejected(db *sql.DB, ip string) int {
	var count int
	row := db.QueryRow("SELECT COUNT(*) FROM attempt_history WHERE session_ip = ? AND status = 'REJECTED'", ip)
	row.Scan(&count)
	return count
}
```
This is different from my other two projects, where I tracked a
precise sliding time window using timestamps in memory. Here, the
count comes straight from the database instead, combined with the
cleanup function that deletes anything older than a set number of
hours. It's simpler, and it means the count survives a restart since
it's not just sitting in memory, but it's less precise about exact
timing than a true sliding window.
 
**This part reads user input, but physically limits how many bytes
it can even read.**
```go
func readGuardedInput(maxBytes int64) string {
	limited := io.LimitReader(os.Stdin, maxBytes+1)
	reader := bufio.NewReader(limited)
	raw, _ := reader.ReadString('\n')
	return strings.TrimSpace(raw)
}
```
`io.LimitReader` wraps the input source so it physically cannot read
more than `maxBytes+1` characters, no matter what the user types.
This is closer to how a real guard would work: not just checking the
size after the fact, but limiting how much can even come in in the
first place.
 
**This part runs the main loop: ask for input, check it, and react.**
```go
for attempt < 20 {
	attempt = attempt + 1
	input := readGuardedInput(cfg.MaxInputBytes)
	size := int64(len(input))
 
	if size <= cfg.MaxInputBytes {
		saveAttempt(db, sessionIP, attempt, size, "ACCEPTED")
		success = true
		break
	}
 
	saveAttempt(db, sessionIP, attempt, size, "REJECTED")
	rejectedCount := countRejected(db, sessionIP)
 
	if rejectedCount >= cfg.BlockAfterAttempts {
		blockIP(db, sessionIP)
		return
	} else if rejectedCount >= cfg.WarningAfterAttempts {
		markSuspicious(db, sessionIP)
	}
}
```
The loop caps at 20 tries total, just as a safety limit so it can't
run forever. Every attempt gets saved to the database right away,
accepted or rejected. If the rejected count crosses the block
threshold, the program blocks the IP and ends immediately with
`return`. If it's past the warning threshold but not the block
threshold yet, it just flags the IP as suspicious and lets the user
try again.
 
