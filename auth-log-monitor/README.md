# Auth Log Monitoring
 
## What This Code Does
 
This is a Go program that reads a file full of security logs and
checks every line for signs of an attack, like someone trying wrong
passwords over and over. If it finds enough attempts from the same
IP address in a short time, it marks that IP as blocked. It also
saves every threat it finds into a small database, writes a full
report to a text file, and keeps that database from growing forever
by deleting old records automatically.
 
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
 
1. **Get a Linux terminal.** I used Killercoda (`killercoda.com`), a
   free browser based terminal, since I don't want to install
   anything on my own computer.
2. **Install Go**, if it isn't already installed:
```bash
   sudo apt update && sudo apt install -y golang-go
```
 
3. **Make a folder and go into it:**
```bash
   mkdir auth-monitor && cd auth-monitor
```
 
4. **Upload three files into this folder:** `auth_log_monitoring.go`,
   `config.json`, and `log.txt`.
5. **Set up the Go project and get the database library:**
```bash
   go mod init auth-monitor
   go get modernc.org/sqlite
```
 
6. **Run the program:**
```bash
   go run auth_log_monitoring.go
```
 
7. **Check the results.** Three new files appear:
   - `security_report.txt` — the full written report
   - `blocked_ips.txt` — any IP addresses that got auto-blocked
   - `threats.db` — a small database with every threat saved in it

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
---
 

 
## Coming Up in the Future
 
- Making the live tail actually run forever, instead of stopping at
  the end of the file, by adding a short wait and re-checking loop.
- Sending a real alert (like an email) when an IP gets blocked,
  instead of just writing it to a file.
- A simple web page to view the report live in a browser, instead of
  only in the terminal or a text file.
These are all things I plan to learn and add as I keep improving this
project.






---

## Code Explained, Block by Block
 
**This part loads all the settings from `config.json`, instead of
having them hard-coded in the program.**
```go
config, err := loadConfig("config.json")
```
This reads the settings file and turns it into something the program
can actually use, like the block threshold and file paths. If
someone wants to change the threshold from 7 to 10 later, they just
edit the JSON file. No code changes needed.
 
**This part finds IP addresses using a pattern, not guesswork.**
```go
var ipRegex = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
```
This is called a regular expression. It searches a line of text for
anything shaped like an IP address (four numbers separated by dots),
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
Instead of reading the whole file once and stopping, this reads line
by line and checks for the end of the file. In a real, always-running
version, instead of stopping at the end, it would just wait a couple
of seconds and check again, so it never misses a new line being
added. Right now it stops once it reaches the end, since this is a
demo running on a fixed log file.
 
**This part checks each line and figures out what kind of threat it
is, if any.**
```go
func processLine(logLine string, counts *ThreatCounts) (bool, string, string) {
```
The `*ThreatCounts` here is called a pointer. Instead of handing this
function a copy of my counters, I hand it the real counters directly.
So when this function adds one to `FailedPassword`, it's updating the
actual, original counter, not a copy that disappears afterward.
 
**This part only counts something as a threat if the wording is
specific enough.**
```go
if strings.Contains(logLine, "CRITICAL") && strings.Contains(logLine, "Failed password") {
```
Earlier, I was just checking for words like "Port scan" anywhere in a
line. That's risky, because a totally normal log line, like someone
mentioning they're testing something, could accidentally get flagged.
Checking for the specific level (`CRITICAL`) together with the exact
phrase makes this much less likely to trigger by mistake.
 
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
attack comes in, it throws out any old attack times that happened
too long ago (outside the time window), then adds the new one. This
matters because someone failing a password once today and once next
week isn't really a brute force attack. Someone failing it seven
times in three minutes clearly is.
 
**This part has two warning levels, not just one.**
```go
if len(validTimes) >= config.BlockThreshold && !blockedIPs[extractedIP] {
    // block it
} else if len(validTimes) >= 5 && !suspiciousIPs[extractedIP] {
    // just watch it closely, don't block yet
}
```
Instead of only having one threshold that jumps straight to blocking,
this adds an earlier stage. At 5 attempts, the IP gets marked as
"suspicious" and a warning is printed, but nothing is blocked yet. It
only actually gets blocked once it crosses the real threshold (7).
This is closer to how real security tools behave, giving a chance to
notice a pattern early, instead of only reacting once it's already a
confirmed attack.
 
**This part skips tracking if there's no IP at all.**
```go
if extractedIP != "" {
```
Some log lines, like a blocked guest attempt, don't have an IP
address in them. Without this check, an empty result would have been
treated like a real IP and could have ended up wrongly blocked.
 
**This part saves every threat into a small database file.**
```go
func saveThreatToDatabase(db *sql.DB, threatType string, ip string, timestamp string) {
    insertSQL := `INSERT INTO threats (threat_type, ip_address, event_time) VALUES (?, ?, ?);`
    db.Exec(insertSQL, threatType, ip, timestamp)
}
``` 
This is a normal SQL command, which just means it's a standard way to
talk to a database. It adds one new row every time a threat is
found, so nothing gets lost, and it can be looked up again later.
 
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
recent batch. Without this, the database file would just keep
growing bigger, forever, the longer the program runs.
 
---
 
## Sandbox Explanation

```bash
NOTE: upcoming in future
```
