# Cloud Site Checker

## What This Code Does

This is a Go program that checks if a list of websites is actually
up and reachable. It reads a list of URLs from a text file, and for
each one, tries to connect with a timeout and a few retries in case
of a quick network hiccup. If a site fails enough times in a row
across separate checks, it gets marked as a confirmed outage instead
of just a one-time warning. Every check gets saved into a log file,
an output report, and a database, which also cleans itself up so it
doesn't grow forever.

## Why I Built This

I started with a version that just checked one URL, typed in by
hand. I wanted to grow it into something closer to how real uptime
monitoring actually works: watching a whole list of sites, and not
overreacting to a single failed check, since a website can just have
one slow moment without actually being down.

## How This Relates to Cybersecurity

Availability is one of the three core ideas in cybersecurity, right
alongside confidentiality and integrity. A system that's been taken
down, whether by an attack or just a real failure, isn't secure
either, even if no data was ever touched. Watching for outages and
knowing quickly when something goes down is part of keeping a system
trustworthy, not just protected from data theft.

## How This Relates to the Real World

Real companies run uptime monitoring tools, like UptimeRobot or
Pingdom, that do exactly this at scale, checking hundreds of
endpoints on a schedule and alerting a team the moment something
looks wrong. They all share the same basic idea this program uses:
don't trust a single failed check completely, since networks hiccup
sometimes, but do take it seriously once a pattern of repeated
failures shows up.

---

## What I Learned Researching Real Attacks

**A stuck connection is its own kind of problem.** I learned that
Go's default HTTP client has no timeout at all. If a site hangs
without ever responding, a program using the default client would
just wait forever. That's exactly the kind of thing attackers can
exploit on purpose, called a slow-loris style attack, where a
connection is kept just barely alive to tie up resources. Setting an
explicit timeout closes that gap.

**A retry and a real outage are two different things.** At first I
only had a check retry a few times if it failed, right there in the
moment. But I learned real monitoring tools separate that from a
"confirmed down" alert, which only fires after the site has failed
across several separate checks over time, not just a few retries
within one single check. That's why this program tracks a
consecutive-failure streak across saved history, not just retries
inside one attempt.

**Not every non-200 response means failure.** I learned a healthy
response isn't only status code 200. Codes like 201 or 204 also mean
success, they just mean slightly different things happened. Treating
the whole 200-299 range as healthy, instead of only checking for
exactly 200, avoids flagging a perfectly fine site as down just
because of that.

**Where I could make this stronger next:**
- Send a real alert, like an email, once a site is confirmed down,
  instead of just logging it.
- Check from more than one location, since a real outage looks
  different from a local network problem on just my end.
- Track response time trends over time, not just pass or fail, since
  a site that's getting slower is often a warning sign before it
  actually goes down.

---

## How to Run This Code, Step by Step

### `go run` vs `go build`

`go run` compiles the code and runs it in one step, but doesn't save
anything afterward. `go build` compiles it into a real `.exe` file
that stays in the folder, so it can be run again anytime without
rebuilding, unless the code changes.

### Setup

1. **Download** `cloud-site-checker.go`, `cloud-site-checker-report.go`,
   `cloud-site-checker-config.json`, and `urls.txt`, and put them all
   in the same folder.
2. **Open that folder in VS Code**, and open a terminal inside it.
3. **Set up the Go project:**
   ```bash
   go mod init cloud-site-checker
   go get modernc.org/sqlite
   ```

### Running the Checker

**Option A — `go run`:**
```bash
go run cloud-site-checker.go
```

**Option B — `go build`:**
```bash
go build -o checker.exe cloud-site-checker.go
.\checker.exe
```

**Check the results.** New files appear:
- `output.txt` — a readable report of each check.
- `cloud-site-checker-log.txt` — a simple log of every check.
- `cloud-site-checker.db` — the database with full history.

### Running the Report Tool

`cloud-site-checker-report.go` sits in the same folder and just reads
the same database.

**Option A — `go run`:**
```bash
go run cloud-site-checker-report.go
```

**Option B — `go build`:**
```bash
go build -o report.exe cloud-site-checker-report.go
.\report.exe
```

---

## Files in This Folder

- `cloud-site-checker.go` — the actual checker program.
- `cloud-site-checker-report.go` — a second program that reads the
  database and prints a clean history of past checks.
- `cloud-site-checker-config.json` — settings, like timeouts,
  retries, and the failure threshold for a confirmed alert.
- `urls.txt` — the list of sites to check, one per line.
- `go.mod` and `go.sum` — files Go creates automatically to manage
  the database library this project uses.
- `output.txt` — a saved copy of the check reports.
- `cloud-site-checker-demo.png` — the terminal output when i ran the commands on vs code

---

## Coming Up in the Future

- Sending a real alert once a site is confirmed down.
- Checking from more than one location or network.
- Tracking response time over time, not just healthy or down.

---

## Code Explained, Block by Block

**This part sets up the settings this program reads from the config
file.**
```go
type Config struct {
	UrlsFile                  string `json:"urls_file"`
	TimeoutSeconds            int    `json:"timeout_seconds"`
	MaxRetries                int    `json:"max_retries"`
	RetryDelaySeconds         int    `json:"retry_delay_seconds"`
	HealthyStatusMin          int    `json:"healthy_status_min"`
	HealthyStatusMax          int    `json:"healthy_status_max"`
	ConsecutiveFailuresForAlert int  `json:"consecutive_failures_for_alert"`
	LogFile                   string `json:"log_file"`
	OutputFile                string `json:"output_file"`
	DatabaseFile              string `json:"database_file"`
	MaxRecordsBeforeCleanup   int    `json:"max_records_before_cleanup"`
}
```
This matches the fields in the JSON file exactly, so all the timing,
retry, and threshold behavior can be tuned without touching the code.

**This part reads the list of sites to check, one per line.**
```go
func readUrls(path string) ([]string, error) {
	file, err := os.ReadFile(path)
	...
	lines := strings.Split(string(file), "\n")
	var urls []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			urls = append(urls, trimmed)
		}
	}
	return urls, nil
}
```
This splits the file by line, trims any extra spaces, and skips
blank lines, so an accidental empty line in `urls.txt` doesn't turn
into a broken check.

**This part builds a safe HTTP client with an actual timeout, and
retries a check a few times before giving up.**
```go
func checkHealth(targetUrl string, cfg *Config) (bool, int, time.Duration, int) {
	client := http.Client{
		Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second,
	}
	...
	for attempt < cfg.MaxRetries {
		attempt++
		start := time.Now()
		response, err := client.Get(targetUrl)
		lastResponseTime = time.Since(start)

		if err == nil {
			lastStatusCode = response.StatusCode
			response.Body.Close()
			if lastStatusCode >= cfg.HealthyStatusMin && lastStatusCode <= cfg.HealthyStatusMax {
				return true, lastStatusCode, lastResponseTime, attempt
			}
		}
		if attempt < cfg.MaxRetries {
			time.Sleep(time.Duration(cfg.RetryDelaySeconds) * time.Second)
		}
	}
	return false, lastStatusCode, lastResponseTime, attempt
}
```
Go's default HTTP client has no timeout at all, so a stuck site could
hang the whole program forever. Building a custom client with a
timeout fixes that. Any status code inside the configured healthy
range counts as success, and if a check fails, it waits a moment and
tries again, up to the configured number of retries, before finally
giving up on this one attempt.

**This part looks at past saved checks to count a real,
across-time failure streak.**
```go
func countRecentConsecutiveFailures(db *sql.DB, targetUrl string) int {
	rows, err := db.Query(
		"SELECT result FROM health_checks WHERE target_url = ? ORDER BY checked_at DESC",
		targetUrl,
	)
	...
	streak := 0
	for rows.Next() {
		var result string
		rows.Scan(&result)
		if result == "DOWN" {
			streak++
		} else {
			break
		}
	}
	return streak
}
```
This is different from the retries inside `checkHealth`. Those
retries only handle one check that might just be a passing network
hiccup. This function instead looks across several separate, already
saved checks over time, most recent first, and counts how many in a
row were DOWN. As soon as it hits a HEALTHY one, it stops, since the
streak is broken there. This is what lets the program tell the
difference between one bad moment and an actual ongoing outage.

**This part runs each URL through a check, and decides how serious a
failure actually is.**
```go
for _, targetUrl := range urls {
	healthy, statusCode, responseTime, attempts := checkHealth(targetUrl, cfg)
	result := "HEALTHY"
	if !healthy {
		result = "DOWN"
	}
	saveCheck(db, targetUrl, result, statusCode, responseTime, attempts)

	if healthy {
		fmt.Printf("success: Healthy...")
	} else {
		streak := countRecentConsecutiveFailures(db, targetUrl)
		if streak >= cfg.ConsecutiveFailuresForAlert {
			fmt.Printf("alert\a: CONFIRMED DOWN...")
		} else {
			fmt.Printf("warning: possible outage...")
		}
	}
}
```
The result gets saved to the database first, before checking the
streak, so this exact failure is already counted as part of its own
streak. If the streak has crossed the configured threshold, it's
treated as a confirmed outage with a real alert sound. If not, it's
shown as just a warning, since it might still turn out to be nothing.

**This part keeps the database from growing forever.**
```go
func cleanupOldChecks(db *sql.DB, maxRecords int) {
	cleanupSQL := `DELETE FROM health_checks WHERE id NOT IN (
		SELECT id FROM health_checks ORDER BY id DESC LIMIT ?
	);`
	db.Exec(cleanupSQL, maxRecords)
}
```
Once the row count passes the limit set in the config file, this
deletes the oldest rows and keeps only the most recent batch.

---

## Report Tool (`cloud-site-checker-report.go`)

### What This Code Does

This is a second, separate program in the same folder. It opens the
same database the main checker writes to, and prints every past
check, grouped by whether the site was healthy or down.

### Why I Built This

I wanted an easy way to look back at the full history of checks for
every site, without scrolling through the raw output file by hand.

## Code Explained, Block by Block

**This part sets up the settings this program reads from the config
file.**
```go
type Config struct {
	UrlsFile                  string `json:"urls_file"`
	TimeoutSeconds            int    `json:"timeout_seconds"`
	MaxRetries                int    `json:"max_retries"`
	RetryDelaySeconds         int    `json:"retry_delay_seconds"`
	HealthyStatusMin          int    `json:"healthy_status_min"`
	HealthyStatusMax          int    `json:"healthy_status_max"`
	ConsecutiveFailuresForAlert int  `json:"consecutive_failures_for_alert"`
	LogFile                   string `json:"log_file"`
	OutputFile                string `json:"output_file"`
	DatabaseFile              string `json:"database_file"`
	MaxRecordsBeforeCleanup   int    `json:"max_records_before_cleanup"`
}
```
This matches the fields in the JSON file exactly, so all the timing,
retry, and threshold behavior can be tuned without touching the code.

**This part reads and loads the settings file into that struct.**
```go
func loadConfig(path string) (*Config, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(file, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
```
`os.ReadFile` grabs the raw text of the JSON file, and
`json.Unmarshal` maps that text into the actual `Config` struct
fields. If either step fails, the error gets passed back up instead
of crashing right here.

**This part writes a simple, timestamped line into the log file.**
```go
func writeLog(path string, message string) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	...
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	file.WriteString(fmt.Sprintf("[%s] %s\n", timestamp, message))
}
```
`os.O_APPEND` means new lines get added to the end of the file
instead of erasing what's already there, so the log keeps growing
with the full history of every check.

**This part writes a more detailed, readable report block into the
output file.**
```go
func writeOutput(path string, targetUrl string, healthy bool, statusCode int, responseTime time.Duration, attempts int) {
	...
	status := "HEALTHY"
	if !healthy {
		status = "DOWN"
	}
	report := fmt.Sprintf(
		"---------------------------------------\nCheck time    : %s\nURL           : %s\nStatus        : %s\n...",
		...
	)
	file.WriteString(report)
}
```
This builds a small formatted block, with each field lined up
neatly, so `output.txt` stays easy to read even after many checks
pile up in it.

**This part opens the database and creates the table if it doesn't
exist yet.**
```go
func openDatabase(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	...
	createTable := `
	CREATE TABLE IF NOT EXISTS health_checks (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target_url TEXT,
		result TEXT,
		status_code INTEGER,
		response_time_ms INTEGER,
		attempts INTEGER,
		checked_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	...
}
```
`IF NOT EXISTS` means this is safe to run every time the program
starts. If the table already exists from an earlier run, this line
does nothing and leaves the old saved history untouched.

**This part saves one completed check into the database.**
```go
func saveCheck(db *sql.DB, targetUrl string, result string, statusCode int, responseTime time.Duration, attempts int) {
	db.Exec(
		"INSERT INTO health_checks (target_url, result, status_code, response_time_ms, attempts) VALUES (?, ?, ?, ?, ?)",
		targetUrl, result, statusCode, responseTime.Milliseconds(), attempts,
	)
}
```
`responseTime.Milliseconds()` converts the duration into a plain
number before it's saved, since the database column is just an
integer, not a special time type.

**This part reads the list of sites to check, one per line.**
```go
func readUrls(path string) ([]string, error) {
	file, err := os.ReadFile(path)
	...
	lines := strings.Split(string(file), "\n")
	var urls []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			urls = append(urls, trimmed)
		}
	}
	return urls, nil
}
```
This splits the file by line, trims any extra spaces, and skips
blank lines, so an accidental empty line in `urls.txt` doesn't turn
into a broken check.

**This part builds a safe HTTP client with an actual timeout, and
retries a check a few times before giving up.**
```go
func checkHealth(targetUrl string, cfg *Config) (bool, int, time.Duration, int) {
	client := http.Client{
		Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second,
	}
	...
	for attempt < cfg.MaxRetries {
		attempt++
		start := time.Now()
		response, err := client.Get(targetUrl)
		lastResponseTime = time.Since(start)

		if err == nil {
			lastStatusCode = response.StatusCode
			response.Body.Close()
			if lastStatusCode >= cfg.HealthyStatusMin && lastStatusCode <= cfg.HealthyStatusMax {
				return true, lastStatusCode, lastResponseTime, attempt
			}
		}
		if attempt < cfg.MaxRetries {
			time.Sleep(time.Duration(cfg.RetryDelaySeconds) * time.Second)
		}
	}
	return false, lastStatusCode, lastResponseTime, attempt
}
```
Go's default HTTP client has no timeout at all, so a stuck site could
hang the whole program forever. Building a custom client with a
timeout fixes that. Any status code inside the configured healthy
range counts as success, and if a check fails, it waits a moment and
tries again, up to the configured number of retries, before finally
giving up on this one attempt.

**This part looks at past saved checks to count a real,
across-time failure streak.**
```go
func countRecentConsecutiveFailures(db *sql.DB, targetUrl string) int {
	rows, err := db.Query(
		"SELECT result FROM health_checks WHERE target_url = ? ORDER BY checked_at DESC",
		targetUrl,
	)
	...
	streak := 0
	for rows.Next() {
		var result string
		rows.Scan(&result)
		if result == "DOWN" {
			streak++
		} else {
			break
		}
	}
	return streak
}
```
This is different from the retries inside `checkHealth`. Those
retries only handle one check that might just be a passing network
hiccup. This function instead looks across several separate, already
saved checks over time, most recent first, and counts how many in a
row were DOWN. As soon as it hits a HEALTHY one, it stops, since the
streak is broken there.

**This part keeps the database from growing forever.**
```go
func cleanupOldChecks(db *sql.DB, maxRecords int) {
	cleanupSQL := `DELETE FROM health_checks WHERE id NOT IN (
		SELECT id FROM health_checks ORDER BY id DESC LIMIT ?
	);`
	db.Exec(cleanupSQL, maxRecords)
}
```
Once the row count passes the limit set in the config file, this
deletes the oldest rows and keeps only the most recent batch.

**This part loads the config, opens the database, and reads the URL
list before anything else can run.**
```go
func main() {
	cfg, err := loadConfig("cloud-site-checker-config.json")
	...
	db, err := openDatabase(cfg.DatabaseFile)
	...
	urls, err := readUrls(cfg.UrlsFile)
	...
	fmt.Printf("Checking %d site(s) from %s\n\n", len(urls), cfg.UrlsFile)
```
If any of these three steps fail, the program prints an error and
stops right there, instead of continuing on with broken settings, no
database, or an empty list.

**This part runs each URL through a check, and decides how serious a
failure actually is.**
```go
for _, targetUrl := range urls {
	healthy, statusCode, responseTime, attempts := checkHealth(targetUrl, cfg)
	result := "HEALTHY"
	if !healthy {
		result = "DOWN"
	}
	saveCheck(db, targetUrl, result, statusCode, responseTime, attempts)

	if healthy {
		fmt.Printf("success: Healthy...")
	} else {
		streak := countRecentConsecutiveFailures(db, targetUrl)
		if streak >= cfg.ConsecutiveFailuresForAlert {
			fmt.Printf("alert\a: CONFIRMED DOWN...")
		} else {
			fmt.Printf("warning: possible outage...")
		}
	}
	writeOutput(cfg.OutputFile, targetUrl, healthy, statusCode, responseTime, attempts)
}

cleanupOldChecks(db, cfg.MaxRecordsBeforeCleanup)
```
The result gets saved to the database first, before checking the
streak, so this exact failure is already counted as part of its own
streak. If the streak has crossed the configured threshold, it's
treated as a confirmed outage with a real alert sound. If not, it's
shown as just a warning, since it might still turn out to be nothing.
Cleanup runs once at the very end, after every site in the list has
been checked.

