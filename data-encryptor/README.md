# Data Encryptor (Secret Redactor)
 
## What This Code Does
 
This is a Go program that finds and hides secrets, like passwords or
API tokens, before they end up sitting in plain text somewhere. It
works two ways: I can type in one secret directly to redact it, or I
can point it at a whole log file, and it scans every line looking for
sensitive keywords like "password" or "api_key", masks the value next
to them, and saves a clean version of the file. Every secret it
finds, in either mode, gets hashed and saved to a database, so there's
proof it existed and was caught, without ever storing the real value.
 
## Why I Built This
 
I wanted to actually understand how real log-scrubbing tools protect
secrets, instead of just knowing "don't log passwords" as a rule. I
started with redacting one typed-in secret, then grew it into
scanning a whole file automatically, which is closer to how this
actually needs to work at any real scale.
 
## How This Relates to Cybersecurity
 
Secrets ending up in plain text logs is a real, common way sensitive
data leaks, often by accident. A developer adds a debug line that
prints a variable, forgets it's there, and a password sits in a log
file for anyone with access to read. This program does two things
that matter a lot here: it masks the actual value so it's never
visible again, and it saves a one-way hash of it instead of the real
secret, so there's still a record that something was caught and
redacted, without that record itself being a new leak.
 
## How This Relates to the Real World
 
Real logging and monitoring pipelines run exactly this kind of
scrubbing automatically, before logs ever get stored or shipped
somewhere else. Companies define a list of sensitive field names,
scan every log line for them, and mask anything that matches, the
same basic approach this program uses. Hashing instead of just
deleting the value also matters in real systems, since it lets a
security team confirm a specific leaked secret was actually this one,
without ever needing to store or expose the real value again.
 
---
 
## What I Learned Researching Real Attacks
 
**A hash is not the same as encryption.** I learned these get
confused a lot. Encryption can be reversed with the right key.
Hashing, like the SHA-256 used here, cannot be reversed at all, the
same input always produces the same output, but there's no way to
turn that output back into the original secret. That's exactly why
it's the right tool for this: I want proof a secret existed, not a
way to recover it later.
 
**Sensitive data hides in more places than expected.** While
researching this, I learned real secret-scanning tools don't just
look for a fixed list of words like "password". They also scan for
patterns that look like real tokens, like long random strings that
match known formats (AWS keys, GitHub tokens, and so on), since a
secret can leak under a completely unexpected variable name.
 
**Where I could make this stronger next:**
- Match known secret formats directly (like AWS key patterns),
  instead of only relying on a keyword sitting next to the value.
- Redact secrets that span more than one line, since this only
  catches a secret if it's on the same line as its keyword.
- Warn if the exact same hash shows up multiple times across
  different scans, since that could mean the same real secret is
  leaking repeatedly from more than one place.
---
 
## How to Run This Code, Step by Step
 
### `go run` vs `go build`
 
`go run` compiles the code and runs it in one step, but doesn't save
anything afterward. `go build` compiles it into a real `.exe` file
that stays in the folder, so it can be run again anytime without
rebuilding, unless the code changes.
 
### Setup
 
1. **Download** `encryptor.go`, `data-encryptor-report.go`,
   `data-encryptor-config.json`, and `sample-log.txt`, and put them
   all in the same folder.
2. **Open that folder in VS Code**, and open a terminal inside it.
3. **Set up the Go project:**
```bash
   go mod init data-encryptor
   go get modernc.org/sqlite
```
 
### Running the Redactor
 
**Option A — `go run`:**
```bash
go run encryptor.go
```
 
**Option B — `go build`:**
```bash
go build -o DataEncryptorTool.exe encryptor.go
.\DataEncryptorTool.exe
```
 
When it runs, choose:
- **1** to type in and redact a single secret directly.
- **2** to scan `sample-log.txt` and redact every match found in it.
**Check the results.** New files appear:
- `output.txt` — a readable report of each redaction.
- `data-encryptor-log.txt` — a simple log of every redaction.
- `redacted-log.txt` — the clean, redacted version of the scanned
  log file (only appears after choosing option 2).
- `data-encryptor.db` — the database with every redacted secret's
  hash saved in it.
### Running the Report Tool
 
**Option A — `go run`:**
```bash
go run data-encryptor-report.go
```
 
**Option B — `go build`:**
```bash
go build -o RedactorReport.exe data-encryptor-report.go
.\RedactorReport.exe
```
 
---
 
## Files in This Folder
 
- `encryptor.go` — the actual redactor program.
- `data-encryptor-report.go` — a second program that reads the
  database and prints the full redaction history.
- `data-encryptor-config.json` — settings, like the mask text,
  sensitive keywords, and file paths.
- `sample-log.txt` — an example log file with fake secrets in it, to
  scan.
- `go.mod` and `go.sum` — files Go creates automatically to manage
  the database library this project uses.
- `output.txt` — a saved copy of the redaction reports.
- `data-encryptor-demo.png` — the terminal output when i ran this program.

---
 
## Coming Up in the Future
 
- Matching known real secret formats directly, not just keywords.
- Catching secrets that span more than one line.
- Flagging repeated hashes across different scans, in case the same
  real secret is leaking from more than one place.
---

## Code Explained, Block by Block

**This part tells Go which tools this program needs, to read files,
hash secrets, talk to the database, and use search patterns.**
```go
import (
	"bufio"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
 
	_ "modernc.org/sqlite"
)
```
`crypto/sha256` and `encoding/hex` are the two tools used for
hashing secrets. `regexp` is for finding sensitive keywords in text.
The last import loads the actual database driver in the background,
so the rest of the code can just use `sql.Open` directly.
 

**This part holds all the settings the program reads from the config
file.**
```go
type Config struct {
	MaskOutput               string   `json:"mask_output"`
	SensitiveKeywords        []string `json:"sensitive_keywords"`
	LogFile                  string   `json:"log_file"`
	OutputFile               string   `json:"output_file"`
	ScanInputFile             string  `json:"scan_input_file"`
	RedactedOutputFile        string  `json:"redacted_output_file"`
	DatabaseFile              string  `json:"database_file"`
	MaxRecordsBeforeCleanup   int     `json:"max_records_before_cleanup"`
}
```
This is just a box that matches the config file. It holds the mask
text, the list of sensitive words, and all the file names, so I can
change any of them without touching the code.

**This part opens the config file and puts its values into that
box.**
```go
func loadConfig(path string) (*Config, error) {
	file, err := os.ReadFile(path)
	...
	var cfg Config
	if err := json.Unmarshal(file, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
```

**This part turns a secret into a one-way code that can never be
turned back into the original.**
```go
func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}
```
This is called hashing. The same secret always makes the same hash,
but there is no way to go backward and get the real secret from the
hash.

**This part adds one line to the log file every time something
happens.**
```go
func writeLog(path string, message string) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	...
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	file.WriteString(fmt.Sprintf("[%s] %s\n", timestamp, message))
}
```
It adds the new line at the end of the file, without deleting the
old lines already there.

**This part writes a longer, easy to read report into the output
file.**
```go
func writeOutput(path string, maskedValue string, hash string) {
	...
	report := fmt.Sprintf(
		"---------------------------------------\nCheck time    : %s\nSaved value   : %s\nSecret hash   : %s\n",
		timestamp, maskedValue, hash,
	)
	file.WriteString(report)
}
```
Only the masked value and the hash go into this file. The real
secret never gets written here.

**This part opens the database and makes the table, if it does not
already exist.**
```go
func openDatabase(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	...
	createTable := `
	CREATE TABLE IF NOT EXISTS redacted_secrets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		masked_value TEXT,
		secret_hash TEXT,
		source TEXT,
		logged_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	...
}
```
If the table is already there from before, this line just does
nothing, so old saved data stays safe.

**This part saves one redacted secret into the database.**
```go
func saveRedactedSecret(db *sql.DB, maskedValue string, hash string, source string) {
	db.Exec(
		"INSERT INTO redacted_secrets (masked_value, secret_hash, source) VALUES (?, ?, ?)",
		maskedValue, hash, source,
	)
}
```
`source` says where the secret came from, either typed in by hand or
the name of a scanned file.

**This part deletes old rows so the database does not grow forever.**
```go
func cleanupOldSecrets(db *sql.DB, maxRecords int) {
	cleanupSQL := `DELETE FROM redacted_secrets WHERE id NOT IN (
		SELECT id FROM redacted_secrets ORDER BY id DESC LIMIT ?
	);`
	db.Exec(cleanupSQL, maxRecords)
}
```
Once there are more rows than the limit set in the config file, the
oldest ones get deleted, and only the newest ones stay.

**This part turns the list of sensitive words into one search
pattern.**
```go
func buildKeywordPattern(keywords []string) *regexp.Regexp {
	joined := strings.Join(keywords, "|")
	pattern := `(?i)(` + joined + `)\s*[:=]\s*(\S+)`
	return regexp.MustCompile(pattern)
}
```
This pattern looks for any of the sensitive words, followed by a
colon or an equals sign, then grabs whatever value comes right after
it. `(?i)` means it does not care about uppercase or lowercase.

**This part reads a whole log file, line by line, and hides every
secret it finds.**
```go
func redactLogFile(cfg *Config, db *sql.DB, pattern *regexp.Regexp) (int, error) {
	inputFile, err := os.Open(cfg.ScanInputFile)
	...
	outputFile, err := os.OpenFile(cfg.RedactedOutputFile, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	...
	for scanner.Scan() {
		line := scanner.Text()
		matches := pattern.FindAllStringSubmatch(line, -1)

		for _, match := range matches {
			originalValue := match[2]
			hash := hashSecret(originalValue)
			maskedValue := cfg.MaskOutput
			line = strings.Replace(line, originalValue, maskedValue, 1)
			saveRedactedSecret(db, maskedValue, hash, cfg.ScanInputFile)
			redactedCount++
		}
		outputFile.WriteString(line + "\n")
	}
	return redactedCount, scanner.Err()
}
```
For every line, it checks for matches. If it finds a secret, it hides
the value, hashes it, saves it to the database, and writes the clean
line into a new file. It checks every match on a line, not just the
first one.

**This part starts the program by loading the settings and opening
the database.**
```go
func main() {
	cfg, err := loadConfig("data-encryptor-config.json")
	if err != nil {
		fmt.Println("Could not load data-encryptor-config.json:", err)
		return
	}
 
	db, err := openDatabase(cfg.DatabaseFile)
	if err != nil {
		fmt.Println("Could not open database:", err)
		return
	}
	defer db.Close()
```
If either the config file or the database fails to open, the program
prints an error and stops right here, instead of continuing on with
broken settings or no database to save anything into.
`defer db.Close()` means the database connection closes automatically
once the whole program is done running.

**This part shows the menu and asks what the user wants to do.**
```go
fmt.Println("1. Redact one secret I type in")
fmt.Println("2. Scan and redact a whole log file")
fmt.Print("Choose 1 or 2: ")
```
If the user types anything other than 1 or 2, the program just stops
and says it was not a valid choice.

**This part handles it if the user types something other than 1 or
2.**
```go
} else {
	fmt.Println("Not a valid choice, please enter 1 or 2.")
	return
}
```
If the input doesn't match either expected option, the program just
prints a message and stops cleanly, instead of guessing what the
user meant or continuing with bad input.

**This part handles option 1: hiding one secret typed in by hand.**
```go
if choice == "1" {
	fmt.Print("Enter your private API token/password: ")
	...
	if userSecret == "" {
		fmt.Println("Error:\a No token input detected.")
		return
	}
	maskedValue := cfg.MaskOutput
	hash := hashSecret(userSecret)
	...
}
```
If nothing was typed, it stops right away. Otherwise, it hashes the
secret and only ever saves or shows the masked value and the hash,
never the real one.

**This part handles option 2: scanning a whole file.**
```go
} else if choice == "2" {
	pattern := buildKeywordPattern(cfg.SensitiveKeywords)
	count, err := redactLogFile(cfg, db, pattern)
	...
	fmt.Printf("Scanned %s — found and redacted %d secret(s).\n", cfg.ScanInputFile, count)
}
```
This builds the search pattern once, then lets `redactLogFile` do all
the real work, and just prints how many secrets it found.

---

## Report Tool (`data-encryptor-report.go`) — Code Explained, Block by Block

**This part opens the same database the main program already
saved everything into.**
```go
db, err := sql.Open("sqlite", "data-encryptor.db")
```
This tool does not create anything new. It just connects to the same
database file the main program already wrote to.

**This part asks the database for every saved secret and prints
them one by one.**
```go
rows, err := db.Query("SELECT masked_value, secret_hash, source, logged_at FROM redacted_secrets ORDER BY logged_at DESC")
...
for rows.Next() {
	var maskedValue, hash, source, loggedAt string
	rows.Scan(&maskedValue, &hash, &source, &loggedAt)
	fmt.Printf("  %s   hash: %s   source: %s   at: %s\n", maskedValue, hash, source, loggedAt)
	found = true
}

if !found {
	fmt.Println("  (no redacted secrets logged yet)")
}
```
`ORDER BY logged_at DESC` shows the newest entries first. Only the
masked value and the hash ever get shown here, the real secret is
never stored anywhere, so it can never be printed by mistake either.

**This part prints a final message once everything is done, no
matter which option was chosen.**
```go
fmt.Println("\nFull results saved in", cfg.DatabaseFile, "and", cfg.LogFile)
```
This line runs after either option 1 or option 2 finishes, letting
the user know exactly where to find the full saved history.
 
