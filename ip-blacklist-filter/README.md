# IP Blacklist Filter

## What This Code Does

This is a Go program that checks if a visitor's IP address is on a
blacklist before letting them in. It supports two kinds of rules: an
exact list of blocked IPs, and CIDR ranges, which block a whole block
of IP addresses at once instead of just one. Every check, allowed,
denied, or invalid, gets saved into a log file, an output report
file, and a database, so nothing gets lost.

## Why I Built This

My other two projects, the auth log monitor and the port firewall,
both watch behavior over time to catch an attack pattern. I wanted
to also build the simpler, more basic version of network defense: a
static list of IPs and ranges that are already known to be bad, and
checking against that list directly, the same way a lot of real
firewalls start.

## How This Relates to Cybersecurity

Blocking known bad IP addresses is one of the most basic ideas in
network security. Before a system even tries to detect suspicious
behavior, it can just refuse entry to addresses that are already
known to be malicious. This program does exactly that: it checks an
incoming IP against both individual blocked addresses and entire
blocked ranges, and only lets it through if it matches nothing on the
list.

## How This Relates to the Real World

Real security teams use threat intelligence feeds, like lists from
AbuseIPDB or Spamhaus, that publish exactly this kind of data: known
malicious IPs and the network ranges they belong to. Real firewalls
and web servers subscribe to these lists and block that traffic
automatically, before it ever reaches the actual application. CIDR
ranges matter a lot here, because attackers usually don't own just
one IP, they often operate from a whole block of addresses owned by
the same hosting provider, so blocking the range is far more
effective than blocking addresses one at a time as they show up.

---

## What I Learned Researching Real Attacks

**Why CIDR ranges matter more than single IPs.** A single malicious
IP is easy for an attacker to abandon and switch away from. But
attackers, or the hosting providers they rent from, usually control a
whole range of addresses. Blocking the entire range, instead of
reacting to one IP at a time, closes the door on the whole
neighborhood, not just one house.

**Static blacklists have a real limit.** This is the same limitation
I found while researching my auth log project too: attackers rotate
IPs, use VPNs, or route through proxies specifically to get around
static blacklists like this one. A list of known-bad addresses is a
strong first layer of defense, but real systems don't rely on it
alone, they combine it with behavior-based detection, which is what
my other two projects actually do.

**Where I could make this stronger next:**
- Pull real, live blacklist data from a public threat intelligence
  feed, instead of a fixed list in a config file.
- Combine this with the behavior-based detection from my other
  projects, so even an IP that isn't on any static list yet can still
  get caught if it starts acting suspicious.
- Support IPv6 ranges more thoroughly, since this currently handles
  IPv6 addresses but hasn't been tested much against real IPv6 CIDR
  ranges.

---

## How to Run This Code, Step by Step

### `go run` vs `go build`

`go run` compiles the code and runs it in one step, but doesn't save
anything afterward. `go build` compiles it into a real `.exe` file
that stays in the folder, so it can be run again anytime without
rebuilding, unless the code changes.

### Setup

1. **Download** `ip-blacklist-filter.go`, `ip-blacklist-filter-report.go`,
   and `ip-blacklist-filter-config.json`, and put them all in the
   same folder.
2. **Open that folder in VS Code**, and open a terminal inside it.
3. **Set up the Go project:**
   ```bash
   go mod init ip-blacklist-filter
   go get modernc.org/sqlite
   ```

### Running the Filter

**Option A — `go run`:**
```bash
go run ip-blacklist-filter.go
```

**Option B — `go build`:**
```bash
go build -o filter.exe ip-blacklist-filter.go
.\filter.exe
```

Type an IP address when prompted, like `172.16.0.4`, to see it get
checked against the blacklist.

**Check the results.** New files appear:
- `output.txt` — a readable record of each check.
- `ip-blacklist-filter-log.txt` — a simple log of every check.
- `ip-blacklist-filter.db` — the database with full history.

### Running the Report Tool

`ip-blacklist-filter-report.go` sits in the same folder and just
reads the same database.

**Option A — `go run`:**
```bash
go run ip-blacklist-filter-report.go
```

**Option B — `go build`:**
```bash
go build -o report.exe ip-blacklist-filter-report.go
.\report.exe
```

---

## Files in This Folder

- `ip-blacklist-filter.go` — the actual filter program.
- `ip-blacklist-filter-report.go` — a second program that reads the
  database and prints a clean report of past checks.
- `ip-blacklist-filter-config.json` — settings, including the
  blocked IPs, blocked CIDR ranges, and file paths.
- `go.mod` and `go.sum` — files Go creates automatically to manage
  the database library this project uses.
- `output.txt` — a saved copy of the check reports.
- `ip-blacklist-filter-log.txt` — the log file.
- `ip-blacklist-demo.png` — the terminal output after running the code with these commands.

---

## Coming Up in the Future

- Pulling in a real, live threat intelligence feed instead of a
  fixed list.
- Combining this with the sliding-window detection ideas from my
  other two projects.
- Testing this more thoroughly against real IPv6 ranges.

---

## Code Explained, Block by Block

**This part tells Go which tools it needs, to read files, work with
network addresses, and talk to the database.**
```go
import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)
```
`net` is the important new one here, it's Go's built-in package for
working with actual IP addresses and network ranges, instead of
treating them as plain text.

**This part sets up the settings this program reads from the config
file.**
```go
type Config struct {
	BlacklistIPs        []string `json:"blacklist_ips"`
	BlacklistCIDRRanges []string `json:"blacklist_cidr_ranges"`
	LogFile              string  `json:"log_file"`
	OutputFile            string `json:"output_file"`
	DatabaseFile         string  `json:"database_file"`
}
```
`BlacklistIPs` holds individual blocked addresses, and
`BlacklistCIDRRanges` holds whole blocked network ranges, like
`10.0.0.0/24`. Keeping both as text lists in the config file means
the blocklist can be updated without touching the code.

**This part turns the list of blocked IPs into a fast lookup set.**
```go
func buildExactMatchSet(ips []string) map[string]bool {
	set := make(map[string]bool)
	for _, ip := range ips {
		set[ip] = true
	}
	return set
}
```
Checking if something exists in a map is much faster than looping
through a whole list every single time, especially if the blacklist
gets long.

**This part turns the CIDR range text strings into something Go can
actually check IPs against.**
```go
func parseCIDRRanges(cidrStrings []string) []*net.IPNet {
	var ranges []*net.IPNet
	for _, cidrStr := range cidrStrings {
		_, network, err := net.ParseCIDR(cidrStr)
		if err == nil {
			ranges = append(ranges, network)
		}
	}
	return ranges
}
```
`net.ParseCIDR` reads something like `192.168.1.0/24` and turns it
into a real network object that knows exactly which addresses fall
inside that range. Any range that fails to parse just gets skipped,
instead of crashing the whole program.

**This part is the actual check: is this IP blocked, and why?**
```go
func checkAccess(visitorIP net.IP, exactSet map[string]bool, cidrRanges []*net.IPNet) (bool, string) {
	if exactSet[visitorIP.String()] {
		return false, "exact match: " + visitorIP.String()
	}

	for _, network := range cidrRanges {
		if network.Contains(visitorIP) {
			return false, "range match: " + network.String()
		}
	}

	return true, "not blacklisted"
}
```
It checks the exact-match list first, since that's the fastest
check. If nothing matches there, it loops through the CIDR ranges and
uses `network.Contains()`, a built-in Go function that correctly
figures out if an IP falls inside a range, without me having to do
any of that math by hand. If nothing matches either way, the IP is
allowed through.

**This part reads the visitor's IP from the terminal and makes sure
it's actually a real IP address.**
```go
reader := bufio.NewReader(os.Stdin)
rawInput, _ := reader.ReadString('\n')
visitorInput := strings.TrimSpace(rawInput)

visitorIP := net.ParseIP(visitorInput)
if visitorIP == nil {
	fmt.Println("INVALID INPUT: that is not a real IP address.")
	writeLog(cfg.LogFile, fmt.Sprintf("Rejected invalid input: %q", visitorInput))
	saveAccessCheck(db, visitorInput, "INVALID", "not a valid IP format")
	return
}
```
`net.ParseIP` returns `nil` if the text typed in isn't actually a
valid IP address at all, like a typo or random text. Instead of
letting that crash something later, it gets caught here, logged as
invalid, and the program stops cleanly.

**This part saves the result of every check into the log, the
output report, and the database.**
```go
writeLog(cfg.LogFile, fmt.Sprintf("IP %s %s (%s)", visitorIP, status, matchedRule))
writeOutput(cfg.OutputFile, visitorIP.String(), allowed, matchedRule)
saveAccessCheck(db, visitorIP.String(), status, matchedRule)
```
Every single check gets recorded in three places at once: a short
log line, a more detailed output report, and a permanent database
row, so nothing about what happened is only living in the terminal
window that's about to close.

---

## Report Tool (`ip-blacklist-filter-report.go`)

### What This Code Does

This is a second, separate program in the same folder. It opens the
same database the main filter writes to, and prints every check,
grouped by whether it was denied, allowed, or invalid.

### Why I Built This

I wanted an easy way to look back at every IP that's been checked so
far, without digging through the raw output file by hand.

### Code Explained, Block by Block

**This part asks the database for every check that matches one
result type, and prints them.**
```go
func printByResult(db *sql.DB, result string) {
	rows, err := db.Query(
		"SELECT visitor_ip, matched_rule, checked_at FROM access_log WHERE result = ? ORDER BY checked_at DESC",
		result,
	)
	...
	for rows.Next() {
		var ip, rule, checkedAt string
		rows.Scan(&ip, &rule, &checkedAt)
		fmt.Printf("  %s   rule: %s   checked at: %s\n", ip, rule, checkedAt)
		found = true
	}

	if !found {
		fmt.Printf("  (no %s entries yet)\n", result)
	}
}
```
This one function gets reused three times in `main`, once each for
`"DENIED"`, `"ALLOWED"`, and `"INVALID"`, instead of writing three
almost-identical blocks of code. If there are no entries for that
result yet, it says so clearly instead of just printing nothing and
looking broken.
