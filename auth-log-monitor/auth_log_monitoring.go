package main

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

/*
	Yeh struct saare counters ko ek box mein rakhta hai.
	Isse function ke andar-bahar counters ko le jaana aasan ho jata hai.
*/
type ThreatCounts struct {
	FailedPassword     int
	UnauthorizedAccess int
	PortScan           int
}

/*
	Yeh struct config.json file ki shape batata hai. Jab hum JSON file
	padhte hain, Go usay is struct ke andar fit kar deta hai, taake
	hum "config.BlockThreshold" jaisa likh kar values use kar sakein.
*/
type Config struct {
	LogFilePath              string `json:"log_file_path"`
	DatabaseName              string `json:"database_name"`
	BlockThreshold            int    `json:"block_threshold"`
	BlockTimeWindowMinutes    int    `json:"block_time_window_minutes"`
	MaxRecordsBeforeCleanup   int    `json:"max_records_before_cleanup"`
}

/*
	Yeh ek regex (regular expression) hai. Regex ek pattern hai jo
	text ke andar se specific shape ki cheez dhoondta hai. Yahan hum
	sirf "X.X.X.X" shape ke IP address ko dhoond rahe hain, chahe
	woh line mein kahin bhi ho, aakhir mein ho ya beech mein.
	Isse purana masla theek ho gaya jahan hum sirf line ka aakhri
	word utha lete the, chahe woh IP ho ya na ho.
*/
var ipRegex = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)

func main() {
	fmt.Println("Starting Cloud Server Log Monitoring")
	fmt.Println()

	/*
		Yeh config.json file se saari settings load karta hai.
		Ab agar kal humein threshold 7 se 10 karna ho, humein code
		dobara compile nahi karna, bas config.json mein number badalna
		hai.
	*/
	config, err := loadConfig("config.json")
	if err != nil {
		fmt.Println("Error loading config.json:", err)
		return
	}

	logFileName := config.LogFilePath
	if len(os.Args) > 1 {
		logFileName = os.Args[1]
	}

	logFile, err := os.Open(logFileName)
	if err != nil {
		fmt.Println("Error: could not open", logFileName)
		return
	}
	defer logFile.Close()

	reportFile, err := os.Create("security_report.txt")
	if err != nil {
		fmt.Println("Error: could not create report file")
		return
	}
	defer reportFile.Close()
	reportWriter := bufio.NewWriter(reportFile)
	defer reportWriter.Flush()

	blocklistFile, err := os.Create("blocked_ips.txt")
	if err != nil {
		fmt.Println("Error: could not create blocklist file")
		return
	}
	defer blocklistFile.Close()
	blocklistWriter := bufio.NewWriter(blocklistFile)
	defer blocklistWriter.Flush()

	db, err := sql.Open("sqlite", config.DatabaseName)
	if err != nil {
		fmt.Println("Error: could not open database")
		return
	}
	defer db.Close()

	createTableSQL := `
	CREATE TABLE IF NOT EXISTS threats (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		threat_type TEXT,
		ip_address TEXT,
		event_time TEXT
	);`
	_, err = db.Exec(createTableSQL)
	if err != nil {
		fmt.Println("Error creating table:", err)
		return
	}

	counts := ThreatCounts{}
	totalLinesRead := 0
	firstThreatTime := ""
	lastThreatTime := ""

	/*
		Yeh map har IP ke against uski attack timestamps ki list
		rakhta hai. Jaise: "192.168.10.5" -> [10:02:29, 10:06:22, 10:10:30]
		Isse hum check kar sakte hain ke kitne attacks ek chhoti
		time window (jaise 3 minute) ke andar hue, sirf total count
		nahi, kyunki poore hafte mein failele hui 7 koshishein
		brute-force nahi hoti, lekin 3 minute mein 7 koshishein hoti hain.
	*/
	ipAttackTimes := make(map[string][]time.Time)
	blockedIPs := make(map[string]bool)

	/*
		Yeh live tail ka hissa hai. Hum bufio.Reader use karte hain,
		normal Scanner ki jagah, kyunki Scanner sirf ek baar file
		padh kar ruk jata hai. Reader ko hum khud control karte hain:
		agar file ka end aa jaye (EOF), hum thoda ruk jate hain
		(time.Sleep) aur dobara try karte hain, taake agar file mein
		nayi line aaye (jaise real server mein hota hai), hum usay
		fauran pakad lein.
	*/
	reader := bufio.NewReader(logFile)
	linesProcessedInThisRun := 0

	fmt.Println("Watching log file... (this demo will process existing lines, then exit)")
	fmt.Println()

	for {
		line, err := reader.ReadString('\n')

		if len(line) > 0 {
			logLine := strings.TrimRight(line, "\r\n")
			totalLinesRead++
			linesProcessedInThisRun++

			isThreat, threatType, timestamp := processLine(logLine, &counts)
			extractedIP := extractIP(logLine)

			if isThreat {
				fmt.Printf("\a Threat Detected! Details: %s\n", logLine)
				reportWriter.WriteString("THREAT: " + logLine + "\n")

				if firstThreatTime == "" {
					firstThreatTime = timestamp
				}
				lastThreatTime = timestamp

				saveThreatToDatabase(db, threatType, extractedIP, timestamp)
				cleanupOldRecords(db, config.MaxRecordsBeforeCleanup)

				/*
					Agar IP khali hai (jaise "guest" wala attempt jisme
					koi IP nahi tha), hum usay tracking mein bilkul
					shamil nahi karte. Warna khali string "" khud
					ek "IP" ki tarah track ho kar block ho sakti thi,
					jo galat hota.
				*/
				if extractedIP != "" {
					eventTime, parseErr := time.Parse("2006-01-02 15:04:05", timestamp)
					if parseErr == nil {
						/*
							Yeh purani timestamps ko list se nikalta hai jo
							ab time window se bahar ho chuki hain, phir
							nayi timestamp add karta hai.
						*/
						windowDuration := time.Duration(config.BlockTimeWindowMinutes) * time.Minute
						validTimes := []time.Time{}
						for _, t := range ipAttackTimes[extractedIP] {
							if eventTime.Sub(t) <= windowDuration {
								validTimes = append(validTimes, t)
							}
						}
						validTimes = append(validTimes, eventTime)
						ipAttackTimes[extractedIP] = validTimes

						if len(validTimes) >= config.BlockThreshold && !blockedIPs[extractedIP] {
							blockedIPs[extractedIP] = true
							fmt.Printf("\a BLOCKED: %s hit %d attempts within %d minutes — auto-blocked\n",
								extractedIP, len(validTimes), config.BlockTimeWindowMinutes)
							blocklistWriter.WriteString(extractedIP + "\n")
						}
					}
				}
			}
		}

		if err != nil {
			if err == io.EOF {
				// File ka end aa gaya hai. Demo ke liye hum yahan ruk
				// jate hain. Agar yeh ek asli live server hota, hum
				// "time.Sleep(2 * time.Second)" laga kar loop jari
				// rakhte, taake nayi lines ka wait karein.
				break
			}
			fmt.Println("Error reading file:", err)
			break
		}
	}

	totalHighRiskAlerts := counts.FailedPassword + counts.UnauthorizedAccess + counts.PortScan

	fmt.Println()
	fmt.Println("\t\t\t---------- Monitoring Summary ----------")
	fmt.Printf("Total log lines read: %d\n", totalLinesRead)
	fmt.Printf("Failed password attempts: %d\n", counts.FailedPassword)
	fmt.Printf("Unauthorized access attempts: %d\n", counts.UnauthorizedAccess)
	fmt.Printf("Port scans detected: %d\n", counts.PortScan)
	fmt.Printf("Total high-risk alerts raised: %d\n", totalHighRiskAlerts)
	fmt.Printf("First threat seen at: %s\n", firstThreatTime)
	fmt.Printf("Last threat seen at: %s\n", lastThreatTime)
	fmt.Println()

	reportWriter.WriteString("\n\t\t\t---------- Monitoring Summary ----------\n")
	reportWriter.WriteString(fmt.Sprintf("Total log lines read: %d\n", totalLinesRead))
	reportWriter.WriteString(fmt.Sprintf("Failed password attempts: %d\n", counts.FailedPassword))
	reportWriter.WriteString(fmt.Sprintf("Unauthorized access attempts: %d\n", counts.UnauthorizedAccess))
	reportWriter.WriteString(fmt.Sprintf("Port scans detected: %d\n", counts.PortScan))
	reportWriter.WriteString(fmt.Sprintf("Total high-risk alerts raised: %d\n", totalHighRiskAlerts))

	fmt.Println()
	fmt.Println("Monitoring Done.")
	fmt.Println("Full report saved to security_report.txt")
	fmt.Println("Blocked IPs saved to blocked_ips.txt")
	fmt.Println("All threats also saved to", config.DatabaseName)
}

/*
	Yeh function config.json ko padh kar Config struct mein convert
	karta hai. json.Unmarshal JSON text ko struct ke fields mein
	fit karta hai, un naamon ke hisaab se jo humne struct ke upar
	`json:"..."` mein likhe hain.
*/
func loadConfig(path string) (Config, error) {
	var config Config
	fileData, err := os.ReadFile(path)
	if err != nil {
		return config, err
	}
	err = json.Unmarshal(fileData, &config)
	return config, err
}

/*
	Yeh function ek line check karta hai aur batata hai ke threat
	hai ya nahi. Humne patterns ko pehle se zyada precise banaya hai
	(sirf "Port scan" ki jagah poora "Port scan detected" match
	karna), taake agar koi normal line mein waise hi "port scan"
	ka zikar ho (jaise koi engineer likhe "running a port scan
	test"), hum use galti se attack na samajh baithein.
*/
func processLine(logLine string, counts *ThreatCounts) (bool, string, string) {
	/*
		Naye log format mein timestamp square brackets ke andar hai:
		"[2026-08-20 10:00:22] Keycloak - WARN: ..."
		Hum yahan se sirf date aur time nikalte hain, brackets hata kar.
	*/
	timestamp := ""
	if strings.HasPrefix(logLine, "[") {
		endBracket := strings.Index(logLine, "]")
		if endBracket != -1 {
			timestamp = logLine[1:endBracket]
		}
	}

	if strings.Contains(logLine, "CRITICAL") && strings.Contains(logLine, "Failed password") {
		counts.FailedPassword++
		return true, "Failed Password", timestamp
	}

	if strings.Contains(logLine, "WARN") && strings.Contains(logLine, "Unauthorized access attempt") {
		counts.UnauthorizedAccess++
		return true, "Unauthorized Access", timestamp
	}

	if strings.Contains(logLine, "WARN") && strings.Contains(logLine, "Port scan detected") {
		counts.PortScan++
		return true, "Port Scan", timestamp
	}

	return false, "", timestamp
}

/*
	Yeh function regex use karke line ke andar se ek valid IP address
	dhoondta hai, chahe woh kahin bhi ho. Agar line mein koi IP nahi
	hai (jaise guest access wali line), yeh khali string "" deta hai,
	aur main loop is khali string ko IP ki tarah track nahi karta.
*/
func extractIP(logLine string) string {
	match := ipRegex.FindString(logLine)
	return match
}

func saveThreatToDatabase(db *sql.DB, threatType string, ip string, timestamp string) {
	insertSQL := `INSERT INTO threats (threat_type, ip_address, event_time) VALUES (?, ?, ?);`
	_, err := db.Exec(insertSQL, threatType, ip, timestamp)
	if err != nil {
		fmt.Println("Error saving to database:", err)
	}
}

/*
	Yeh function check karta hai ke database mein kitni rows hain.
	Agar rows ki ginti humari config wali limit (jaise 100) se zyada
	ho jaye, yeh sabse purani rows delete kar deta hai, aur sirf
	sabse nayi (limit jitni) rows rakhta hai. Isse database file
	hamesha ek reasonable size mein rehti hai, chahe program kitni
	der bhi chale.
*/
func cleanupOldRecords(db *sql.DB, maxRecords int) {
	cleanupSQL := `
	DELETE FROM threats WHERE id NOT IN (
		SELECT id FROM threats ORDER BY id DESC LIMIT ?
	);`
	_, err := db.Exec(cleanupSQL, maxRecords)
	if err != nil {
		fmt.Println("Error during cleanup:", err)
	}
}
