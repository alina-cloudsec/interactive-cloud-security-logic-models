package main
import "fmt"
import "strings"
func main() 
{
	fmt.Println("\t\t\tStarting Cloud Server Log Monitoring\t\t\t")
	fmt.Println()
	systemLogs := []string                                  // Simulated live operating system system logs stream
  {
		"Info: Session opened for user alina",
		"CRITICAL: Failed password for root from IP 192.168.10.5",
		"Info: Database connection established",
		"CRITICAL: Failed password for admin from IP 192.168.10.5",
		"Info: Automated background backup finished",
	}
	attackCount := 0

	for _, logLine:= range systemLogs 
  {
		if strings.Contains(logLine, "Failed password") 
    {
			attackCount++
			fmt.Printf("\a Threat Detected! Details: %s", logLine)
		}
	}
	fmt.Printf("Monitoring Done. Total high-risk alerts raised: %d", attackCount)
}
