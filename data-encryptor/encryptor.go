package main
import "fmt"
func main() 
{
	var userSecret string
	var maskedOutput string
	maskedOutput = "*********"

	fmt.Println("\t\t\tALINA'S LIVE SECURITY LOG REDACTOR\t\t\t")
	fmt.Print("Enter your private API token/password: ")
	fmt.Scanln(&userSecret)

	if userSecret != "" 
  {
		fmt.Println("Sanitized Log File Output Saved: ", maskedOutput)
	} 
  else 
  {
		fmt.Println("Error:\a No token input detected.")
	}
}
