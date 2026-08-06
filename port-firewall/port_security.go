package main
import "fmt"
func main() 
{
	var dangerousPort int
	var incomingPort int
	dangerousPort = 22 

	fmt.Println("--- ALINA'S LIVE PORT SECURITY SYSTEM ---")
	fmt.Print("Enter the port number you want to connect to: ")
	fmt.Scanln(&incomingPort)

	if incomingPort == dangerousPort 
  {
		fmt.Println("WARNING\a: Connection to dangerous port 22 is BLOCKED!")
	} 
  else 
  {
		fmt.Println("SAFE: Connection allowed on a safe port.")
	}
}
