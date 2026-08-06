package main
import "fmt"
func main() 
{
	var blacklist []string
	var visitorIP string
	var isBlocked bool

	blacklist = []string{"192.168.1.50", "10.0.0.99", "172.16.0.4"}
	isBlocked = false 

	fmt.Println("--- ALINA'S LIVE MULTI-IP FIREWALL ---")
	fmt.Print("Enter your IP Address to check network permission: ")
	fmt.Scanln(&visitorIP)

	for _,badIP:=range blacklist 
  {
		if visitorIP == badIP 
    {
			isBlocked = true
		}
	}

	if isBlocked == true 
  {
		fmt.Println("ACCESS DENIED\a! Your IP is blacklisted in our database.")
	} 
  else 
  {
		fmt.Println("ACCESS ALLOWED! Welcome to the network.")
	}
}
