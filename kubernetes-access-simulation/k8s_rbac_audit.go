package main
import "fmt"
type UserProfile struct 
{
	UserName    string
	UserRole    string 
	Environment string 
}

func main() 
{
	fmt.Println("\t\t\tVerifying Cloud Infrastructure Access Matrix\t\t\t")
	fmt.Println()

	registeredUsers := []UserProfile
  {
		{UserName: "alina-security", UserRole: "admin", Environment: "production"},
		{UserName: "untrusted-agent", UserRole: "developer", Environment: "production"},
		{UserName: "guest-test", UserRole: "guest", Environment: "staging"},
	}

	for _, singleUser := range registeredUsers 
  {
		fmt.Printf("Checking access tokens for: %s\n", singleUser.UserName)
    
		if singleUser.UserRole == "developer" && singleUser.Environment == "production" 
    {
			fmt.Println("\a Policy Violation: Non-admin users cannot push into production zones!")
		} 
    else if singleUser.UserRole == "admin" 
    {
			fmt.Println("clear: Global administrator permissions detected.")
		} 
    else 
    {
			fmt.Println(" Clear: Standard isolated low-risk token verified.")
		}
	}
}
