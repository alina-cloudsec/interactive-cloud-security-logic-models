package main
import "fmt"
func main() 
{
	var safeMemoryLimit int
	var userMessage string
	var inputLength int
	var attempt int
	var success bool

	safeMemoryLimit = 10 
	success = false                                                           // False by default until safe input is given

	fmt.Println("\t\t\tALINA'S INTELLECTUAL BUFFER INPUT GUARD\t\t\t")
	for attempt = 1; attempt <= 3; attempt++ 
  {
		fmt.Printf("\n[Attempt %d/3] Type your message (Max 10 characters): ", attempt)
		fmt.Scanln(&userMessage)

		inputLength = len(userMessage)

		if inputLength <= safeMemoryLimit 
    {
			fmt.Println("SYSTEM sAFE: Input size is within safe boundaries.")
			success = true
			break 
		} else 
    {
			if attempt == 1 
      {
				fmt.Println("WARNING 1:\a Your input is too long! Please try again.")
			} 
      else if attempt == 2 
      {
				fmt.Println("WARNING 2:\a Last chance! Input is still too long.")
			}
		}
	}

	if success == false                             // If user failed all 3 attempts, block the session
  {
		fmt.Println("\nSECURITY bLOCK:\a\a Too many violations! Your ID/Session is now BLOCKED.")
	}
}
