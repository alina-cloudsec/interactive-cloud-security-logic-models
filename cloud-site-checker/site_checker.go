package main
import "fmt"
import "net/http"
func main() 
{
	var targetUrl string
	var response *http.Response
	var err error

	fmt.Println("\t\t\tALINA'S LIVE CONTAINER HEALTH PROBE\t\t\t")
	fmt.Print("Enter complete Website URL to test: ")
	fmt.Scanln(&targetUrl)
  
	response, err = http.Get(targetUrl)
  
	if err == nil && response.StatusCode == http.StatusOK 
  {
		fmt.Println("success: Application is Healthy (Status 200 OK)!")
	} 
  else 
  {
		fmt.Println("alert\a: Container Health Check Failed! Service is down.")
	}
}
