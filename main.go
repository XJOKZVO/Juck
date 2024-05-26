package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)
const (
	ThreatCrowdAPI = "http://ci-www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s"
	CrtShAPI       = "https://crt.sh/?q=%%25.%s&output=json"
	URLScanAPI     = "https://urlscan.io/api/v1/search/?q=domain:%s"
)

func getDomain(url string) (string, error) {
	re := regexp.MustCompile(`^(?:https?://)?(?:[^@/]+@)?(?:www\.)?([^:/?]+)`)
	match := re.FindStringSubmatch(url)
	if len(match) > 1 {
		return match[1], nil
	}
	return "", fmt.Errorf("invalid URL format")
}

func fetchData(url string) ([]byte, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("received non-200 response code")
	}
	return ioutil.ReadAll(resp.Body)
}

func subdomainScan(url string) ([]string, error) {
	domain, err := getDomain(url)
	if err != nil {
		return nil, err
	}

	threatCrowdURL := fmt.Sprintf(ThreatCrowdAPI, domain)
	crtShURL := fmt.Sprintf(CrtShAPI, domain)
	urlScanURL := fmt.Sprintf(URLScanAPI, domain)

	var wg sync.WaitGroup
	wg.Add(3)

	var threatCrowdData, crtShData, urlScanData []byte
	var threatCrowdErr, crtShErr, urlScanErr error

	go func() {
		defer wg.Done()
		threatCrowdData, threatCrowdErr = fetchData(threatCrowdURL)
	}()

	go func() {
		defer wg.Done()
		crtShData, crtShErr = fetchData(crtShURL)
	}()

	go func() {
		defer wg.Done()
		urlScanData, urlScanErr = fetchData(urlScanURL)
	}()

	// Wait for all fetch operations to complete
	wg.Wait()

	if threatCrowdErr != nil || crtShErr != nil || urlScanErr != nil {
		return nil, fmt.Errorf("failed to fetch data from one or more sources")
	}

	// Parse responses concurrently
	var subdomains []string
	var mutex sync.Mutex

	// Parse ThreatCrowd response
	go func() {
		var threatCrowdResponse struct {
			Subdomains []string `json:"subdomains"`
		}
		if err := json.Unmarshal(threatCrowdData, &threatCrowdResponse); err != nil {
			fmt.Println("Error parsing ThreatCrowd response:", err)
			return
		}

		mutex.Lock()
		subdomains = append(subdomains, threatCrowdResponse.Subdomains...)
		mutex.Unlock()
	}()

	// Parse Crt.sh response
	go func() {
		var crtShResponse []struct {
			NameValue string `json:"name_value"`
		}
		if err := json.Unmarshal(crtShData, &crtShResponse); err != nil {
			fmt.Println("Error parsing Crt.sh response:", err)
			return
		}

		mutex.Lock()
		for _, entry := range crtShResponse {
			subdomains = append(subdomains, strings.Split(entry.NameValue, "\n")...)
		}
		mutex.Unlock()
	}()

	// Parse URLScan response
	go func() {
		var urlScanResponse struct {
			Results []struct {
				Page struct {
					Domain string `json:"domain"`
				} `json:"page"`
			} `json:"results"`
		}
		if err := json.Unmarshal(urlScanData, &urlScanResponse); err != nil {
			fmt.Println("Error parsing URLScan response:", err)
			return
		}

		mutex.Lock()
		for _, result := range urlScanResponse.Results {
			subdomains = append(subdomains, result.Page.Domain)
		}
		mutex.Unlock()
	}()

	// Wait for all parsing operations to complete
	time.Sleep(2 * time.Second) // Adjust as needed to ensure parsing completes
	return subdomains, nil
}

func main() {
	fmt.Println(`      _   _   _    ____   _    
     | | | | | |  / ___| | | __
  _  | | | | | | | |     | |/ /
 | |_| | | |_| | | |___  |   < 
  \___/   \___/   \____| |_|\_\
                               `)

	var url string
	if len(os.Args) > 1 {
		url = os.Args[1]
	} else {
		fmt.Print("Enter a domain: ")
		fmt.Scan(&url)
	}

	subdomains, err := subdomainScan(url)
	if err != nil {
		fmt.Printf("\nFailed to find subdomains of %s\n", url)
		return
	}

	fmt.Printf("\nSubdomains of %s found!\n\n", url)
	for _, subdomain := range subdomains {
		fmt.Printf("http://%s\n", subdomain)
	}

	domain, _ := getDomain(url)
	fileName := fmt.Sprintf("%s_subdomains.txt", domain)
	file, err := os.Create(fileName)
	if err != nil {
		fmt.Printf("\nFailed to save subdomains to file: %s\n", err)
		return
	}
	defer file.Close()

	for _, subdomain := range subdomains {
		file.WriteString(fmt.Sprintf("http://%s\n", subdomain))
	}
	fmt.Printf("\nSubdomains saved to '%s'\n", fileName)
}
