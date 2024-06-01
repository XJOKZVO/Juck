# Juck
This Go program is designed to perform a subdomain enumeration on a given domain using three different APIs: ThreatCrowd, CRT.sh, and URLScan. It then prints out the discovered subdomains and saves them to a text file. Here's a breakdown of how it works:

1.Main Function: The main function checks if a command-line argument is provided; if not, it prompts the user to enter a domain. It then calls the subdomainScan function with the domain.

2. Subdomain Enumeration:

+ Domain Extraction: The getDomain function extracts the domain name from the provided URL using a regular expression.

+ Fetching Data: The fetchData function makes HTTP GET requests to the specified API URLs, setting a custom User-Agent header to mimic a browser request.

+ Concurrency: The subdomainScan function uses goroutines and a wait group (sync.WaitGroup) to fetch data from all three APIs concurrently. This improves performance by allowing multiple network requests to run in parallel.

+ Parsing Responses: After fetching the data, the program parses the JSON responses from each API to extract subdomains. It uses concurrent goroutines for parsing as well, ensuring that the process does not block the main thread.
 
+ Mutex Locking: To prevent race conditions when appending subdomains to the slice, a mutex lock is used. This ensures that only one goroutine can modify the slice at any given time.

3. Output:

+ The program prints out the discovered subdomains to the console.

+ It also saves the subdomains to a text file named after the domain with _subdomains.txt appended to the end.

4. Error Handling: Throughout the program, errors are checked and handled appropriately. For instance, if there's an issue fetching data from any of the APIs, the program will return an error message instead of proceeding.

5. Regular Expressions and JSON Parsing: The program uses regular expressions to parse URLs and JSON to handle the API responses. This requires understanding of both Go's regexp and encoding/json packages.

6. File Operations: The program creates a new file to store the subdomains and writes the results to this file. It handles potential errors during file creation and writing.

# Installation
```
go install github.com/XJOKZVO/Juck@latest
```

# Usage:
```
./Juck
      _   _   _    ____   _    
     | | | | | |  / ___| | | __
  _  | | | | | | | |     | |/ /
 | |_| | | |_| | | |___  |   < 
  \___/   \___/   \____| |_|\_\
                               
Enter a domain:
```
