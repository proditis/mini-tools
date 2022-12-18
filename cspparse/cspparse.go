package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
)

func matchIps(haystack string) bool {
	ValidIpAddressRegex := `(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`

	return len(matchWrapper(ValidIpAddressRegex, haystack)) > 0
}

func matchHostnames(haystack string) bool {
	ValidHostnameRegex := `^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/|ws:\/\/||wss:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$`

	return len(matchWrapper(ValidHostnameRegex, haystack)) > 0
}
func matchUrls(haystack string) bool {
	ValidUriRegex := `((([A-Za-z]{3,19}:(?:\/\/)?)(?:[-;:&=\+\$,\w]+@)?[A-Za-z0-9.-]+|(?:www.|[-;:&=\+\$,\w]+@)[A-Za-z0-9.-]+)((?:\/[\+~%\/.\w-_]*)?\??(?:[-\+=&;%@.\w_]*)#?(?:[\w]*))?)`

	return len(matchWrapper(ValidUriRegex, haystack)) > 0
}

func matchWrapper(Regexp string, haystack string) []string {
	re := regexp.MustCompile(Regexp)

	return re.FindAllString(haystack, -1)
}

func quickMatch(haystack string) bool {
	return (strings.HasPrefix(haystack, "http") || strings.HasPrefix(haystack, "ws") || strings.Contains(haystack, "//"))
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalln("Please provide a URL to check its CSP")
	}
	URI := os.Args[1]
	var base string
	if len(os.Args) == 3 {
		base = os.Args[2]
	}
	req, e := http.NewRequest("GET", URI, nil)
	if e != nil {
		log.Print("NewRequest:", e)
		os.Exit(0)
	}
	res, e := new(http.Client).Do(req)
	if e != nil {
		log.Printf("Do:", e)
		os.Exit(0)
	}
	fmt.Fprintf(os.Stderr, "[+] Checking %s status: %d for CSP: ", URI, res.StatusCode)
	policy := res.Header.Get("content-security-policy")
	if strings.TrimSpace(policy) == "" {
		println("not found")
		os.Exit(0)
	} else {
		println("found")
	}

	matches := make(map[string]bool)
	for _, element := range strings.Split(policy, " ") {
		element = strings.TrimSpace(element)
		element = strings.TrimSpace(strings.Replace(element, `;`, ``, -1))
		if quickMatch(element) || matchUrls(element) || matchHostnames(element) || matchHostnames(element) {
			// if base is not given it matches every result which has the same effect
			if strings.Contains(element, base) {
				matches[element] = true
			}
		}
	}

	fmt.Fprintf(os.Stderr, "[+] Found %d entries", len(matches))
	if base != "" {
		fmt.Fprintf(os.Stderr, " for base string [%s]", base)
	}
	fmt.Fprintln(os.Stderr, "")
	for element, _ := range matches {
		fmt.Println(element)
	}
}
