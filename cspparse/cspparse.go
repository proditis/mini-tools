package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
)

func matchIps(haystack string) []string {
	ValidIpAddressRegex := `(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`
	return matchWrapper(ValidIpAddressRegex, haystack)
}

func matchHostnames(haystack string) []string {
	ValidHostnameRegex := `(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$`
	return matchWrapper(ValidHostnameRegex, haystack)
}
func matchUrls(haystack string) []string {
	ValidUriRegex := `((([A-Za-z]{3,19}:(?:\/\/)?)(?:[-;:&=\+\$,\w]+@)?[A-Za-z0-9.-]+|(?:www.|[-;:&=\+\$,\w]+@)[A-Za-z0-9.-]+)((?:\/[\+~%\/.\w-_]*)?\??(?:[-\+=&;%@.\w_]*)#?(?:[\w]*))?)`

	return matchWrapper(ValidUriRegex, haystack)
}

func matchWrapper(Regexp string, haystack string) []string {
	re := regexp.MustCompile(Regexp)
	match := re.FindAllString(haystack, -1)
	return match
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
		log.Fatalln("NewRequest:", e)
	}
	res, e := new(http.Client).Do(req)
	if e != nil {
		log.Fatalln("Do:", e)
	}
	fmt.Fprintf(os.Stderr, "[+] Checking %s status: %d for CSP: ", URI, res.StatusCode)
	policy := res.Header.Get("content-security-policy")
	if strings.TrimSpace(policy) == "" {
		println("not found")
		os.Exit(1)
	} else {
		println("found")
	}

	matches := make(map[string]bool)
	for _, element := range matchIps(policy) {
		if strings.Contains(element, base) {
			matches[strings.Replace(element, `;`, ``, -1)] = true
		}
	}
	//for _, element := range matchHostnames(policy) {
	//	if strings.Contains(element, base) {
	//		matches[strings.Replace(element, `;`, ``, -1)] = true
	//	}
	//}
	for _, element := range matchUrls(policy) {
		if strings.Contains(element, base) {
			matches[strings.Replace(element, `;`, ``, -1)] = true
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
