package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
)

const version = "v0.0.0" // populated by build script
const scriptname = "cspparse"
const shortDescription = "Extracts domains, IPs and URLs from Content Security Policy headers"

const (
	PROTO_REGEXP    = `[A-Z]+://`
	HOSTNAME_REGEXP = `[-\\w]+(?:\\.\\w[-\\w]*)+`
	PORT_REGEXP     = `:\\d+`
	PATH_REGEXP     = `/[^.!,?\"<>\\[\\]{}\\s\\x7F-\\xFF]*(?:[.!,?]+[^.!,?\"<>\\[\\]{}\\s\\x7F-\\xFF]+)*`
	URL_REGEX       = PROTO_REGEXP + HOSTNAME_REGEXP + "(?:" + PORT_REGEXP + ")?(?:" + PATH_REGEXP + ")?"
	DOMAIN_REGEX    = `\b(([a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}\b`
)

// holds the args supplied to the program
type commandArgs struct {
	Debug bool
	Base  string
}

type matchStatus struct {
	Quick    bool
	Url      bool
	IP       bool
	Hostname bool
	Filter   bool
}

func usage() {
	//usage := `Usage: ` + scriptname + ` [Options] files`
	usage := scriptname + ` ` + version + `
   ` + shortDescription + `

Usage: ` + scriptname + ` [Options] URL [string]
  URL          the url to fetch the CSP header from
  [string]     (optional) only return entries matching string

Options:
  -h, --help   show this help message and exit
  -d           debug output (displays match statuses)

`
	fmt.Fprint(flag.CommandLine.Output(), usage)
	os.Exit(0)
}

func matchIps(haystack string) bool {
	ValidIpAddressRegex := `(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`

	return len(matchWrapper(ValidIpAddressRegex, haystack)) > 0
}

func matchHostnames(haystack string) bool {
	return len(matchWrapper(DOMAIN_REGEX, haystack)) > 0
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
	args := commandArgs{}
	log.SetFlags(0)
	log.SetPrefix("")
	flag.BoolVar(&args.Debug, "d", false, "debug output")
	flag.Usage = usage
	flag.Parse()

	if len(flag.Args()) < 1 {
		log.Println("Please provide a URL to check its CSP")
		flag.Usage()
	}
	URI := flag.Arg(0)
	if len(flag.Args()) == 2 {
		args.Base = flag.Arg(1)
	}
	req, e := http.NewRequest("GET", URI, nil)
	if e != nil {
		log.Println("NewRequest:", e)
		return
	}
	res, e := new(http.Client).Do(req)
	if e != nil {
		log.Println("Do:", e)
		return
	}
	fmt.Fprintf(os.Stderr, "[+] Checking %s status: %d for CSP: ", URI, res.StatusCode)
	policy := res.Header.Get("content-security-policy")
	if strings.TrimSpace(policy) == "" {
		println("not found")
		return
	} else {
		println("found")
	}

	matches := make(map[string]matchStatus)
	for _, element := range strings.Split(policy, " ") {
		element = strings.TrimSpace(element)
		element = strings.TrimSpace(strings.Replace(element, `;`, ``, -1))
		qM := quickMatch(element)
		mU := matchUrls(element)
		mI := matchIps(element)
		mH := matchHostnames(element)
		if qM || mU || mH || mI {
			// if base is not given it matches every result which has the same effect
			if strings.Contains(element, args.Base) {
				matches[element] = matchStatus{qM, mU, mI, mH, args.Base != "" && strings.Contains(element, args.Base)}
			}
		}
	}

	fmt.Fprintf(os.Stderr, "[+] Found %d entries", len(matches))
	if args.Base != "" {
		fmt.Fprintf(os.Stderr, " for base string [%s]", args.Base)
	}
	fmt.Fprintln(os.Stderr, "")
	for element, data := range matches {
		fmt.Print(element)
		if args.Debug {
			fmt.Printf(" %+v", data)
		}
		fmt.Println()
	}
}
