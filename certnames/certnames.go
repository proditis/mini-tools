package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
)

var version = "X.X.X" // populated by build script
// holds the args supplied to the program
type commandArgs struct {
	Debug          bool
	IncludeSubject bool
	DoDNS          bool
}

// Display usage then exit
func usage() {
	usage := `Usage: certnames [Options] files`
	usage += `
Extracts Subject Alt Names from x509 PEM format certificate(s) from a list of files
  certnames v` + version + `
Options:
  -h, --help    show this help message and exit
  -s, --subject include subject display
  -d, --dns     do dns on subject names
`
	fmt.Fprint(flag.CommandLine.Output(), usage)
	os.Exit(0)
}

// Helper func to handle errors that should exit the program
func handlErrFatal(err error) {
	if err != nil {
		log.Fatal("[!] ", err)
	}
}

// Check that the args passed are valid, returns either the host string or shows usage
func checkArgs() {
	if len(os.Args) < 2 {
		fmt.Fprint(flag.CommandLine.Output(), "Missing pem filename\n")
		usage()
	}
}

func lookupHelper(DNSNames string) []string {
	var ipStr []string
	ips, err := net.LookupIP(DNSNames)
	if err == nil {
		for _, lip := range ips {
			ipStr = append(ipStr, lip.String())
		}
	}
	return ipStr
}
func main() {
	args := commandArgs{}
	log.SetFlags(0)
	log.SetPrefix("")

	// setup and process args
	flag.BoolVar(&args.Debug, "debug", false, "debug output")
	flag.BoolVar(&args.IncludeSubject, "s", false, "include cetificate subject")
	flag.BoolVar(&args.IncludeSubject, "subject", false, "include cetificate subject")
	flag.BoolVar(&args.DoDNS, "d", false, "do DNS on names")
	flag.BoolVar(&args.DoDNS, "dns", false, "do DNS on names")
	flag.Usage = usage
	flag.Parse()
	checkArgs()

	for _, certFile := range flag.Args() {
		if args.Debug {
			fmt.Println(certFile)
		}

		bs, err := os.ReadFile(certFile) // handle error
		if err != nil {
			fmt.Fprintf(flag.CommandLine.Output(), "File %s not found", certFile)
			continue
		}

		block, _ := pem.Decode(bs)
		if block == nil {
			log.Println("failed to parse PEM block containing the public key")
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes) // handle error
		if args.IncludeSubject {
			fmt.Printf("# Subject:   %v\n", cert.Subject)
		}
		//fmt.Printf("DNS names: %+v\n", cert.DNSNames)
		for i := 0; i < len(cert.DNSNames); i++ {
			fmt.Fprintf(flag.CommandLine.Output(), "%s", cert.DNSNames[i])
			if args.DoDNS {
				ips := lookupHelper(cert.DNSNames[i])
				if len(ips) > 0 {
					fmt.Fprintf(flag.CommandLine.Output(), " %s", strings.Join(ips, " "))
				}
			}
			fmt.Fprintln(flag.CommandLine.Output(), "")
		}
		fmt.Fprintln(flag.CommandLine.Output(), "")
	}

}
