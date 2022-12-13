package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

const version = "X.X.X" // populated by build script
const scriptname = "certnames"
const shortDescription = "Extracts Subject Alt Names from x509 PEM format certificate(s) from a list of files"

// holds the args supplied to the program
type commandArgs struct {
	Debug          bool
	IncludeSubject bool
	DoDNS          bool
}

// Display usage then exit
func usage() {
	//usage := `Usage: ` + scriptname + ` [Options] files`
	usage := scriptname + ` v` + version + `
   ` + shortDescription + `

Usage: ` + scriptname + ` [Options] files
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
	}

}
