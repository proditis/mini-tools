package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalln("Missing pem filename")
	}
	certFile := os.Args[1]
	bs, err := os.ReadFile(certFile) // handle error
	if err != nil {
		log.Fatalf("File %s not found", certFile)
	}
	block, _ := pem.Decode(bs)
	if block == nil {
		log.Fatal("failed to parse PEM block containing the public key")
	}

	cert, err := x509.ParseCertificate(block.Bytes) // handle error

	fmt.Printf("Subject:   %v\n", cert.Subject)
	fmt.Printf("DNS names: %+v\n", cert.DNSNames)

	for i := 0; i < len(cert.DNSNames); i++ {
		ips, err := net.LookupIP(cert.DNSNames[i])
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s no dns\n", cert.DNSNames[i])
		} else {
			fmt.Printf("%s %-v\n", cert.DNSNames[i], ips)
		}
	}
}
