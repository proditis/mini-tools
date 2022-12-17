package main

/*
 * code heavily based on https://github.com/jvns/tiny-resolver
 * credits: Julia Evans @jvns http://jvns.ca
 */

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/proditis/mini-tools/cyberchef"
)

var interesting = []string{"domain", "verif"}

// Parse SPF txt record for entries matching a: and include:
func parseSpf(line string) []string {
	var spfHosts []string
	for _, portion := range strings.Split(line, " ")[1:] {
		if strings.Contains(portion, "a:") || strings.Contains(portion, "include:") {
			spfHosts = append(spfHosts, strings.TrimSpace(strings.Split(portion, ":")[1]))
		} else if !strings.Contains(portion, "-all") {
			spfHosts = append(spfHosts, strings.TrimSpace(portion))
		}

	}
	return spfHosts
}

func isInteresting(line string) string {
	var val string
	for _, entry := range interesting {
		if strings.Contains(line, entry) && !strings.Contains(line, "=") {
			return line
		} else if strings.Contains(line, "=") {
			if strings.HasSuffix(line, "=") {
				decoded, _ := base64.StdEncoding.DecodeString(line)
				//fmt.Print(" has base64 decoded length: ", len(decoded))
				val = string(decoded[:])

			} else if strings.Contains(line, "=") {
				val = strings.Split(line, "=")[1]
				//fmt.Print(" has = ", val)
			}
			//fmt.Println()
			if hash, err := cyberchef.AnalyzeHash(val); err == nil {
				return strings.Join(hash, ", ")
			} else if strings.Contains(line, "=") && !strings.HasSuffix(line, "=") {
				return strings.Split(line, "=")[0]
			}
		}
	}
	return ""
}

func lookupDMARC(name string) {
	var selectors = []string{"selector._domainkey", "_dmarc", "selector1._domainkey", "_domainkey"}
	for _, selector := range selectors {
		records, err := net.LookupTXT(selector + "." + name)
		if err == nil {
			for _, entry := range records {
				fmt.Println("Found DMARC selector:", selector, "=>", entry)
			}
		}
	}
}
func lookupNS(name string) []string {
	var ns []string
	records, err := net.LookupNS(name)
	if err == nil {
		for _, entry := range records {
			ns = append(ns, strings.Trim(entry.Host, "."))
			fmt.Println("NS:", entry.Host)
		}
	}
	return ns
}

func main() {
	for _, name := range os.Args[1:] {
		if !strings.HasSuffix(name, ".") {
			name = name + "."
		}
		fmt.Println("Querying for:", name)
		NS := lookupNS(name)
		for _, nsServer := range NS {
			r := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{
						Timeout: time.Millisecond * time.Duration(10000),
					}
					return d.DialContext(ctx, network, nsServer+":53")
				},
			}
			fmt.Println("Using dns:", nsServer)
			records, err := r.LookupTXT(context.Background(), name)
			if err == nil {
				for _, entry := range records {
					if strings.Contains(entry, "v=spf") {
						fmt.Println("SPF Record hosts:", parseSpf(entry))
					} else if isInteresting(entry) != "" {
						fmt.Printf("Interesting Record: %v => %s\n", entry, isInteresting(entry))
					}
				}
			}

			records, err = r.LookupHost(context.Background(), name)
			if err == nil {
				fmt.Println("A Records:", records)
				//for _, entry := range records {
				//	fmt.Println(entry)
				//}
			}

			cname, err := r.LookupCNAME(context.Background(), name)
			if err == nil && cname != name {
				fmt.Println("CNAME:", cname)
			}
			mx, err := r.LookupMX(context.Background(), name)
			if err == nil {
				for _, mxHost := range mx {
					fmt.Println("MX:", mxHost.Host)

				}
			}

		}
		lookupDMARC(name)
		CheckSOA(name)
	}
}
