// Go equivalent of the "DNS & BIND" book check-soa program.
// Created by Stephane Bortzmeyer.
package main

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	TIMEOUT time.Duration = 5 // seconds
)

var (
	localm *dns.Msg
	localc *dns.Client
	conf   *dns.ClientConfig
)

func localQuery(qname string, qtype uint16) (*dns.Msg, error) {
	localm.SetQuestion(qname, qtype)
	for i := range conf.Servers {
		server := conf.Servers[i]
		r, _, err := localc.Exchange(localm, server+":"+conf.Port)
		if r == nil || r.Rcode == dns.RcodeNameError || r.Rcode == dns.RcodeSuccess {
			return r, err
		}
	}
	return nil, errors.New("No name server to answer the question")
}

func CheckSOA(name string) (string, error) {
	var err error
	conf, err = dns.ClientConfigFromFile("/etc/resolv.conf")
	if conf == nil {
		return "", errors.New(fmt.Sprint("Cannot initialize the local resolver: %s", err))
	}
	localm = new(dns.Msg)
	localm.RecursionDesired = true
	localm.Question = make([]dns.Question, 1)
	localc = new(dns.Client)
	localc.ReadTimeout = TIMEOUT * 1e9
	r, err := localQuery(name, dns.TypeNS)
	if r == nil {
		return "", errors.New(fmt.Sprintf("Cannot retrieve the list of name servers for %s: %s", dns.Fqdn(name), err))
	}
	if r.Rcode == dns.RcodeNameError {
		return "", errors.New(fmt.Sprintf("No such domain %s", dns.Fqdn(name)))
	}
	m := new(dns.Msg)
	m.RecursionDesired = false
	m.Question = make([]dns.Question, 1)
	c := new(dns.Client)
	c.ReadTimeout = TIMEOUT * 1e9
	success := true
	numNS := 0
	for _, ans := range r.Answer {
		switch ans.(type) {
		case *dns.NS:
			nameserver := ans.(*dns.NS).Ns
			numNS += 1
			ipsNS := make([]string, 0)
			fmt.Printf("NS %s: ", nameserver)
			ra, err := localQuery(nameserver, dns.TypeA)
			if ra == nil {
				return "", errors.New(fmt.Sprintf("Error getting the IPv4 address of %s: %s", nameserver, err))
			}

			if ra.Rcode != dns.RcodeSuccess {
				return "", errors.New(fmt.Sprintf("Error getting the IPv4 address of %s: %s", nameserver, dns.RcodeToString[ra.Rcode]))
			}

			for _, ansa := range ra.Answer {
				switch ansa.(type) {
				case *dns.A:
					ipsNS = append(ipsNS, ansa.(*dns.A).A.String())
				}
			}
			//fmt.Println(ipsNS)
			if len(ipsNS) == 0 {
				success = false
				fmt.Printf("No IP address for this server")
			}

			for _, ip := range ipsNS {
				m.Question[0] = dns.Question{dns.Fqdn(name), dns.TypeSOA, dns.ClassINET}
				nsAddressPort := ""
				if strings.ContainsAny(":", ip) {
					nsAddressPort = "[" + ip + "]:53"
				} else {
					nsAddressPort = ip + ":53"
				}
				soa, _, err := c.Exchange(m, nsAddressPort)
				//fmt.Println(soa)
				// TODO: retry if timeout? Otherwise, one lost UDP packet and it is the end
				if soa == nil {
					success = false
					fmt.Printf("%s (%s) ", ip, err)
					goto Next
				}
				if soa.Rcode != dns.RcodeSuccess {
					success = false
					fmt.Printf("%s (%s) ", ipsNS, dns.RcodeToString[soa.Rcode])
					goto Next
				}
				if len(soa.Answer) == 0 { // May happen if the server is a recursor, not authoritative, since we query with RD=0
					success = false
					fmt.Printf("%s (0 answer) ", ip)
					goto Next
				}
				rsoa := soa.Answer[0]
				switch rsoa.(type) {
				case *dns.SOA:
					if soa.Authoritative {
						// TODO: test if all name servers have the same serial ?
						fmt.Printf("%s (%d) %s %s", ipsNS, rsoa.(*dns.SOA).Serial, rsoa.(*dns.SOA).Ns, rsoa.(*dns.SOA).Mbox)
					} else {
						success = false
						fmt.Printf("%s (not authoritative) ", ipsNS)
					}
				}
			}
		Next:
			fmt.Printf("\n")
		}
	}
	if numNS == 0 {
		return "", errors.New(fmt.Sprintf("No NS records for \"%s\". It is probably a CNAME to a domain but not a zone", dns.Fqdn(name)))
	}

	if !success {
		return "", errors.New("SOA NOT FOUND")
	}

	return "Success", nil
}
