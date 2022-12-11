package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

func handlErrFatal(err error) {
	if err != nil {
		log.Fatal("[!] ", err)
	}
}

func getCerts(host string) []*x509.Certificate {
	log.Printf("[*] retrieving cert(s) from %s", host)
	// not bothered about verification of cert
	cfg := &tls.Config{InsecureSkipVerify: true}
	dialer := &net.Dialer{}
	conn, err := tls.DialWithDialer(dialer, "tcp", host, cfg)
	handlErrFatal(err)
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates
}

func processCerts(certs []*x509.Certificate) []string {
	m := make(map[string]bool)
	var hostnames []string
	// only use the first item in the slice
	certs = []*x509.Certificate{certs[0]}

	log.Printf("[+] retrieved %d cert(s)", len(certs))
	for _, cert := range certs {
		//fmt.Printf("Subject:   %v\n", cert.Subject)
		for _, _h := range cert.DNSNames {

			if m[_h] != true && !strings.HasPrefix(_h, "*") {
				m[_h] = true
				hostnames = append(hostnames, _h)
			} //else if strings.HasPrefix(_h, "*") {
			//fmt.Println("[-] skipping:", _h)
			//}
		}
	}
	sort.Strings(hostnames)
	return hostnames
}

func simpleNoSNI(ipStr string, url string, follow bool) (*http.Response, error) {
	req, _ := http.NewRequest("GET", url, nil)
	//	trace := &httptrace.ClientTrace{
	//		GotConn: func(connInfo httptrace.GotConnInfo) {
	//			log.Printf("resolved to: %s", connInfo.Conn.RemoteAddr())
	//		},
	//	}
	//
	//	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	req.Header.Set("User-Agent", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36")

	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}

	client := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !follow {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// redirect all connections to 127.0.0.1
				addr = ipStr + addr[strings.LastIndex(addr, ":"):]
				return dialer.DialContext(ctx, network, addr)
			},
		},
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return res, nil

}
func NoSNI(ipStr string, hostname string, url string) *http.Response {

	client := &http.Client{
		// adapted from http.DefaultTransport
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig: &tls.Config{
				ServerName:         ipStr,
				InsecureSkipVerify: true,
				VerifyConnection: func(cs tls.ConnectionState) error {
					opts := x509.VerifyOptions{
						DNSName:       hostname,
						Intermediates: x509.NewCertPool(),
					}
					for _, cert := range cs.PeerCertificates[1:] {
						opts.Intermediates.AddCert(cert)
					}
					_, err := cs.PeerCertificates[0].Verify(opts)
					return err
				},
			},
		},
	}

	res, err := client.Get(url)
	if err != nil {
		fmt.Printf("%v\n", err)
		return nil
	}
	defer res.Body.Close()
	//body, err := io.ReadAll(res.Body)
	//headers := res.Header
	//fmt.Printf("%+v\n", headers)
	//fmt.Println(string(body))
	return res
}
func main() {
	port := "443"
	if len(os.Args) < 2 {
		log.Fatalln("Missing hostname")
	} else if len(os.Args) == 3 {
		port = os.Args[2]
	}

	hostname := os.Args[1]

	ips, err := net.LookupIP(hostname)
	if err != nil {
		fmt.Printf("failed to resolve domain %s %v", hostname, err)
	}

	firstIP := fmt.Sprintf("%s", ips[0])
	log.Printf("[+] base domain: %s", hostname)
	log.Printf("[+] base IP: %s", firstIP)
	certs := getCerts(hostname + `:` + port)
	hostnames := processCerts(certs)
	log.Printf("Found %d unique domains: %+v\n", len(hostnames), hostnames)
	for _, host := range hostnames {
		url := `https://` + host + `:` + port
		//NoSNI(firstIP, host, url)
		response, err := simpleNoSNI(firstIP, url, false)
		if err == nil {
			log.Printf("[+] status: %d, host: %s\n", response.StatusCode, host)
		} // else {
		// log.Printf("[-] host: %s got error: %v", host, err)
		//}
	}

}
