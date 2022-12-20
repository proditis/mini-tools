# CyberChef in Go packaged functions
This is an attempt to port some of the cyberchef functions into Go so that they can be used by my mini-tools :smiley:

## example
```go
package main

import (
	"fmt"
	"os"

	"github.com/proditis/mini-tools/cyberchef"
)

func main() {
  hash:="098f6bcd4621d373cade4e832627b4f6"
	analysis, _ := cyberchef.AnalyzeHash(hash)
	fmt.Println("Hash:", hash)
	fmt.Println("Analysis:", analysis)
}
```

running it produces
```shell
$ go run example.go
Hash: 098f6bcd4621d373cade4e832627b4f6
Analysis: [MD5 MD4 MD2 HAVAL-128 RIPEMD-128 Snefru Tiger-128]
```