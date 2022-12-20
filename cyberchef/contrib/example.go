package main

import (
	"fmt"

	"github.com/proditis/mini-tools/cyberchef"
)

func main() {
	hash := "098f6bcd4621d373cade4e832627b4f6"
	analysis, _ := cyberchef.AnalyzeHash(hash)
	fmt.Println("Hash:", hash)
	fmt.Println("Analysis:", analysis)
}
