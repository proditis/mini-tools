package cyberchef

//
// Mostly ported from the official https://github.com/gchq/CyberChef
//

import (
	"errors"
	"regexp"
	"strings"
)

func AnalyzeHash(input string) ([]string, error) {
	input = strings.ReplaceAll(input, " ", "")
	var (
		possibleHashFunctions []string
	)
	var byteLength = len(input) / 2
	var bitLength = byteLength * 8
	var validHash = regexp.MustCompile(`^[a-f0-9]+$(?i)`)

	if !validHash.MatchString(input) {
		return possibleHashFunctions, errors.New("Not a hash")
	}

	switch bitLength {
	case 4:
		possibleHashFunctions = []string{
			"Fletcher-4",
			"Luhn algorithm",
			"Verhoeff algorithm"}
		break
	case 8:
		possibleHashFunctions = []string{
			"Fletcher-8"}
		break
	case 16:
		possibleHashFunctions = []string{
			"BSD checksum",
			"CRC-16",
			"SYSV checksum",
			"Fletcher-16"}
		break
	case 32:
		possibleHashFunctions = []string{
			"CRC-32",
			"Fletcher-32",
			"Adler-32"}
		break
	case 64:
		possibleHashFunctions = []string{
			"CRC-64",
			"RIPEMD-64",
			"SipHash"}
		break
	case 128:
		possibleHashFunctions = []string{
			"MD5",
			"MD4",
			"MD2",
			"HAVAL-128",
			"RIPEMD-128",
			"Snefru",
			"Tiger-128"}
		break
	case 160:
		possibleHashFunctions = []string{
			"SHA-1",
			"SHA-0",
			"FSB-160",
			"HAS-160",
			"HAVAL-160",
			"RIPEMD-160",
			"Tiger-160"}
		break
	case 192:
		possibleHashFunctions = []string{
			"Tiger",
			"HAVAL-192"}
		break
	case 224:
		possibleHashFunctions = []string{
			"SHA-224",
			"SHA3-224",
			"ECOH-224",
			"FSB-224",
			"HAVAL-224"}
		break
	case 256:
		possibleHashFunctions = []string{
			"SHA-256",
			"SHA3-256",
			"BLAKE-256",
			"ECOH-256",
			"FSB-256",
			"GOST",
			"Grøstl-256",
			"HAVAL-256",
			"PANAMA",
			"RIPEMD-256",
			"Snefru"}
		break
	case 320:
		possibleHashFunctions = []string{
			"RIPEMD-320",
		}
		break
	case 384:
		possibleHashFunctions = []string{
			"SHA-384",
			"SHA3-384",
			"ECOH-384",
			"FSB-384"}
		break
	case 512:
		possibleHashFunctions = []string{
			"SHA-512",
			"SHA3-512",
			"BLAKE-512",
			"ECOH-512",
			"FSB-512",
			"Grøstl-512",
			"JH",
			"MD6",
			"Spectral Hash",
			"SWIFFT",
			"Whirlpool"}
		break
	case 1024:
		possibleHashFunctions = []string{"Fowler-Noll-Vo"}
		break
	default:
		possibleHashFunctions = []string{"Unknown"}
		break
	}

	return possibleHashFunctions, nil
}
