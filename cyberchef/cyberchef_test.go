package cyberchef

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAnalyzeEmptyHash(t *testing.T) {
	var want []string
	noHash, _ := AnalyzeHash("   ")
	assert.Equal(t, want, noHash)
}

func TestAnalyzeNotAHash(t *testing.T) {
	noHash, _ := AnalyzeHash("this is not a hash")
	var want []string
	assert.Equal(t, want, noHash)
}

func TestAnalyzeMD5AHash(t *testing.T) {
	noHash, _ := AnalyzeHash("d8e8fca2dc0f896fd7cb4cb0031ba249")
	assert.Equal(t, 7, len(noHash))
	assert.Equal(t, "MD5", noHash[0])
}
func TestAnalyzeSHAHash(t *testing.T) {
	noHash, _ := AnalyzeHash("4e1243bd22c66e76c2ba9eddc1f91394e57f9f83")
	assert.Equal(t, 7, len(noHash))
	assert.Equal(t, "SHA-1", noHash[0])
}
