package enrollmenttoken

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestGeneratorCreatesOpaqueHashedToken(t *testing.T) {
	generator := NewGenerator()

	first, err := generator.New()
	if err != nil {
		t.Fatal(err)
	}
	second, err := generator.New()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(first.Plaintext, "enr_") || first.Plaintext == second.Plaintext {
		t.Fatalf("generated tokens = %q, %q", first.Plaintext, second.Plaintext)
	}
	sum := sha256.Sum256([]byte(first.Plaintext))
	if first.Hash != hex.EncodeToString(sum[:]) {
		t.Fatalf("token hash = %q", first.Hash)
	}
	if !strings.Contains(first.Preview, "...") || strings.Contains(first.Preview, first.Plaintext) {
		t.Fatalf("token preview = %q", first.Preview)
	}
}
