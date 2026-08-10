package enrollmenttoken

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type Generator struct{}

func NewGenerator() *Generator { return &Generator{} }

func (*Generator) New() (ports.EnrollmentToken, error) {
	var entropy [24]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return ports.EnrollmentToken{}, fmt.Errorf("generate enrollment token: %w", err)
	}
	plaintext := "enr_" + base64.RawURLEncoding.EncodeToString(entropy[:])
	sum := sha256.Sum256([]byte(plaintext))
	return ports.EnrollmentToken{
		Plaintext: plaintext,
		Hash:      hex.EncodeToString(sum[:]),
		Preview:   plaintext[:8] + "..." + plaintext[len(plaintext)-4:],
	}, nil
}
