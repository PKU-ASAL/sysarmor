package event

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func StableProcessID(hostID string, pid uint32, startNS uint64) string {
	return shortHash(fmt.Sprintf("%s:%d:%d", hostID, pid, startNS))
}

func SensorProcessID(hostID, execID string) string {
	return shortHash(fmt.Sprintf("%s:%s", hostID, execID))
}

func EventID(agentID string, sequence uint64) string {
	return fmt.Sprintf("%s-%020d", agentID, sequence)
}

func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:12])
}
