package event

import "strings"

const (
	BehaviorProcessExec    = "process.exec"
	BehaviorProcessFork    = "process.fork"
	BehaviorProcessExit    = "process.exit"
	BehaviorFileOpen       = "file.open"
	BehaviorFileRead       = "file.read"
	BehaviorFileWrite      = "file.write"
	BehaviorFileChmod      = "file.chmod"
	BehaviorNetworkConnect = "network.connect"
)

func NormalizeBehavior(value string) string {
	return strings.TrimSpace(strings.ToLower(value))
}
