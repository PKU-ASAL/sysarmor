//go:build !linux

package tetragon

import "os/exec"

func configureProcessGroup(_ *exec.Cmd) {}
