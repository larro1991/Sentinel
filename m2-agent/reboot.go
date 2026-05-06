package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// execCommand is swappable for testing.
var execCommand = exec.Command

func runCmd(name string, args ...string) (string, error) {
	out, err := execCommand(name, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out), nil
}
