package main

import (
	"bytes"
	"os/exec"
	"runtime"
	"strings"
)

var blockedChars = []string{"|", "&", ";", ">", "<", "`", "$("}

var blockedTokens = map[string]bool{
	"rm": true, "curl": true, "wget": true,
	"chmod": true, "chown": true, "kill": true,
}

var simpleAllowed = map[string]bool{
	"df": true, "du": true, "ls": true, "cat": true, "ps": true,
	"top": true, "netstat": true, "ss": true, "ip": true,
	"hostname": true, "uname": true, "journalctl": true,
}

func RunShell(cmd string) ShellResponse {
	if runtime.GOOS == "windows" {
		return ShellResponse{Stderr: "shell disabled on windows", RC: 126}
	}

	reject := ShellResponse{Stderr: "command not in whitelist", RC: 126}

	for _, ch := range blockedChars {
		if strings.Contains(cmd, ch) {
			return reject
		}
	}

	args := strings.Fields(strings.TrimSpace(cmd))
	if len(args) == 0 {
		return reject
	}

	first := args[0]

	if blockedTokens[first] {
		return reject
	}

	switch first {
	case "efibootmgr":
		if len(args) != 2 || args[1] != "-v" {
			return reject
		}
	case "systemctl":
		if len(args) < 2 || args[1] != "status" {
			return reject
		}
	case "docker":
		allowed := map[string]bool{"ps": true, "logs": true, "inspect": true}
		if len(args) < 2 || !allowed[args[1]] {
			return reject
		}
	default:
		if !simpleAllowed[first] {
			return reject
		}
	}

	var stdout, stderr bytes.Buffer
	c := exec.Command(args[0], args[1:]...)
	c.Stdout = &stdout
	c.Stderr = &stderr
	err := c.Run()

	rc := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			rc = exitErr.ExitCode()
		} else {
			rc = 1
		}
	}

	return ShellResponse{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
		RC:     rc,
	}
}
