package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
)

type ScriptRequest struct {
	Script string `json:"script"`
	Shell  string `json:"shell"` // default: /bin/bash
}

// handleScript runs an arbitrary bash script with no filter.
// Caller must be trusted (LAN-only, no auth by design — broker is the gatekeeper).
func handleScript(w http.ResponseWriter, r *http.Request) {
	var req ScriptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Script == "" {
		http.Error(w, "script required", http.StatusBadRequest)
		return
	}
	shell := req.Shell
	if shell == "" {
		shell = "/bin/bash"
	}

	f, err := os.CreateTemp("", "m2script*.sh")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, ShellResponse{Stderr: err.Error(), RC: 1})
		return
	}
	defer os.Remove(f.Name())

	if _, err := io.WriteString(f, req.Script); err != nil {
		f.Close()
		writeJSON(w, http.StatusInternalServerError, ShellResponse{Stderr: err.Error(), RC: 1})
		return
	}
	f.Close()

	var stdout, stderr bytes.Buffer
	c := exec.Command(shell, f.Name())
	c.Stdout = &stdout
	c.Stderr = &stderr
	err = c.Run()

	rc := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			rc = exitErr.ExitCode()
		} else {
			rc = 1
		}
	}

	writeJSON(w, http.StatusOK, ShellResponse{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
		RC:     rc,
	})
}
