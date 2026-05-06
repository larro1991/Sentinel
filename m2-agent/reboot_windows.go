//go:build windows

package main

import (
	"fmt"
	"strings"
)

func SetNextBootAndReboot(entry string) error {
	if entry == "" {
		entry = "sentry"
	}

	out, err := runCmd("bcdedit", "/enum", "firmware")
	if err != nil {
		return err
	}

	entryLower := strings.ToLower(entry)

	// bcdedit separates entries with blank lines; handle both CRLF and LF.
	normalized := strings.ReplaceAll(out, "\r\n", "\n")
	blocks := strings.Split(normalized, "\n\n")

	for _, block := range blocks {
		var id, desc string
		for _, line := range strings.Split(block, "\n") {
			line = strings.TrimSpace(line)
			lower := strings.ToLower(line)
			if strings.HasPrefix(lower, "identifier") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					id = fields[len(fields)-1]
				}
			}
			if strings.HasPrefix(lower, "description") {
				idx := strings.Index(line, " ")
				if idx >= 0 {
					desc = strings.TrimSpace(line[idx:])
				}
			}
		}
		descLower := strings.ToLower(desc)
		if id != "" && (strings.Contains(descLower, entryLower) || strings.Contains(descLower, "sentryboot")) {
			if _, err := runCmd("bcdedit", "/set", "{fwbootmgr}", "bootsequence", id); err != nil {
				return err
			}
			_, err = runCmd("shutdown", "/r", "/t", "0")
			return err
		}
	}

	return fmt.Errorf("no matching boot entry")
}

func Poweroff() error {
	_, err := runCmd("shutdown", "/s", "/t", "0")
	return err
}
