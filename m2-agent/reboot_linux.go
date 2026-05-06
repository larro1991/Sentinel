//go:build linux

package main

import (
	"fmt"
	"regexp"
	"strings"
)

var bootEntryRe = regexp.MustCompile(`^Boot([0-9A-F]{4})\* (.+)$`)

func SetNextBootAndReboot(entry string) error {
	if entry == "" {
		// Plain reboot — no EFI BootNext manipulation.
		_, err := runCmd("sudo", "/sbin/reboot")
		return err
	}

	out, err := runCmd("sudo", "/usr/sbin/efibootmgr", "-v")
	if err != nil {
		return err
	}

	entryLower := strings.ToLower(entry)
	for _, line := range strings.Split(out, "\n") {
		m := bootEntryRe.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if m == nil {
			continue
		}
		bootnum, label := m[1], m[2]
		labelLower := strings.ToLower(label)
		if strings.Contains(labelLower, entryLower) || strings.Contains(labelLower, "sentryboot") {
			if _, err := runCmd("sudo", "/usr/sbin/efibootmgr", "-n", bootnum); err != nil {
				return err
			}
			_, err = runCmd("sudo", "/sbin/reboot")
			return err
		}
	}

	return fmt.Errorf("no matching boot entry for %q", entry)
}

func Poweroff() error {
	_, err := runCmd("sudo", "/sbin/poweroff")
	return err
}
