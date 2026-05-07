package main

import (
	"bytes"
	"os/exec"
	"runtime"
	"strings"
)

// Characters that allow code injection or output redirection — always blocked.
var blockedChars = []string{"&", ";", ">", "<", "`", "$("}

// Commands that are always blocked regardless of arguments.
var blockedCmds = map[string]bool{
	"rm": true, "rmdir": true, "dd": true, "mkfs": true, "fdisk": true,
	"parted": true, "shred": true, "wipefs": true,
	"chmod": true, "chown": true, "chattr": true,
	"kill": true, "killall": true, "pkill": true,
	"shutdown": true, "halt": true, "init": true,
	"wget": true, "nc": true, "ncat": true, "socat": true,
	"python": true, "python3": true, "ruby": true, "perl": true,
	"sh": true, "bash": true, "zsh": true, "ash": true, "dash": true,
	"su": true, "sudo": true, "doas": true,
	"passwd": true, "useradd": true, "userdel": true, "usermod": true,
	"crontab": true, "at": true,
	"insmod": true, "rmmod": true, "modprobe": true,
}

// Commands explicitly allowed (first token of each pipe segment).
var allowedCmds = map[string]bool{
	// system info
	"echo": true, "hostname": true, "uname": true, "uptime": true, "date": true,
	"env": true, "printenv": true, "which": true, "whoami": true, "id": true,
	"free": true, "vmstat": true, "lscpu": true, "lsblk": true, "lspci": true,
	"lsusb": true, "lshw": true, "dmidecode": true,
	// disk / fs
	"df": true, "du": true, "ls": true, "find": true, "stat": true,
	"mount": true,
	// files
	"cat": true, "head": true, "tail": true, "wc": true, "tee": true,
	"diff": true, "md5sum": true, "sha256sum": true,
	// text processing
	"grep": true, "awk": true, "sed": true, "cut": true, "sort": true,
	"uniq": true, "tr": true, "xargs": true,
	// network
	"curl": true, "ip": true, "ss": true, "netstat": true, "ping": true,
	"nslookup": true, "dig": true, "traceroute": true,
	// processes
	"ps": true, "top": true, "htop": true, "pgrep": true, "pstree": true,
	// services
	"systemctl": true, "journalctl": true, "service": true,
	// docker
	"docker": true,
	// GPU
	"nvidia-smi": true,
	// ollama
	"ollama": true,
	// go
	"go": true,
	// Proxmox VM/CT/storage management
	"qm": true, "pct": true, "pvesh": true, "pvesm": true, "pveum": true, "pvecm": true,
	// file ops (non-destructive writes via tee, copies, dirs)
	"cp": true, "mkdir": true, "ln": true, "touch": true,
	// misc safe
	"zpool": true, "zfs": true, "efibootmgr": true, "qemu-img": true,
}

// splitPipe splits a command on | and returns each segment's trimmed tokens.
func splitPipe(cmd string) [][]string {
	segments := strings.Split(cmd, "|")
	out := make([][]string, 0, len(segments))
	for _, s := range segments {
		t := strings.Fields(strings.TrimSpace(s))
		if len(t) > 0 {
			out = append(out, t)
		}
	}
	return out
}

// Windows commands that are always blocked.
var blockedCmdsWindows = map[string]bool{
	"Remove-Item": true, "rmdir": true, "del": true, "rd": true,
	"Stop-Process": true, "Kill": true, "taskkill": true,
	"Stop-Service": true, "Disable-NetAdapter": true,
	"Format-Volume": true, "Clear-Disk": true, "Initialize-Disk": true,
	"Set-ExecutionPolicy": true, "Invoke-Expression": true, "iex": true,
	"Invoke-Command": true, "Enter-PSSession": true, "New-PSSession": true,
	"Add-LocalGroupMember": true, "New-LocalUser": true, "Remove-LocalUser": true,
	"Set-LocalUser": true, "net": true, "netsh": true,
	"reg": true, "regedit": true, "regedt32": true,
	"shutdown": true, "restart-computer": true,
}

// Windows commands explicitly allowed (case-insensitive first token).
var allowedCmdsWindows = map[string]bool{
	// info
	"Get-Process": true, "ps": true, "tasklist": true,
	"Get-Service": true, "Get-EventLog": true, "Get-WinEvent": true,
	"Get-ComputerInfo": true, "systeminfo": true, "hostname": true,
	"Get-Date": true, "uptime": true, "whoami": true,
	// disk / fs
	"Get-Disk": true, "Get-Volume": true, "Get-Partition": true,
	"Get-PSDrive": true, "dir": true, "ls": true, "Get-ChildItem": true,
	"Get-Item": true, "Get-Content": true, "cat": true,
	// network
	"ipconfig": true, "Get-NetIPAddress": true, "Get-NetAdapter": true,
	"Get-NetTCPConnection": true, "netstat": true, "ping": true,
	"Resolve-DnsName": true, "nslookup": true, "tracert": true,
	// docker / GPU
	"docker": true, "nvidia-smi": true,
	// misc
	"echo": true, "Write-Output": true, "Where-Object": true,
	"Select-Object": true, "Sort-Object": true, "Measure-Object": true,
	"Format-List": true, "Format-Table": true, "ConvertTo-Json": true,
	"Get-Variable": true, "Get-Command": true, "Get-Module": true,
}

func runWindows(cmd string) ShellResponse {
	reject := func(reason string) ShellResponse {
		return ShellResponse{Stderr: reason, RC: 126}
	}

	// Block shell injection characters
	blockedWin := []string{"&", ">", "<", "`", "$(", ";"}
	for _, ch := range blockedWin {
		if strings.Contains(cmd, ch) {
			return reject("blocked: contains " + ch)
		}
	}

	// Extract first token (command name) for allowlist check — pipes allowed
	first := strings.Fields(strings.TrimSpace(strings.SplitN(cmd, "|", 2)[0]))[0]
	firstLower := strings.ToLower(first)

	// Check block list (case-insensitive)
	for k := range blockedCmdsWindows {
		if strings.ToLower(k) == firstLower {
			return reject("blocked command: " + first)
		}
	}

	// Check allow list (case-insensitive)
	allowed := false
	for k := range allowedCmdsWindows {
		if strings.ToLower(k) == firstLower {
			allowed = true
			break
		}
	}
	if !allowed {
		return reject("command not in allowlist: " + first)
	}

	var stdout, stderr bytes.Buffer
	c := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", cmd)
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

func RunShell(cmd string) ShellResponse {
	if runtime.GOOS == "windows" {
		return runWindows(cmd)
	}

	reject := func(reason string) ShellResponse {
		return ShellResponse{Stderr: reason, RC: 126}
	}

	// Block injection characters (but not |)
	for _, ch := range blockedChars {
		if strings.Contains(cmd, ch) {
			return reject("blocked: contains " + ch)
		}
	}

	// Check every pipe segment's leading command
	segments := splitPipe(cmd)
	if len(segments) == 0 {
		return reject("empty command")
	}

	for _, seg := range segments {
		first := seg[0]
		if blockedCmds[first] {
			return reject("blocked command: " + first)
		}
		if !allowedCmds[first] {
			return reject("command not in allowlist: " + first)
		}
	}

	// Execute via sh -c to handle pipes correctly
	var stdout, stderr bytes.Buffer
	c := exec.Command("sh", "-c", cmd)
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
