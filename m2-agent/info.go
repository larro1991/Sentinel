package main

import (
	"net"
	"os"
	"runtime"
)

func CollectInfo() InfoResponse {
	hostname, _ := os.Hostname()

	var ips []string
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		v4 := ipnet.IP.To4()
		if v4 == nil || v4.IsLoopback() {
			continue
		}
		ips = append(ips, v4.String())
	}

	ramGB, diskGB := platformMemDisk()

	return InfoResponse{
		Hostname: hostname,
		OS:       runtime.GOOS,
		IPs:      ips,
		CPUCount: runtime.NumCPU(),
		RAMGB:    ramGB,
		DiskGB:   diskGB,
	}
}
