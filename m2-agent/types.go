package main

type HealthResponse struct {
	OK       bool   `json:"ok"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
}

type InfoResponse struct {
	Hostname string   `json:"hostname"`
	OS       string   `json:"os"`
	IPs      []string `json:"ips"`
	DiskGB   uint64   `json:"disk_gb"`
	RAMGB    uint64   `json:"ram_gb"`
	CPUCount int      `json:"cpu_count"`
}

type ShellRequest struct {
	Cmd string `json:"cmd"`
}

type ShellResponse struct {
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
	RC     int    `json:"rc"`
}

type RebootRequest struct {
	Entry string `json:"entry"`
}

type HeartbeatPayload struct {
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Status   string `json:"status"`
}
