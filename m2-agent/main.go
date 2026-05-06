package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

func firstNonLoopbackIPv4() string {
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		v4 := ipnet.IP.To4()
		if v4 != nil && !v4.IsLoopback() {
			return v4.String()
		}
	}
	return "127.0.0.1"
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	hostname, _ := os.Hostname()
	writeJSON(w, http.StatusOK, HealthResponse{OK: true, Hostname: hostname, OS: runtime.GOOS})
}

func handleInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, CollectInfo())
}

func handleShell(w http.ResponseWriter, r *http.Request) {
	var req ShellRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, RunShell(req.Cmd))
}

func handleReboot(w http.ResponseWriter, r *http.Request) {
	var req RebootRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusAccepted)
	go func() {
		time.Sleep(1 * time.Second)
		if err := SetNextBootAndReboot(req.Entry); err != nil {
			log.Printf("reboot error: %v", err)
		}
	}()
}

func handlePoweroff(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusAccepted)
	go func() {
		time.Sleep(1 * time.Second)
		if err := Poweroff(); err != nil {
			log.Printf("poweroff error: %v", err)
		}
	}()
}

func runHeartbeat(brokerURL string, port int) {
	client := &http.Client{Timeout: 5 * time.Second}
	send := func() {
		hostname, _ := os.Hostname()
		payload := HeartbeatPayload{
			Hostname: hostname,
			IP:       firstNonLoopbackIPv4(),
			Port:     port,
			Status:   "alive",
		}
		body, _ := json.Marshal(payload)
		resp, err := client.Post(brokerURL, "application/json", bytes.NewReader(body))
		if err != nil {
			log.Printf("heartbeat error: %v", err)
			return
		}
		resp.Body.Close()
	}

	// Fire immediately so errors appear quickly, then every 30s.
	send()
	for range time.Tick(30 * time.Second) {
		send()
	}
}

func main() {
	port := "7800"
	if p := os.Getenv("M2_AGENT_PORT"); p != "" {
		port = p
	}
	brokerURL := "http://192.168.110.25:7700/broker/heartbeat"
	if b := os.Getenv("M2_BROKER_URL"); b != "" {
		brokerURL = b
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", handleHealth)
	mux.HandleFunc("GET /info", handleInfo)
	mux.HandleFunc("POST /shell", handleShell)
	mux.HandleFunc("POST /reboot", handleReboot)
	mux.HandleFunc("POST /poweroff", handlePoweroff)

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go runHeartbeat(brokerURL, 7800)

	go func() {
		log.Printf("m2-agent listening on :%s", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	<-ctx.Done()
	log.Printf("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
}
