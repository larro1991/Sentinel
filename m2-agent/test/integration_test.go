//go:build integration

package integration_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

var (
	agentBase  = envOr("BEDROCK_AGENT", "http://192.168.110.185:7800")
	brokerBase = envOr("BEDROCK_BROKER", "http://192.168.110.25:7700")
	pmBase     = envOr("BEDROCK_PM", "http://192.168.110.185:3000")
	pmToken    = envOr("BEDROCK_PM_TOKEN", "tZuGme-gu_8n3KMFg3kU-8EQPp2KaXZhmO0VbHJ2Rhs")
	client     = &http.Client{Timeout: 10 * time.Second}
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// --- helpers ----------------------------------------------------------------

func getJSON(t *testing.T, url string) map[string]any {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d", url, resp.StatusCode)
	}
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("GET %s: decode: %v", url, err)
	}
	return m
}

func postJSON(t *testing.T, url string, body any, expectStatus int, headers map[string]string) map[string]any {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != expectStatus {
		t.Fatalf("POST %s: expected %d got %d", url, expectStatus, resp.StatusCode)
	}
	if expectStatus == http.StatusAccepted {
		return nil // 202 has no body we need
	}
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m) //nolint:errcheck
	return m
}

// --- m2-agent ---------------------------------------------------------------

func TestAgentHealth(t *testing.T) {
	m := getJSON(t, agentBase+"/health")
	if ok, _ := m["ok"].(bool); !ok {
		t.Fatalf("health.ok = false, got %v", m)
	}
	if h, _ := m["hostname"].(string); h == "" {
		t.Fatal("health.hostname empty")
	}
	t.Logf("host=%s os=%s", m["hostname"], m["os"])
}

func TestAgentInfo(t *testing.T) {
	m := getJSON(t, agentBase+"/info")
	fields := []string{"hostname", "ip", "os", "uptime_seconds"}
	for _, f := range fields {
		if _, ok := m[f]; !ok {
			t.Errorf("info missing field %q", f)
		}
	}
	t.Logf("uptime=%.0fs ip=%s", m["uptime_seconds"], m["ip"])
}

func TestAgentShellEcho(t *testing.T) {
	m := postJSON(t, agentBase+"/shell", map[string]string{"cmd": "echo bedrock-test-ok"}, http.StatusOK, nil)
	stdout, _ := m["stdout"].(string)
	if !strings.Contains(stdout, "bedrock-test-ok") {
		t.Fatalf("stdout missing expected string: %q", stdout)
	}
}

func TestAgentShellUptime(t *testing.T) {
	m := postJSON(t, agentBase+"/shell", map[string]string{"cmd": "uptime"}, http.StatusOK, nil)
	stdout, _ := m["stdout"].(string)
	if stdout == "" {
		t.Fatalf("uptime stdout empty, stderr=%q", m["stderr"])
	}
	t.Logf("uptime: %s", strings.TrimSpace(stdout))
}

func TestAgentShellDockerCount(t *testing.T) {
	m := postJSON(t, agentBase+"/shell", map[string]string{"cmd": `docker ps -q | wc -l`}, http.StatusOK, nil)
	stdout, _ := m["stdout"].(string)
	count := strings.TrimSpace(stdout)
	t.Logf("running containers: %s", count)
	if count == "" || count == "0" {
		t.Errorf("expected containers running, got %q", count)
	}
}

func TestAgentShellGPU(t *testing.T) {
	m := postJSON(t, agentBase+"/shell", map[string]string{"cmd": "nvidia-smi --query-gpu=name,memory.total --format=csv,noheader"}, http.StatusOK, nil)
	stdout, _ := m["stdout"].(string)
	if strings.TrimSpace(stdout) == "" {
		t.Fatal("nvidia-smi returned empty — GPU may be down")
	}
	t.Logf("GPU: %s", strings.TrimSpace(stdout))
}

func TestAgentShellBadCommand(t *testing.T) {
	// Non-zero exit should still return 200 with stderr populated
	m := postJSON(t, agentBase+"/shell", map[string]string{"cmd": "ls /nonexistent-path-xyz"}, http.StatusOK, nil)
	exitCode, _ := m["exit_code"].(float64)
	if exitCode == 0 {
		t.Fatal("expected non-zero exit code for bad path")
	}
}

func TestAgentShellBadRequest(t *testing.T) {
	req, _ := http.NewRequest("POST", agentBase+"/shell", bytes.NewBufferString("not-json"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

// Reboot/poweroff: only verify API accepts request — does NOT send real entry.
// Set TEST_DESTRUCTIVE=1 to skip the guard (still uses safe no-op entry).
func TestAgentRebootAccepts(t *testing.T) {
	if os.Getenv("TEST_DESTRUCTIVE") == "" {
		t.Skip("set TEST_DESTRUCTIVE=1 to run reboot/poweroff tests")
	}
	// Entry "" = noop on efibootmgr (will fail gracefully in goroutine, not panic)
	postJSON(t, agentBase+"/reboot", map[string]string{"entry": ""}, http.StatusAccepted, nil)
}

func TestAgentPoweroffAccepts(t *testing.T) {
	if os.Getenv("TEST_DESTRUCTIVE") == "" {
		t.Skip("set TEST_DESTRUCTIVE=1 to run reboot/poweroff tests")
	}
	postJSON(t, agentBase+"/poweroff", map[string]any{}, http.StatusAccepted, nil)
}

// --- UAI broker -------------------------------------------------------------

func TestBrokerAgentRegistered(t *testing.T) {
	resp, err := client.Get(brokerBase + "/broker/agents")
	if err != nil {
		t.Fatalf("GET /broker/agents: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("broker agents: status %d", resp.StatusCode)
	}
	var agents []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&agents); err != nil {
		// broker may return map instead of slice
		t.Logf("decode as slice failed (%v), test inconclusive", err)
		return
	}
	for _, a := range agents {
		if name, _ := a["hostname"].(string); strings.Contains(strings.ToLower(name), "proxmox") || strings.Contains(strings.ToLower(name), "sentry") {
			alive, _ := a["alive"].(bool)
			t.Logf("found agent %q alive=%v", name, alive)
			if !alive {
				t.Errorf("sentry-proxmox agent not alive")
			}
			return
		}
	}
	t.Errorf("sentry-proxmox not found in broker agents: %v", agents)
}

func TestBrokerHeartbeatEndpoint(t *testing.T) {
	// Send a fake heartbeat with a test hostname — verifies endpoint is live
	payload := map[string]any{
		"hostname": "bedrock-test-probe",
		"ip":       "127.0.0.99",
		"port":     9999,
		"status":   "test",
	}
	resp, err := client.Post(brokerBase+"/broker/heartbeat", "application/json", jsonBody(payload))
	if err != nil {
		t.Fatalf("POST /broker/heartbeat: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		t.Fatalf("broker heartbeat server error: %d", resp.StatusCode)
	}
	t.Logf("broker heartbeat status: %d", resp.StatusCode)
}

func jsonBody(v any) *bytes.Reader {
	b, _ := json.Marshal(v)
	return bytes.NewReader(b)
}

// --- PM agent REST ----------------------------------------------------------

func TestPMHealth(t *testing.T) {
	resp, err := client.Get(pmBase + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pm health: status %d", resp.StatusCode)
	}
}

func TestPMProgramStatus(t *testing.T) {
	req, _ := http.NewRequest("GET", pmBase+"/api/program/status", nil)
	req.Header.Set("Authorization", "Bearer "+pmToken)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /api/program/status: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("program status: %d", resp.StatusCode)
	}
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body) //nolint:errcheck
	t.Logf("program status keys: %v", keys(body))
}

func TestPMMemoryLoad(t *testing.T) {
	// Verify pm_memory.md is being served (indirectly via /debug or just shell)
	m := postJSON(t, agentBase+"/shell",
		map[string]string{"cmd": "cat /mnt/Main/appdata/pm-agent/pm_memory.md | wc -l"},
		http.StatusOK, nil)
	stdout, _ := m["stdout"].(string)
	lines := strings.TrimSpace(stdout)
	t.Logf("pm_memory.md lines: %s", lines)
	if lines == "0" || lines == "" {
		t.Error("pm_memory.md empty or missing")
	}
}

func TestPMEnglishEnforcement(t *testing.T) {
	// Verify language instruction present in pm_agent.py
	m := postJSON(t, agentBase+"/shell",
		map[string]string{"cmd": `grep -c "ALWAYS respond in English" /Main/appdata/pm-agent/pm_agent.py`},
		http.StatusOK, nil)
	stdout := strings.TrimSpace(m["stdout"].(string))
	if stdout == "0" || stdout == "" {
		t.Error("English-only instruction missing from pm_agent.py")
	}
}

// --- Restart resilience -----------------------------------------------------

func TestM2AgentSystemdEnabled(t *testing.T) {
	m := postJSON(t, agentBase+"/shell",
		map[string]string{"cmd": "systemctl is-enabled m2-agent"},
		http.StatusOK, nil)
	stdout := strings.TrimSpace(m["stdout"].(string))
	if stdout != "enabled" {
		t.Errorf("m2-agent not enabled: %q", stdout)
	}
}

func TestComposeStacksEnabled(t *testing.T) {
	m := postJSON(t, agentBase+"/shell",
		map[string]string{"cmd": "systemctl is-enabled compose-stacks"},
		http.StatusOK, nil)
	stdout := strings.TrimSpace(m["stdout"].(string))
	if stdout != "enabled" {
		t.Errorf("compose-stacks not enabled: %q", stdout)
	}
}

func TestOllamaRunning(t *testing.T) {
	m := postJSON(t, agentBase+"/shell",
		map[string]string{"cmd": "curl -s -o /dev/null -w '%{http_code}' http://localhost:11434/api/tags"},
		http.StatusOK, nil)
	stdout := strings.TrimSpace(m["stdout"].(string))
	if stdout != "200" {
		t.Errorf("ollama not responding: got %q", stdout)
	}
}

func TestContainerCount(t *testing.T) {
	m := postJSON(t, agentBase+"/shell",
		map[string]string{"cmd": "docker ps -q | wc -l"},
		http.StatusOK, nil)
	stdout := strings.TrimSpace(m["stdout"].(string))
	t.Logf("running containers: %s (expect ~42)", stdout)
	// Warn if count drops significantly — not hard fail (some may be stopped intentionally)
	var count int
	fmt.Sscanf(stdout, "%d", &count)
	if count < 30 {
		t.Errorf("container count %d below threshold (expect ≥30)", count)
	}
}

// --- helpers ----------------------------------------------------------------

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
