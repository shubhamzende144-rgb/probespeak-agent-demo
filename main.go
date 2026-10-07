package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const listenHost = "127.0.0.1"
const listenPort = "8765"

var allowed = map[string]bool{
	"VERIFY_DNS": true, "FIX_DNS": true, "RESTORE_DNS": true, "VERIFY_GATEWAY": true,
	"RENEW_DHCP": true, "RECONNECT_NETWORK": true, "VERIFY_PACKET_LOSS": true, "RETEST": true,
}

type backup struct {
	Service string   `json:"service"`
	Servers []string `json:"servers"`
}

func main() {
	exe, _ := os.Executable()
	_ = installBackground(exe)
	mux := http.NewServeMux()
	mux.HandleFunc("/health", health)
	mux.HandleFunc("/verify", verify)
	mux.HandleFunc("/fix/dns", fixDNS)
	mux.HandleFunc("/restore", restore)
	mux.HandleFunc("/retest", verify)
	fmt.Printf("ProbeSpeak demo agent on http://%s:%s\n", listenHost, listenPort)
	if err := (&http.Server{Addr: listenHost + ":" + listenPort, Handler: cors(mux)}).ListenAndServe(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func installBackground(exe string) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, "Library", "Application Support", "ProbeSpeak")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	dest := filepath.Join(dir, "ProbeSpeakAgent")
	if exe != dest {
		if raw, err := os.ReadFile(exe); err == nil {
			_ = os.WriteFile(dest, raw, 0o755)
		}
	}
	plistDir := filepath.Join(home, "Library", "LaunchAgents")
	_ = os.MkdirAll(plistDir, 0o755)
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>in.probespeak.agent</string>
<key>ProgramArguments</key><array><string>%s</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
</dict></plist>`, dest)
	return os.WriteFile(filepath.Join(plistDir, "in.probespeak.agent.plist"), []byte(plist), 0o644)
}

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); strings.HasPrefix(origin, "http://") || strings.HasPrefix(origin, "https://") {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Private-Network", "true")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func health(w http.ResponseWriter, r *http.Request) {
	send(w, 200, map[string]any{"ok": true, "host": listenHost, "port": 8765, "build": "development-demo"})
}

func verify(w http.ResponseWriter, r *http.Request) {
	body := bodyOf(r)
	if reject(w, body) {
		return
	}
	ok, errText := lookup()
	send(w, 200, map[string]any{"ok": true, "action": action(body), "confirmed": !ok, "dns": map[string]any{"ok": ok, "error": errText}})
}

func fixDNS(w http.ResponseWriter, r *http.Request) {
	body := bodyOf(r)
	if reject(w, body) {
		return
	}
	if body["permission"] != true {
		send(w, 403, map[string]any{"ok": false, "error": "user permission required"})
		return
	}
	before, _ := lookup()
	if before {
		send(w, 200, map[string]any{"ok": true, "verified": false, "status": "not_confirmed", "error": "Agent verification failed. No repair performed."})
		return
	}
	if runtime.GOOS != "darwin" {
		send(w, 200, map[string]any{"ok": false, "verified": false, "status": "unresolved", "error": "DNS change runs on the Mac demo app only. No settings were changed."})
		return
	}
	service := activeService()
	prev := currentDNS(service)
	_ = save(backup{Service: service, Servers: prev})
	if err := setDNS(service, []string{"1.1.1.1", "1.0.0.1"}); err != nil {
		send(w, 200, map[string]any{"ok": false, "verified": false, "error": err.Error(), "rollback": "not_needed"})
		return
	}
	_ = exec.Command("dscacheutil", "-flushcache").Run()
	_ = exec.Command("killall", "-HUP", "mDNSResponder").Run()
	after, _ := lookup()
	if !after {
		_ = setDNS(service, prev)
		send(w, 200, map[string]any{"ok": false, "verified": false, "status": "unresolved", "error": "Recovery failed verification. Previous DNS restored."})
		return
	}
	send(w, 200, map[string]any{"ok": true, "verified": true, "status": "resolved", "action": "FIX_DNS", "before": map[string]string{"dns": "failed"}, "after": map[string]string{"dns": "passed"}, "rollback_available": true})
}

func restore(w http.ResponseWriter, r *http.Request) {
	body := bodyOf(r)
	if reject(w, body) {
		return
	}
	state, err := load()
	if err != nil {
		send(w, 200, map[string]any{"ok": false, "detail": "No saved DNS configuration."})
		return
	}
	if err := setDNS(state.Service, state.Servers); err != nil {
		send(w, 200, map[string]any{"ok": false, "detail": err.Error()})
		return
	}
	send(w, 200, map[string]any{"ok": true, "detail": "Previous DNS restored."})
}

func reject(w http.ResponseWriter, body map[string]any) bool {
	if body["command"] != nil || body["shell"] != nil {
		send(w, 400, map[string]any{"ok": false, "error": "arbitrary commands are rejected"})
		return true
	}
	if action(body) != "" && !allowed[action(body)] {
		send(w, 400, map[string]any{"ok": false, "error": "action not allowlisted"})
		return true
	}
	return false
}

func action(body map[string]any) string {
	value, _ := body["action"].(string)
	return value
}

func bodyOf(r *http.Request) map[string]any {
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body == nil {
		body = map[string]any{}
	}
	return body
}

func lookup() (bool, string) {
	done := make(chan error, 1)
	go func() {
		_, err := net.LookupHost("one.one.one.one")
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			return false, err.Error()
		}
		return true, ""
	case <-time.After(4 * time.Second):
		return false, "timeout"
	}
}

func activeService() string {
	out, err := exec.Command("networksetup", "-listnetworkserviceorder").Output()
	if err != nil {
		return "Wi-Fi"
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "(") && strings.Contains(line, "Device:") && !strings.Contains(strings.ToLower(line), "asterisk") {
			parts := strings.SplitN(line, ") ", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(strings.Split(parts[1], ",")[0])
			}
		}
	}
	return "Wi-Fi"
}

func currentDNS(service string) []string {
	out, err := exec.Command("networksetup", "-getdnsservers", service).Output()
	if err != nil {
		return nil
	}
	var servers []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "aren't any") {
			continue
		}
		servers = append(servers, line)
	}
	return servers
}

func setDNS(service string, servers []string) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("DNS change is macOS only")
	}
	args := []string{"-setdnsservers", service}
	if len(servers) == 0 {
		args = append(args, "Empty")
	} else {
		args = append(args, servers...)
	}
	return exec.Command("networksetup", args...).Run()
}

func backupPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "Application Support", "ProbeSpeak", "dns-backup.json")
}

func save(state backup) error {
	_ = os.MkdirAll(filepath.Dir(backupPath()), 0o755)
	raw, _ := json.Marshal(state)
	return os.WriteFile(backupPath(), raw, 0o600)
}

func load() (backup, error) {
	raw, err := os.ReadFile(backupPath())
	if err != nil {
		return backup{}, err
	}
	var state backup
	return state, json.Unmarshal(raw, &state)
}

func send(w http.ResponseWriter, code int, payload map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}
