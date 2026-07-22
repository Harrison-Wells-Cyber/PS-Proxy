package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/psproxy/psproxy/internal/staging"
)

func main() {
	domain := flag.String("domain", "", "public DNS name used for TLS and agent staging")
	port := flag.Int("port", 443, "TLS listener port")
	cert := flag.String("cert", "", "TLS fullchain PEM; defaults to /etc/letsencrypt/live/<domain>/fullchain.pem")
	key := flag.String("key", "", "TLS private key PEM; defaults to /etc/letsencrypt/live/<domain>/privkey.pem")
	tun := flag.String("tun", "psproxy0", "TUN interface name for the future netstack data plane")
	agentTemplate := flag.String("agent-template", "agent/loader/agent.ps1.tmpl", "PowerShell agent loader template")
	agentAssemblyFile := flag.String("agent-assembly-b64-file", "", "file containing compressed/base64 PSProxy.Agent.dll; release builds embed this")
	routes := multiFlag{}
	flag.Var(&routes, "route", "CIDR to route through the agent; repeatable")
	ttl := flag.Duration("agent-url-ttl", 10*time.Minute, "one-time agent URL lifetime")
	listen := flag.String("listen", "0.0.0.0", "listener address")
	flag.Parse()
	if *domain == "" {
		log.Fatal("--domain is required")
	}
	if len(routes) == 0 {
		log.Fatal("at least one --route is required")
	}
	if *cert == "" {
		*cert = filepath.Join("/etc/letsencrypt/live", *domain, "fullchain.pem")
	}
	if *key == "" {
		*key = filepath.Join("/etc/letsencrypt/live", *domain, "privkey.pem")
	}
	pin, err := certPin(*cert)
	if err != nil {
		log.Fatalf("certificate pin failed: %v", err)
	}
	assembly, err := loadAssemblyB64(*agentAssemblyFile)
	if err != nil {
		log.Fatalf("agent assembly load failed: %v", err)
	}
	if assembly == "__ASSEMBLY_B64__" {
		log.Printf("WARNING: agent assembly is not packaged; generated agent will instruct you to run tools/build-agent.ps1")
	}
	tmpl := template.Must(template.ParseFiles(*agentTemplate))
	store := staging.NewStore(*ttl)
	sess, err := store.Create(*domain, *port, pin)
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /a/{id}", staging.AgentHandler(store, tmpl, assembly))
	mux.HandleFunc("POST /enroll", func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-PSProxy-Enrollment")
		if token == "" {
			http.Error(w, "missing enrollment token", http.StatusUnauthorized)
			return
		}
		if err := store.Enroll(token); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("OK\n"))
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	addr := fmt.Sprintf("%s:%d", *listen, *port)
	log.Printf("PS-Proxy Go server starting on https://%s", addr)
	log.Printf("TLS certificate: %s", *cert)
	log.Printf("Agent cert pin: %s", pin)
	log.Printf("TUN target: %s routes=%s", *tun, strings.Join(routes, ","))
	log.Printf("Run this on the Windows host: irm %s/a/%s | iex", publicURL(*domain, *port), sess.ID)
	srv := &http.Server{Addr: addr, Handler: mux, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	log.Fatal(srv.ListenAndServeTLS(*cert, *key))
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func certPin(path string) (string, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("no PEM certificate found in %s", path)
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}

func publicURL(domain string, port int) string {
	if port == 443 {
		return "https://" + domain
	}
	return fmt.Sprintf("https://%s:%d", domain, port)
}

func loadAssemblyB64(path string) (string, error) {
	if path == "" {
		return "__ASSEMBLY_B64__", nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
