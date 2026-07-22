package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
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
	"text/template"
	"time"

	"github.com/psproxy/psproxy/internal/protocol"
	"github.com/psproxy/psproxy/internal/staging"
)

func main() {
	domain := flag.String("domain", "", "public DNS name used for TLS and agent staging")
	port := flag.Int("port", 443, "TLS listener port")
	cert := flag.String("cert", "", "TLS fullchain PEM; defaults to /etc/letsencrypt/live/<domain>/fullchain.pem")
	key := flag.String("key", "", "TLS private key PEM; defaults to /etc/letsencrypt/live/<domain>/privkey.pem")
	identityKeyPath := flag.String("identity-key", "psproxy_identity.pem", "stable RSA identity private key PEM for PS-Proxy application-layer tunnel trust")
	tun := flag.String("tun", "psproxy0", "TUN interface name for the planned netstack data plane")
	agentTemplate := flag.String("agent-template", "agent/loader/agent.ps1.tmpl", "PowerShell agent loader template")
	agentAssemblyFile := flag.String("agent-assembly-b64-file", "", "file containing compressed/base64 PSProxy.Agent.dll; defaults to release/agent_assembly.b64 when present")
	redirect := flag.Bool("redirect", false, "install Linux iptables REDIRECT rules for --route CIDRs and relay original destinations through the agent")
	redirectPort := flag.Int("redirect-port", 15080, "local transparent redirect listener port")
	maxStreams := flag.Int("max-streams", 256, "maximum concurrent proxied TCP streams")
	dnsListen := flag.String("dns-listen", "", "optional UDP DNS listener that forwards queries through the agent, e.g. 127.0.0.1:5353")
	dnsTarget := flag.String("dns-target", "", "DNS server reachable by the agent for --dns-listen queries, e.g. 10.10.10.10:53")
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
	if (*dnsListen == "") != (*dnsTarget == "") {
		log.Fatal("--dns-listen and --dns-target must be supplied together")
	}
	if *redirect && len(routes) == 0 {
		log.Fatal("--redirect requires at least one --route CIDR")
	}
	if err := validateRoutes(routes); err != nil {
		log.Fatal(err)
	}
	identityKey, err := loadOrCreateIdentityKey(*identityKeyPath)
	if err != nil {
		log.Fatalf("identity key load failed: %v", err)
	}
	serverKey, identityPin, err := publicKeyStaging(identityKey)
	if err != nil {
		log.Fatalf("identity public key encode failed: %v", err)
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
	sess, err := store.Create(*domain, *port, serverKey, *dnsTarget)
	if err != nil {
		log.Fatal(err)
	}
	server := NewTunnelServer(store, *maxStreams)
	server.identityKey = identityKey
	mux := http.NewServeMux()
	mux.HandleFunc("GET /a/{id}", staging.AgentHandler(store, tmpl, assembly))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /status", statusHandler(server))
	var redirectCleanup func()
	if *redirect {
		redirectCleanup = setupRedirectOrFatal(routes, *redirectPort)
		defer redirectCleanup()
		go serveTransparentRelay(fmt.Sprintf("127.0.0.1:%d", *redirectPort), server)
	}
	if *tcpListen != "" {
		go serveTCPRelay(*tcpListen, *tcpTarget, server)
	}
	if *dnsListen != "" {
		go serveDNSRelay(*dnsListen, server)
	}
	installSignalCleanup(redirectCleanup)
	addr := fmt.Sprintf("%s:%d", *listen, *port)
	log.Printf("PS-Proxy Go server starting on https://%s", addr)
	log.Printf("TLS certificate: %s", *cert)
	log.Printf("PS-Proxy identity key: %s", *identityKeyPath)
	log.Printf("PS-Proxy identity public key pin: %s", identityPin)
	log.Printf("Planned TUN target: %s routes=%s", *tun, strings.Join(routes, ","))
	if *redirect {
		log.Printf("Transparent redirect mode enabled on 127.0.0.1:%d", *redirectPort)
	}
	if *tcpListen != "" {
		log.Printf("Developer TCP relay: %s -> agent -> %s", *tcpListen, *tcpTarget)
	}
	if *dnsListen != "" {
		log.Printf("DNS relay: %s -> agent -> %s", *dnsListen, *dnsTarget)
	}
	log.Printf("Run this on the Windows host: irm %s/a/%s | iex", publicURL(*domain, *port), sess.ID)
	log.Fatal(serveMixedTLS(addr, *cert, *key, mux, server))
}

type TunnelServer struct {
	store       *staging.Store
	identityKey *rsa.PrivateKey
	mu          sync.Mutex
	session     *AgentSession
	nextID      atomic.Uint64
	dnsID       atomic.Uint64
	maxStreams  int
}

func NewTunnelServer(store *staging.Store, maxStreams int) *TunnelServer {
	if maxStreams < 1 {
		maxStreams = 1
	}
	return &TunnelServer{store: store, maxStreams: maxStreams}
}

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

func (s *TunnelServer) ClearSession(a *AgentSession) {
	s.mu.Lock()
	if s.session == a {
		s.session = nil
	}
	s.mu.Unlock()
}

func (s *TunnelServer) OpenAttached(target string, local net.Conn) (*AgentSession, uint64, error) {
	a := s.Current()
	if a == nil {
		return nil, 0, errors.New("no enrolled agent connected")
	}
	id := s.nextID.Add(1)
	if err := a.AttachLocal(id, local); err != nil {
		return nil, 0, err
	}
	if err := a.Open(id, target); err != nil {
		a.RemoveLocal(id)
		return nil, 0, err
	}
	return a, id, nil
}

type AgentSession struct {
	conn       net.Conn
	br         *bufio.Reader
	sendMu     sync.Mutex
	closeOnce  sync.Once
	closed     chan struct{}
	mu         sync.Mutex
	pending    map[uint64]chan error
	dnsPending map[uint64]chan []byte
	locals     map[uint64]*localStream
	maxStreams int
	codec      protocol.Codec
}

func NewAgentSession(c net.Conn, br *bufio.Reader, maxStreams int) *AgentSession {
	if maxStreams < 1 {
		maxStreams = 1
	}
	return &AgentSession{conn: c, br: br, codec: protocol.NewPlainCodec(br, c), closed: make(chan struct{}), pending: map[uint64]chan error{}, dnsPending: map[uint64]chan []byte{}, locals: map[uint64]*localStream{}, maxStreams: maxStreams}
}

func (a *AgentSession) Close() {
	a.closeOnce.Do(func() {
		close(a.closed)
		_ = a.conn.Close()
		a.mu.Lock()
		for id, ch := range a.pending {
			delete(a.pending, id)
			ch <- errors.New("agent session closed")
		}
		for id, ch := range a.dnsPending {
			delete(a.dnsPending, id)
			close(ch)
		}
		for id, ls := range a.locals {
			delete(a.locals, id)
			ls.close()
		}
		a.mu.Unlock()
	})
}

func (a *AgentSession) send(f protocol.Frame) error {
	a.sendMu.Lock()
	defer a.sendMu.Unlock()
	return a.codec.WriteFrame(f)
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

func (a *AgentSession) AttachLocal(id uint64, c net.Conn) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	select {
	case <-a.closed:
		return errors.New("agent session closed")
	default:
	}
	if len(a.locals) >= a.maxStreams {
		return fmt.Errorf("maximum concurrent streams reached: %d", a.maxStreams)
	}
	a.locals[id] = newLocalStream(c)
	return nil
}

func (a *AgentSession) RemoveLocal(id uint64) {
	a.mu.Lock()
	ls := a.locals[id]
	delete(a.locals, id)
	a.mu.Unlock()
	if ls != nil {
		ls.close()
	}
}

func (a *AgentSession) Run() {
	defer a.Close()
	for {
		f, err := a.codec.ReadFrame()
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
			ls := a.locals[f.StreamID]
			a.mu.Unlock()
			if ls != nil && !ls.enqueue(f.Payload) {
				a.RemoveLocal(f.StreamID)
				_ = a.send(protocol.Frame{StreamID: f.StreamID, Type: protocol.FrameClose})
			}
		case protocol.FrameClose:
			a.RemoveLocal(f.StreamID)
		case protocol.FrameDNSReply:
			a.mu.Lock()
			ch := a.dnsPending[f.StreamID]
			delete(a.dnsPending, f.StreamID)
			a.mu.Unlock()
			if ch != nil {
				ch <- f.Payload
			}
		case protocol.FramePing:
			_ = a.send(protocol.Frame{StreamID: f.StreamID, Type: protocol.FramePong})
		}
	}
}

type localStream struct {
	conn net.Conn
	ch   chan []byte
	done chan struct{}
	once sync.Once
}

func newLocalStream(c net.Conn) *localStream {
	ls := &localStream{conn: c, ch: make(chan []byte, 32), done: make(chan struct{})}
	go ls.writeLoop()
	return ls
}

func (l *localStream) enqueue(payload []byte) bool {
	buf := append([]byte(nil), payload...)
	select {
	case l.ch <- buf:
		return true
	case <-l.done:
		return false
	default:
		return false
	}
}

func (l *localStream) writeLoop() {
	defer l.close()
	for {
		select {
		case payload := <-l.ch:
			if _, err := l.conn.Write(payload); err != nil {
				return
			}
		case <-l.done:
			return
		}
	}
}

func (l *localStream) close() {
	l.once.Do(func() {
		close(l.done)
		_ = l.conn.Close()
	})
}

func (s *TunnelServer) Status() map[string]any {
	a := s.Current()
	status := map[string]any{"agent_connected": a != nil, "max_streams": s.maxStreams}
	if a != nil {
		a.mu.Lock()
		status["active_streams"] = len(a.locals)
		status["pending_opens"] = len(a.pending)
		status["pending_dns"] = len(a.dnsPending)
		a.mu.Unlock()
	}
	return status
}

func (s *TunnelServer) QueryDNS(query []byte) ([]byte, error) {
	a := s.Current()
	if a == nil {
		return nil, errors.New("no enrolled agent connected")
	}
	id := s.dnsID.Add(1)
	ch := make(chan []byte, 1)
	a.mu.Lock()
	select {
	case <-a.closed:
		a.mu.Unlock()
		return nil, errors.New("agent session closed")
	default:
	}
	a.dnsPending[id] = ch
	a.mu.Unlock()
	if err := a.send(protocol.Frame{StreamID: id, Type: protocol.FrameDNSQuery, Payload: query}); err != nil {
		a.mu.Lock()
		delete(a.dnsPending, id)
		a.mu.Unlock()
		return nil, err
	}
	select {
	case resp, ok := <-ch:
		if !ok {
			return nil, errors.New("agent session closed")
		}
		if len(resp) == 0 {
			return nil, errors.New("empty DNS response from agent")
		}
		return resp, nil
	case <-time.After(5 * time.Second):
		a.mu.Lock()
		delete(a.dnsPending, id)
		a.mu.Unlock()
		return nil, errors.New("timeout waiting for DNS response")
	}
}

func statusHandler(server *TunnelServer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(server.Status())
	}
}

func serveDNSRelay(listenAddr string, server *TunnelServer) {
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		log.Fatalf("dns relay resolve failed: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("dns relay listen failed: %v", err)
	}
	log.Printf("dns relay listening on udp://%s", listenAddr)
	buf := make([]byte, 4096)
	for {
		n, client, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("dns relay read failed: %v", err)
			continue
		}
		query := append([]byte(nil), buf[:n]...)
		go func() {
			resp, err := server.QueryDNS(query)
			if err != nil {
				log.Printf("dns relay query failed: %v", err)
				return
			}
			_, _ = conn.WriteToUDP(resp, client)
		}()
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

func validateRoutes(routes []string) error {
	for _, route := range routes {
		if _, _, err := net.ParseCIDR(route); err != nil {
			return fmt.Errorf("invalid --route CIDR %q: %w", route, err)
		}
	}
	return nil
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
	codec := protocol.Codec(protocol.NewPlainCodec(br, conn))
	if server.identityKey != nil {
		secure, err := serverHandshake(conn, br, server.identityKey)
		if err != nil {
			log.Printf("agent secure handshake failed: %v", err)
			_ = conn.Close()
			return
		}
		codec = secure
	}
	f, err := codec.ReadFrame()
	if err != nil || f.Type != protocol.FramePing {
		_ = conn.Close()
		return
	}
	fields := strings.Fields(string(f.Payload))
	if len(fields) == 0 || fields[0] != "ENROLL" || len(fields) < 2 {
		_ = conn.Close()
		return
	}
	enrollToken := fields[1]
	reconnectToken := ""
	if len(fields) > 2 {
		reconnectToken = fields[2]
	}
	if err := server.store.Authenticate(enrollToken, reconnectToken); err != nil {
		log.Printf("agent enrollment failed: %v", err)
		_ = conn.Close()
		return
	}
	a := NewAgentSession(conn, br, server.maxStreams)
	a.codec = codec
	server.SetSession(a)
	log.Printf("agent enrolled and connected from %s", conn.RemoteAddr())
	_ = a.send(protocol.Frame{Type: protocol.FramePong, Payload: []byte("OK")})
	a.Run()
	server.ClearSession(a)
}

func serverHandshake(conn net.Conn, br *bufio.Reader, key *rsa.PrivateKey) (*protocol.SecureCodec, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) != 3 || parts[0] != "HELLO" {
		return nil, errors.New("expected HELLO")
	}
	encSecret, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	clientNonce, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	if len(clientNonce) != 32 {
		return nil, errors.New("invalid client nonce")
	}
	secret, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, encSecret, []byte("PS-Proxy PSP1 session"))
	if err != nil {
		return nil, err
	}
	if len(secret) != 32 {
		return nil, errors.New("invalid session secret")
	}
	serverNonce := make([]byte, 32)
	if _, err := rand.Read(serverNonce); err != nil {
		return nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(protocol.Magic))
	mac.Write([]byte(line))
	mac.Write(serverNonce)
	mac.Write(clientNonce)
	mac.Write(pubDER)
	proof := mac.Sum(nil)
	resp := "PROOF " + base64.RawURLEncoding.EncodeToString(serverNonce) + " " + base64.RawURLEncoding.EncodeToString(proof) + "\n"
	if _, err := io.WriteString(conn, resp); err != nil {
		return nil, err
	}
	return protocol.NewSecureCodec(br, conn, secret)
}

type singleListener struct {
	conn net.Conn
	done chan struct{}
	once sync.Once
}

func (s *singleListener) Accept() (net.Conn, error) {
	if s.conn == nil {
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

func loadOrCreateIdentityKey(path string) (*rsa.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, fmt.Errorf("no PEM block in %s", path)
		}
		if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return k, nil
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		k, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("identity key is not RSA")
		}
		return k, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	k, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, err
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	if err := os.WriteFile(path, b, 0600); err != nil {
		return nil, err
	}
	return k, nil
}

func publicKeyStaging(k *rsa.PrivateKey) (string, string, error) {
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(der)
	return base64.StdEncoding.EncodeToString(der), hex.EncodeToString(sum[:]), nil
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
