package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/psproxy/psproxy/internal/protocol"
	"github.com/psproxy/psproxy/internal/staging"
)

func TestTunnelServerMaxStreams(t *testing.T) {
	server := NewTunnelServer(staging.NewStore(time.Minute), 1)
	agent, peer := net.Pipe()
	defer peer.Close()
	sess := NewAgentSession(agent, bufio.NewReader(agent), server.maxStreams)
	defer sess.Close()
	server.SetSession(sess)

	local1, remote1 := net.Pipe()
	defer remote1.Close()
	defer local1.Close()
	if err := sess.AttachLocal(1, local1); err != nil {
		t.Fatalf("first stream should attach: %v", err)
	}

	local2, remote2 := net.Pipe()
	defer remote2.Close()
	defer local2.Close()
	if err := sess.AttachLocal(2, local2); err == nil {
		t.Fatal("second stream should be rejected at max stream limit")
	}
}

func TestLocalStreamBackpressureClosesConnection(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	ls := newLocalStream(local)
	defer ls.close()

	failed := false
	for i := 0; i < cap(ls.ch)+10; i++ {
		if !ls.enqueue([]byte("x")) {
			failed = true
			break
		}
	}
	if !failed {
		t.Fatal("enqueue should eventually fail when the local write queue is full")
	}
}

func TestTunnelServerQueryDNS(t *testing.T) {
	server := NewTunnelServer(staging.NewStore(time.Minute), 2)
	agent, peer := net.Pipe()
	defer peer.Close()
	sess := NewAgentSession(agent, bufio.NewReader(agent), server.maxStreams)
	defer sess.Close()
	server.SetSession(sess)
	go sess.Run()

	go func() {
		f, err := protocol.ReadFrame(peer)
		if err != nil {
			return
		}
		_ = protocol.WriteFrame(peer, protocol.Frame{StreamID: f.StreamID, Type: protocol.FrameDNSReply, Payload: []byte("dns-response")})
	}()

	resp, err := server.QueryDNS([]byte("dns-query"))
	if err != nil {
		t.Fatalf("dns query failed: %v", err)
	}
	if string(resp) != "dns-response" {
		t.Fatalf("unexpected dns response: %q", resp)
	}
}

func TestValidateRoutes(t *testing.T) {
	if err := validateRoutes([]string{"10.0.0.0/24", "192.168.1.10/32"}); err != nil {
		t.Fatalf("valid routes rejected: %v", err)
	}
	if err := validateRoutes([]string{"not-a-cidr"}); err == nil {
		t.Fatal("invalid CIDR should be rejected")
	}
}

func TestTunnelServerQueryDNSEmptyResponseFails(t *testing.T) {
	server := NewTunnelServer(staging.NewStore(time.Minute), 2)
	agent, peer := net.Pipe()
	defer peer.Close()
	sess := NewAgentSession(agent, bufio.NewReader(agent), server.maxStreams)
	defer sess.Close()
	server.SetSession(sess)
	go sess.Run()

	go func() {
		f, err := protocol.ReadFrame(peer)
		if err != nil {
			return
		}
		_ = protocol.WriteFrame(peer, protocol.Frame{StreamID: f.StreamID, Type: protocol.FrameDNSReply})
	}()

	if _, err := server.QueryDNS([]byte("dns-query")); err == nil {
		t.Fatal("empty DNS replies should fail")
	}
}

func TestSingleListenerAcceptReturnsEOFAfterFirstConn(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	ln := &singleListener{conn: c1, done: make(chan struct{})}
	got, err := ln.Accept()
	if err != nil {
		t.Fatalf("first accept failed: %v", err)
	}
	if got != c1 {
		t.Fatal("first accept returned unexpected connection")
	}
	if _, err := ln.Accept(); err == nil {
		t.Fatal("second accept should return EOF")
	}
}
func TestDecryptSessionSecretAcceptsAgentSHA1OAEP(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("0123456789abcdef0123456789abcdef")
	enc, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &key.PublicKey, secret, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decryptSessionSecret(key, enc)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(secret) {
		t.Fatalf("got %q want %q", got, secret)
	}
}

func TestServerSecureHandshakeEncryptedFrame(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	store := staging.NewStore(time.Minute)
	sess, err := store.Create("c2.example.com", 443, "server-key", "")
	if err != nil {
		t.Fatal(err)
	}
	server := NewTunnelServer(store, 2)
	server.identityKey = key
	srv, cli := net.Pipe()
	defer cli.Close()
	go handleAgent(srv, bufio.NewReader(srv), server)
	if _, err := cli.Write([]byte("HELLO ")); err != nil {
		t.Fatal(err)
	}
	secret := []byte("0123456789abcdef0123456789abcdef")
	nonce := []byte("abcdef0123456789abcdef0123456789")
	enc, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, secret, []byte("PS-Proxy PSP1 session"))
	if err != nil {
		t.Fatal(err)
	}
	helloTail := base64.RawURLEncoding.EncodeToString(enc) + " " + base64.RawURLEncoding.EncodeToString(nonce) + "\n"
	if _, err := cli.Write([]byte(helloTail)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(cli)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) != 3 || parts[0] != "PROOF" {
		t.Fatalf("bad proof line: %q", line)
	}
	serverNonce, _ := base64.RawURLEncoding.DecodeString(parts[1])
	proof, _ := base64.RawURLEncoding.DecodeString(parts[2])
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(protocol.Magic))
	mac.Write([]byte("HELLO " + helloTail))
	mac.Write(serverNonce)
	mac.Write(nonce)
	mac.Write(pubDER)
	if !hmac.Equal(proof, mac.Sum(nil)) {
		t.Fatal("proof mismatch")
	}
	codec, err := protocol.NewSecureCodec(br, cli, secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := codec.WriteFrame(protocol.Frame{Type: protocol.FramePing, Payload: []byte("ENROLL " + sess.EnrollToken + " " + sess.ReconnectToken)}); err != nil {
		t.Fatal(err)
	}
	f, err := codec.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != protocol.FramePong || string(f.Payload) != "OK" {
		t.Fatalf("unexpected ack: %#v", f)
	}
}
