package main

import (
	"bufio"
	"net"
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

func TestNormalizeCertPin(t *testing.T) {
	pin := "BC:1D:96:47:91:A5:11:B4:95:26:EC:F2:25:35:37:F6:E6:17:0A:1A:19:4F:45:65:9E:88:0C:A7:A4:3D:6C:02"
	got, err := normalizeCertPin(pin)
	if err != nil {
		t.Fatalf("normalize pin failed: %v", err)
	}
	want := "bc1d964791a511b49526ecf2253537f6e6170a1a194f45659e880ca7a43d6c02"
	if got != want {
		t.Fatalf("unexpected normalized pin: %s", got)
	}
}

func TestNormalizeCertPinRejectsInvalidPins(t *testing.T) {
	for _, pin := range []string{"abc", "zz1d964791a511b49526ecf2253537f6e6170a1a194f45659e880ca7a43d6c02"} {
		if _, err := normalizeCertPin(pin); err == nil {
			t.Fatalf("expected invalid pin %q to fail", pin)
		}
	}
}
