package protocol

import (
	"net"
	"testing"
)

func TestSecureCodecRoundTrip(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	secret := []byte("0123456789abcdef0123456789abcdef")
	a, _ := NewSecureCodec(c1, c1, secret)
	b, _ := NewSecureCodec(c2, c2, secret)
	want := Frame{StreamID: 7, Type: FrameData, Payload: []byte("hello")}
	go func() { _ = a.WriteFrame(want) }()
	got, err := b.ReadFrame()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.StreamID != want.StreamID || got.Type != want.Type || string(got.Payload) != string(want.Payload) {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

func TestSecureCodecTamperRejection(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	secret := []byte("0123456789abcdef0123456789abcdef")
	a, _ := NewSecureCodec(c1, c1, secret)
	go func() { _ = a.WriteFrame(Frame{Type: FrameData, Payload: []byte("hello")}) }()
	lenb := make([]byte, 4)
	if _, err := c2.Read(lenb); err != nil {
		t.Fatal(err)
	}
	rec := make([]byte, int(lenb[0])<<24|int(lenb[1])<<16|int(lenb[2])<<8|int(lenb[3]))
	if _, err := c2.Read(rec); err != nil {
		t.Fatal(err)
	}
	rec[len(rec)-1] ^= 0xff
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	go func() { client.Write(lenb); client.Write(rec) }()
	b, _ := NewSecureCodec(server, server, secret)
	if _, err := b.ReadFrame(); err == nil {
		t.Fatal("tampered frame should be rejected")
	}
}
