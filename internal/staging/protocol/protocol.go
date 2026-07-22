package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	Magic = "PSP1\n"

	FrameOpen     byte = 1
	FrameOpenOK   byte = 2
	FrameOpenFail byte = 3
	FrameData     byte = 4
	FrameClose    byte = 5
	FramePing     byte = 6
	FramePong     byte = 7

	MaxPayload = 1 << 20
)

const headerLen = 13

type Frame struct {
	StreamID uint64
	Type     byte
	Payload  []byte
}

func ReadFrame(r io.Reader) (Frame, error) {
	var hdr [headerLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	length := binary.BigEndian.Uint32(hdr[9:13])
	if length > MaxPayload {
		return Frame{}, fmt.Errorf("frame payload too large: %d", length)
	}
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return Frame{}, err
		}
	}
	return Frame{StreamID: binary.BigEndian.Uint64(hdr[0:8]), Type: hdr[8], Payload: payload}, nil
}

func WriteFrame(w io.Writer, f Frame) error {
	if len(f.Payload) > MaxPayload {
		return fmt.Errorf("frame payload too large: %d", len(f.Payload))
	}
	var hdr [headerLen]byte
	binary.BigEndian.PutUint64(hdr[0:8], f.StreamID)
	hdr[8] = f.Type
	binary.BigEndian.PutUint32(hdr[9:13], uint32(len(f.Payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(f.Payload) > 0 {
		_, err := w.Write(f.Payload)
		return err
	}
	return nil
}
