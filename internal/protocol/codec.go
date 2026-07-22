package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const secureMaxRecord = MaxPayload + 1024

type Codec interface {
	ReadFrame() (Frame, error)
	WriteFrame(Frame) error
}

type PlainCodec struct {
	R io.Reader
	W io.Writer
}

func NewPlainCodec(r io.Reader, w io.Writer) *PlainCodec { return &PlainCodec{R: r, W: w} }
func (c *PlainCodec) ReadFrame() (Frame, error)          { return ReadFrame(c.R) }
func (c *PlainCodec) WriteFrame(f Frame) error           { return WriteFrame(c.W, f) }

type SecureCodec struct {
	r                io.Reader
	w                io.Writer
	encKey, macKey   []byte
	sendSeq, recvSeq uint64
}

func NewSecureCodec(r io.Reader, w io.Writer, secret []byte) (*SecureCodec, error) {
	if len(secret) != 32 {
		return nil, fmt.Errorf("secure codec requires 32-byte secret")
	}
	e := sha256.Sum256(append(append([]byte(nil), secret...), []byte("psproxy aes-cbc")...))
	m := sha256.Sum256(append(append([]byte(nil), secret...), []byte("psproxy hmac")...))
	return &SecureCodec{r: r, w: w, encKey: e[:], macKey: m[:]}, nil
}
func (c *SecureCodec) WriteFrame(f Frame) error {
	var plain bytes.Buffer
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], c.sendSeq)
	plain.Write(seq[:])
	if err := WriteFrame(&plain, f); err != nil {
		return err
	}
	padded := pkcs7Pad(plain.Bytes(), aes.BlockSize)
	block, err := aes.NewCipher(c.encKey)
	if err != nil {
		return err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return err
	}
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	rec := append(iv, ct...)
	mac := hmac.New(sha256.New, c.macKey)
	mac.Write(seq[:])
	mac.Write(rec)
	tag := mac.Sum(nil)
	if len(rec)+len(tag) > secureMaxRecord {
		return fmt.Errorf("secure record too large")
	}
	var lenb [4]byte
	binary.BigEndian.PutUint32(lenb[:], uint32(len(rec)+len(tag)))
	if _, err := c.w.Write(lenb[:]); err != nil {
		return err
	}
	if _, err := c.w.Write(rec); err != nil {
		return err
	}
	if _, err := c.w.Write(tag); err != nil {
		return err
	}
	c.sendSeq++
	return nil
}
func (c *SecureCodec) ReadFrame() (Frame, error) {
	var lenb [4]byte
	if _, err := io.ReadFull(c.r, lenb[:]); err != nil {
		return Frame{}, err
	}
	n := binary.BigEndian.Uint32(lenb[:])
	if n < aes.BlockSize+sha256.Size || n > secureMaxRecord {
		return Frame{}, fmt.Errorf("invalid secure record length: %d", n)
	}
	rec := make([]byte, n)
	if _, err := io.ReadFull(c.r, rec); err != nil {
		return Frame{}, err
	}
	body, tag := rec[:n-sha256.Size], rec[n-sha256.Size:]
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], c.recvSeq)
	mac := hmac.New(sha256.New, c.macKey)
	mac.Write(seq[:])
	mac.Write(body)
	if !hmac.Equal(tag, mac.Sum(nil)) {
		return Frame{}, errors.New("secure frame authentication failed")
	}
	if (len(body)-aes.BlockSize)%aes.BlockSize != 0 {
		return Frame{}, errors.New("invalid secure ciphertext length")
	}
	block, err := aes.NewCipher(c.encKey)
	if err != nil {
		return Frame{}, err
	}
	pt := make([]byte, len(body)-aes.BlockSize)
	cipher.NewCBCDecrypter(block, body[:aes.BlockSize]).CryptBlocks(pt, body[aes.BlockSize:])
	pt, err = pkcs7Unpad(pt, aes.BlockSize)
	if err != nil {
		return Frame{}, err
	}
	if len(pt) < 8 {
		return Frame{}, errors.New("secure plaintext too short")
	}
	got := binary.BigEndian.Uint64(pt[:8])
	if got != c.recvSeq {
		return Frame{}, fmt.Errorf("secure frame sequence mismatch: got %d want %d", got, c.recvSeq)
	}
	f, err := ReadFrame(bytes.NewReader(pt[8:]))
	if err != nil {
		return Frame{}, err
	}
	c.recvSeq++
	return f, nil
}
func pkcs7Pad(b []byte, block int) []byte {
	pad := block - len(b)%block
	out := append([]byte(nil), b...)
	for i := 0; i < pad; i++ {
		out = append(out, byte(pad))
	}
	return out
}
func pkcs7Unpad(b []byte, block int) ([]byte, error) {
	if len(b) == 0 || len(b)%block != 0 {
		return nil, errors.New("invalid padding length")
	}
	p := int(b[len(b)-1])
	if p == 0 || p > block || p > len(b) {
		return nil, errors.New("invalid padding")
	}
	for _, v := range b[len(b)-p:] {
		if int(v) != p {
			return nil, errors.New("invalid padding")
		}
	}
	return b[:len(b)-p], nil
}
