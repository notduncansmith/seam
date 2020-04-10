package seam

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/nacl/secretbox"
)

// SharedMessage32 represents a Message32 intended for recipients with access to a shared secret. The body may contain anything and is usually encrypted, but if not the EncryptionNonce will be all zero bytes.
type SharedMessage32 struct {
	Body        []byte `json:"body"`
	Destination string `json:"destination"`
	Mode        string `json:"mode"`
	Nonce24     []byte `json:"nonce"`
	Timestamp   `json:"timestamp"`
}

// NewSharedMessage32 returns a SharedMessage32 with the given properties
func NewSharedMessage32(timestamp time.Time, dest string) *SharedMessage32 {
	return &SharedMessage32{Timestamp: Timestamp(timestamp.UnixNano() / 1000), Mode: "shared", Destination: dest}
}

// Canonical returns the canonical encoding of the message
func (m *SharedMessage32) Canonical() ([]byte, error) {
	jsonStr := strings.Join([]string{
		"{",
		"\"mode\":\"shared\",",
		"\"body\":\"" + base64.StdEncoding.EncodeToString(m.Body) + "\",",
		"\"destination\":\"" + m.Destination + "\",",
		"\"nonce\":\"" + base64.StdEncoding.EncodeToString(m.Nonce24[:]) + "\",",
		"\"timestamp\":" + strconv.FormatInt(int64(m.Timestamp), 10),
		"}",
	}, "")

	return []byte(jsonStr), nil
}

// WriteBody encrypts the given bytes, then attaches the cyphertext and nonce to the Message
func (m *SharedMessage32) WriteBody(bz []byte, secret *SharedSecret32) error {
	nonce := [24]byte{}
	secretKey := [32]byte(*secret)

	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return err
	}

	cypherbz := secretbox.Seal(nil, bz, &nonce, &secretKey)

	m.Body = cypherbz
	m.Nonce24 = nonce[:]

	return nil
}

// Open implements Message using the `secretbox` construction
func (m *SharedMessage32) Open(secret *SharedSecret32) ([]byte, error) {
	secretKey := [32]byte(*secret)
	nonce := [24]byte{}
	copy(nonce[:], m.Nonce24)

	clearbz, ok := secretbox.Open(nil, m.Body, &nonce, &secretKey)
	if !ok {
		return nil, errors.New("Unable to decrypt")
	}
	return clearbz, nil
}
