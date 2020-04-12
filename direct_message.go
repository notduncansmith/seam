package seam

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// DirectMessage32 represents a message intended for recipients with access to the secret. The body may contain anything and is usually encrypted, but if not the Nonce24 will be all zero bytes.
type DirectMessage32 struct {
	Body            []byte `json:"body"`
	Destination     string `json:"destination"`
	Mode            string `json:"mode"`
	Nonce24         []byte `json:"nonce"`
	Timestamp       `json:"timestamp"`
	TransitIdentity []byte `json:"transitIdentity"`
}

// NewDirectMessage32 returns a DirectMessage32 with the given properties
func NewDirectMessage32(timestamp time.Time, dest string) *DirectMessage32 {
	return &DirectMessage32{Timestamp: Timestamp(timestamp.UnixNano() / 1000000), Mode: "direct", Destination: dest}
}

// Canonical returns canonical encoding of the message
func (m *DirectMessage32) Canonical() ([]byte, error) {
	jsonStr := strings.Join([]string{
		"{",
		"\"mode\":\"direct\",",
		"\"body\":\"" + base64.StdEncoding.EncodeToString(m.Body) + "\",",
		"\"destination\":\"" + m.Destination + "\",",
		"\"nonce\":\"" + base64.StdEncoding.EncodeToString(m.Nonce24[:]) + "\",",
		"\"timestamp\":" + strconv.FormatInt(int64(m.Timestamp), 10) + ",",
		"\"transitIdentity\":\"" + base64.StdEncoding.EncodeToString(m.TransitIdentity) + "\"",
		"}",
	}, "")

	return []byte(jsonStr), nil
}

// WriteBody encrypts the given bytes using the `box` construction, then attaches the cyphertext and nonce to the Message
func (m *DirectMessage32) WriteBody(bz []byte, recipientDMIdentity *DMIdentity32, transitKeyPair *DMKeyPair) error {
	nonce := [24]byte{}
	secretKey := [32]byte{}
	copy(secretKey[:], transitKeyPair.PrivateKey[:])
	recipientKey := [32]byte{}
	copy(recipientKey[:], recipientDMIdentity[:])

	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return err
	}

	cypherbz := box.Seal(nonce[:], bz, &nonce, &recipientKey, &secretKey)

	m.Body = cypherbz[24:]
	m.Nonce24 = nonce[:]
	m.TransitIdentity = transitKeyPair.PublicKey[:]

	return nil
}

// Open implements Message using the `box` construction
func (m *DirectMessage32) Open(recipientDMSecret *DMSecret32) ([]byte, error) {
	secretKey := [32]byte(*recipientDMSecret)
	nonce := [24]byte{}
	copy(nonce[:], m.Nonce24[:])
	publicKey := [32]byte{}
	copy(publicKey[:], m.TransitIdentity)
	clearbz, ok := box.Open(nil, m.Body[:], &nonce, &publicKey, &secretKey)
	if !ok {
		return nil, errors.New("Unable to decrypt")
	}
	return clearbz, nil
}
