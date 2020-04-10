package seam

import (
	"crypto/rand"
	"io"
	"time"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/sign"
)

// Timestamp is a Unix milliseconds offset representing when the message was authored
type Timestamp int64

// SigningSecret64 is a 64-byte secret key that is used to assume a cryptographic identity
type SigningSecret64 [64]byte

// Identity32 is a 32-byte public key that represents a cryptographic identity
type Identity32 [32]byte

// SharedSecret32 is a 32-byte secret key used for encryption
type SharedSecret32 [32]byte

// DMSecret32 is a 32-byte secret key used to decrypt direct messages
type DMSecret32 [32]byte

// DMIdentity32 is a 32-byte public key used to encrypt direct messages
type DMIdentity32 [32]byte

// IdentityKeyPair is a SigningSecret64 paired with its derived Identity32
type IdentityKeyPair struct {
	PrivateKey *SigningSecret64 `json:"privateKey,omitempty"`
	PublicKey  *Identity32      `json:"publicKey,omitempty"`
}

// DMKeyPair is a SharedSecret32 paired with its derived DMIdentity32
type DMKeyPair struct {
	PrivateKey *DMSecret32   `json:"privateKey,omitempty"`
	PublicKey  *DMIdentity32 `json:"publicKey,omitempty"`
}

// Signature64 is a 64-byte cryptographic signature
type Signature64 [64]byte

// Nonce24 is a 24-byte encryption nonce
type Nonce24 [24]byte

// SharedMessageEnvelope takes a body, signing identity, and secret, and returns an Envelope ready to send
func SharedMessageEnvelope(body []byte, destination string, ikp *IdentityKeyPair, secret *SharedSecret32) (*Envelope, error) {
	sm := NewSharedMessage32(time.Now(), destination)
	sm.WriteBody(body, secret)

	bz, err := sm.Canonical()
	if err != nil {
		return nil, err
	}

	e := NewEnvelope(bz)
	e.Sign(ikp)

	return e, nil
}

// DirectMessageEnvelope takes a body, signing identity, and secret, and returns an Envelope ready to send
func DirectMessageEnvelope(body []byte, destination string, ikp *IdentityKeyPair, transitKeyPair *DMKeyPair, recipient *DMIdentity32) (*Envelope, error) {
	sm := NewDirectMessage32(time.Now(), destination)
	sm.WriteBody(body, recipient, transitKeyPair)

	bz, err := sm.Canonical()
	if err != nil {
		return nil, err
	}

	e := NewEnvelope(bz)
	e.Sign(ikp)

	return e, nil
}

func generateDMKeyPair() (*DMKeyPair, error) {
	public, private, err := box.GenerateKey(rand.Reader)
	di32 := DMIdentity32(*public)
	ds32 := DMSecret32(*private)
	return &DMKeyPair{PublicKey: &di32, PrivateKey: &ds32}, err
}

func generateSharedSecret32() (*SharedSecret32, error) {
	var secretKey SharedSecret32
	if _, err := io.ReadFull(rand.Reader, secretKey[:]); err != nil {
		return nil, err
	}
	return &secretKey, nil
}

func generateIdentityKeyPair() (*IdentityKeyPair, error) {
	public, private, err := sign.GenerateKey(rand.Reader)
	i32 := Identity32(*public)
	s64 := SigningSecret64(*private)
	return &IdentityKeyPair{PublicKey: &i32, PrivateKey: &s64}, err
}
