package seam

import (
	"crypto/sha512"
	"errors"

	"golang.org/x/crypto/nacl/sign"
)

// Envelope is a public key and signature wrapping a blob of bytes
type Envelope struct {
	Identity32  `json:"author"`
	Signature64 `json:"signature"`
	Message     []byte `json:"message"`
}

// NewEnvelope returns an unsigned envelope for the given bytes
func NewEnvelope(msg []byte) *Envelope {
	return &Envelope{Identity32{}, Signature64{}, msg}
}

// Sign signs the message with the given identity key pair and attaches the author and signature to the Envelope
func (e *Envelope) Sign(ikp *IdentityKeyPair) {
	secret := [64]byte(*ikp.PrivateKey)
	h := sha512.New()
	hbz := h.Sum(e.Message)
	signed := sign.Sign(nil, hbz, &secret)
	var signature Signature64
	copy(signature[:], signed[:64])
	e.Identity32 = *ikp.PublicKey
	e.Signature64 = signature
}

// Verify checks the signature against the contents of the envelope
func (e *Envelope) Verify(ikp *IdentityKeyPair) error {
	h := sha512.New()
	hbz := h.Sum(e.Message)
	signedBz := make([]byte, len(hbz)+64)
	copy(signedBz[:64], e.Signature64[:])
	copy(signedBz[64:], hbz)
	publicKey := [32]byte(*ikp.PublicKey)
	_, valid := sign.Open(nil, signedBz, &publicKey)
	if !valid {
		return errors.New("Invalid signature")
	}
	return nil
}
