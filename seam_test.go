package seam

import (
	"encoding/json"
	"testing"
)

func TestRoundtripDM32(t *testing.T) {
	ikp, err := generateIdentityKeyPair()
	if err != nil {
		t.Fatalf("Unable to generate identity key pair: %v", err)
	}
	recipient32, err := generateDMKeyPair()
	if err != nil {
		t.Fatalf("Unable to generate recipient key pair: %v", err)
	}
	transit32, err := generateDMKeyPair()
	if err != nil {
		t.Fatalf("Unable to generate transit key pair: %v", err)
	}

	body := []byte("carole baskin fed her husband to the tigers")
	e, err := DirectMessageEnvelope(body, "joe@wynnewoodzoo.org", ikp, transit32, recipient32.PublicKey)

	if err = e.Verify(ikp); err != nil {
		t.Fatalf("Unable to verify signature: %v", err)
	}

	parsed := DirectMessage32{}
	if err = json.Unmarshal(e.Message, &parsed); err != nil {
		t.Fatalf("Unable to parse message body: %v", err)
	}

	decrypted, err := parsed.Open(recipient32.PrivateKey)
	if err != nil {
		t.Fatalf("Unable to open message: %v", err)
	}

	if string(decrypted) != string(body) {
		t.Fatalf("Decrypted body did not match: got %v", string(decrypted))
	}
}

func TestRoundtripShared32(t *testing.T) {
	ikp, err := generateIdentityKeyPair()
	if err != nil {
		t.Fatalf("Unable to generate identity key pair: %v", err)
	}

	shared32, err := generateSharedSecret32()
	if err != nil {
		t.Fatalf("Unable to generate recipient key pair: %v", err)
	}

	body := []byte("carole baskin fed her husband to the tigers")
	e, err := SharedMessageEnvelope(body, "joe@wynnewoodzoo.org", ikp, shared32)
	if err != nil {
		t.Fatalf("Unable to get envelope: %v", err)
	}

	if err = e.Verify(ikp); err != nil {
		t.Fatalf("Unable to verify signature: %v", err)
	}

	parsed := SharedMessage32{}
	if err = json.Unmarshal(e.Message, &parsed); err != nil {
		t.Fatalf("Unable to parse message body: %v", err)
	}

	decrypted, err := parsed.Open(shared32)
	if err != nil {
		t.Fatalf("Unable to open message: %v", err)
	}

	if string(decrypted) != string(body) {
		t.Fatalf("Decrypted body did not match: got %v", string(decrypted))
	}
}
