package client

import (
	"strings"
	"testing"
)

func TestKeyGenerationAndRoundTrip(t *testing.T) {
	alice, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	bob, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if alice.PublicKey == alice.PrivateKey || alice.PublicKey == bob.PublicKey {
		t.Fatal("keys not random/distinct")
	}

	// Alice encrypts to Bob; Bob decrypts.
	sealed, err := encryptTo([]byte("meet at dawn"), alice.PrivateKey, bob.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := decryptFrom(sealed, bob.PrivateKey, alice.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "meet at dawn" {
		t.Fatalf("plaintext = %q", pt)
	}
	// Ciphertext must not contain the plaintext.
	if strings.Contains(sealed, "dawn") {
		t.Fatal("ciphertext leaks plaintext")
	}
	// Nonce prefix differs each time (random nonce).
	sealed2, _ := encryptTo([]byte("meet at dawn"), alice.PrivateKey, bob.PublicKey)
	if sealed == sealed2 {
		t.Fatal("no random nonce")
	}
}

func TestWrongKeyFails(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	eve, _ := GenerateKeyPair()

	sealed, err := encryptTo([]byte("secret"), alice.PrivateKey, bob.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	// Eve cannot open Bob's message, even with her own private key and
	// Alice's public key.
	if _, err := decryptFrom(sealed, eve.PrivateKey, alice.PublicKey); err == nil {
		t.Fatal("eve decrypted the message")
	}
	// Bob cannot open with the wrong (Eve's) public key.
	if _, err := decryptFrom(sealed, bob.PrivateKey, eve.PublicKey); err == nil {
		t.Fatal("wrong public key decrypted")
	}
	// Tampered ciphertext fails.
	if _, err := decryptFrom(sealed[:len(sealed)-2]+"XX", bob.PrivateKey, alice.PublicKey); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}

func TestClientKeyManagement(t *testing.T) {
	c := New("http://127.0.0.1:1")
	if _, ok := c.KeyPair(); ok {
		t.Fatal("keys should be unset")
	}
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	c.SetKeys(kp)
	got, ok := c.KeyPair()
	if !ok || got.PublicKey != kp.PublicKey {
		t.Fatal("SetKeys did not stick")
	}
	// Encrypt before keys set: error.
	c2 := New("http://127.0.0.1:1")
	if _, err := c2.Encrypt("aGVsbG8=", "hi"); err == nil {
		t.Fatal("encrypt without keys should fail")
	}
}

func TestMalformedKeys(t *testing.T) {
	c := New("http://x")
	kp, _ := GenerateKeyPair()
	c.SetKeys(kp)
	if _, err := c.Encrypt("!!!!not-base64!!!!", "hi"); err == nil {
		t.Fatal("malformed recipient key accepted")
	}
	if _, err := c.Encrypt("aGVsbG8=", "hi"); err == nil { // 5 bytes, not 32
		t.Fatal("short recipient key accepted")
	}
}
