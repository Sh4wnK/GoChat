// Package client is the official GoChat client library. It implements
// the REST user management API, the WebSocket protocol, and the
// end-to-end encryption used for private messages: clients exchange
// X25519 keypairs, derive a shared secret with X25519, and encrypt
// message bodies with an XChaCha20-Poly1305 AEAD. The server only ever
// sees and relays the opaque ciphertext.
package client

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// KeyPair is an X25519 keypair. PublicKey is exported to the chat server
// over REST so other users can encrypt DMs to this user.
type KeyPair struct {
	PublicKey  string `json:"publicKey"`  // base64 raw std encoding, 32 bytes
	PrivateKey string `json:"privateKey"` // base64 raw std encoding, 32 bytes
}

// GenerateKeyPair creates a fresh X25519 keypair.
func GenerateKeyPair() (KeyPair, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return KeyPair{}, err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{
		PublicKey:  base64.RawStdEncoding.EncodeToString(pub),
		PrivateKey: base64.RawStdEncoding.EncodeToString(priv[:]),
	}, nil
}

// ErrMalformedKey is returned when a key cannot be decoded.
var ErrMalformedKey = errors.New("client: malformed keys")

var errBadNonce = errors.New("client: malformed nonce")

// encryptTo seals plaintext using the shared secret derived from
// privateKey (ours) and publicKey (theirs). Output format:
//
//	[ 24-byte random nonce ][ AEAD ciphertext ]
//
// both segments base64-encoded as a single string.
func encryptTo(plaintext []byte, privateKey, publicKey string) (string, error) {
	priv, err := base64.RawStdEncoding.DecodeString(privateKey)
	if err != nil || len(priv) != curve25519.PointSize {
		return "", fmt.Errorf("%w: private key", ErrMalformedKey)
	}
	pub, err := base64.RawStdEncoding.DecodeString(publicKey)
	if err != nil || len(pub) != curve25519.PointSize {
		return "", fmt.Errorf("%w: public key", ErrMalformedKey)
	}
	shared, err := curve25519.X25519(priv, pub)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrMalformedKey, err)
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	aead, err := chacha20poly1305.NewX(shared)
	if err != nil {
		return "", err
	}
	sealed := aead.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, len(nonce)+len(sealed))
	out = append(out, nonce...)
	out = append(out, sealed...)
	return base64.RawStdEncoding.EncodeToString(out), nil
}

func decryptFrom(sealedB64 string, privateKey, publicKey string) ([]byte, error) {
	raw, err := base64.RawStdEncoding.DecodeString(sealedB64)
	if err != nil || len(raw) < chacha20poly1305.NonceSizeX {
		return nil, errBadNonce
	}
	priv, err := base64.RawStdEncoding.DecodeString(privateKey)
	if err != nil || len(priv) != curve25519.PointSize {
		return nil, fmt.Errorf("%w: private key", ErrMalformedKey)
	}
	pub, err := base64.RawStdEncoding.DecodeString(publicKey)
	if err != nil || len(pub) != curve25519.PointSize {
		return nil, fmt.Errorf("%w: public key", ErrMalformedKey)
	}
	shared, err := curve25519.X25519(priv, pub)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedKey, err)
	}
	aead, err := chacha20poly1305.NewX(shared)
	if err != nil {
		return nil, err
	}
	nonce, ct := raw[:chacha20poly1305.NonceSizeX], raw[chacha20poly1305.NonceSizeX:]
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, errors.New("client: decryption failed (wrong key or tampered data)")
	}
	return pt, nil
}

// Encrypt seals a DM body addressed to the recipient's public key.
func (c *Client) Encrypt(recipientPublicKey string, plaintext string) (string, error) {
	if !c.keysSet() {
		return "", errors.New("client: no local keypair; call LoadKey or GenerateKeyPair/SetKeys")
	}
	return encryptTo([]byte(plaintext), c.privateKey, recipientPublicKey)
}

// Decrypt opens a sealed DM body from the sender's public key.
func (c *Client) Decrypt(senderPublicKey string, sealed string) (string, error) {
	if !c.keysSet() {
		return "", errors.New("client: no local keypair; call LoadKey or GenerateKeyPair/SetKeys")
	}
	pt, err := decryptFrom(sealed, c.privateKey, senderPublicKey)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}
