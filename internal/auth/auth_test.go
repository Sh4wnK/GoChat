package auth

import (
	"strings"
	"testing"
	"time"
)

func TestHashVerify(t *testing.T) {
	h, err := HashPassword("hunter2-secret")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$") {
		t.Fatalf("hash %q not argon2id PHC", h)
	}
	ok, err := VerifyPassword("hunter2-secret", h)
	if err != nil || !ok {
		t.Fatalf("valid password rejected: ok=%v err=%v", ok, err)
	}
	ok, _ = VerifyPassword("wrong", h)
	if ok {
		t.Fatal("wrong password accepted")
	}
	// Two hashes of the same password differ (random salt).
	h2, _ := HashPassword("hunter2-secret")
	if h == h2 {
		t.Fatal("hashes not salted")
	}
}

func TestHashRejectsLongPassword(t *testing.T) {
	if _, err := HashPassword(strings.Repeat("x", 2048)); err != ErrPasswordTooLong {
		t.Fatalf("err = %v, want ErrPasswordTooLong", err)
	}
}

func TestSignerRoundTrip(t *testing.T) {
	signer := NewSigner(TokenConfig{
		Secret: []byte("01234567890123456789012345678901"), // 32 bytes
		TTL:    time.Hour,
		Issuer: "gochat",
	})
	tok, err := signer.Issue("u42", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if tok.Value == "" || tok.ExpiresAt.Before(time.Now()) {
		t.Fatalf("bad token %+v", tok)
	}
	claims, err := signer.Verify(tok.Value)
	if err != nil {
		t.Fatal(err)
	}
	if claims.UserID != "u42" || claims.Username != "alice" {
		t.Fatalf("claims = %+v", claims)
	}
}

func TestSignerRejectsTampered(t *testing.T) {
	signer := NewSigner(TokenConfig{Secret: []byte("01234567890123456789012345678901")})
	tok, _ := signer.Issue("u1", "a")
	if _, err := signer.Verify(tok.Value + "x"); err == nil {
		t.Fatal("tampered token accepted")
	}
	// Wrong secret.
	other := NewSigner(TokenConfig{Secret: []byte("fedcba9876543210fedcba9876543210")})
	if _, err := other.Verify(tok.Value); err == nil {
		t.Fatal("token signed with another secret accepted")
	}
}

func TestSignerPanicsOnShortSecret(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("no panic for short secret")
		}
	}()
	NewSigner(TokenConfig{Secret: []byte("short")})
}
