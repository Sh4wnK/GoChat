// Package auth implements password hashing (argon2id) and JWT access
// token minting/validation.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/argon2"
)

const (
	// Argon2id parameters: OWASP-recommended for interactive logins
	// (64 MiB memory, 1 thread is lowered to 2 for portability).
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 2
	argonLen     = 32
	saltLen      = 16
)

// Errors returned by the auth package.
var (
	ErrInvalidToken    = errors.New("invalid or expired token")
	ErrPasswordTooLong = errors.New("password too long")
)

// HashPassword derives an argon2id hash encoded as PHC string:
// $argon2id$v=19$m=65536,t=3,p=2$<salt b64>$<hash b64>
func HashPassword(password string) (string, error) {
	if len(password) > 1024 {
		return "", ErrPasswordTooLong
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword checks a password against a PHC argon2id string.
func VerifyPassword(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	// [$argon2id v=19 m=65536,t=3,p=2 salt hash]
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false, errors.New("malformed password hash")
	}
	m, t, p, err := parseParams(parts[3])
	if err != nil {
		return false, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(password), salt, uint32(t), uint32(m), uint8(p), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// parseParams parses the "m=65536,t=3,p=2" section.
func parseParams(s string) (m, t, p int, err error) {
	for _, kv := range strings.Split(s, ",") {
		var v int
		var key string
		if _, e := fmt.Sscanf(kv, "%1s=%d", &key, &v); e != nil {
			return 0, 0, 0, errors.New("malformed password hash")
		}
		switch key {
		case "m":
			m = v
		case "t":
			t = v
		case "p":
			p = v
		default:
			return 0, 0, 0, errors.New("malformed password hash")
		}
	}
	if m <= 0 || t <= 0 || p <= 0 {
		return 0, 0, 0, errors.New("malformed password hash")
	}
	return m, t, p, nil
}

// TokenConfig configures JWT access token issuance.
type TokenConfig struct {
	// Secret is the HMAC signing key (at least 32 bytes).
	Secret []byte
	// TTL is the token lifetime.
	TTL time.Duration
	// Issuer is embedded in the token.
	Issuer string
}

// Token contains the access token and its expiry.
type Token struct {
	Value     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// Claims are the JWT claims carried by access tokens.
type Claims struct {
	UserID   string `json:"uid"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// Signer mints and validates access tokens.
type Signer struct {
	cfg TokenConfig
}

// NewSigner returns a Signer. Panics if Secret is shorter than 32 bytes.
func NewSigner(cfg TokenConfig) *Signer {
	if len(cfg.Secret) < 32 {
		panic("auth: signing secret must be at least 32 bytes")
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 24 * time.Hour
	}
	if cfg.Issuer == "" {
		cfg.Issuer = "gochat"
	}
	return &Signer{cfg: cfg}
}

// Issue creates an access token for a user.
func (s *Signer) Issue(userID, username string) (Token, error) {
	now := time.Now()
	exp := now.Add(s.cfg.TTL)
	claims := Claims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.cfg.Issuer,
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(s.cfg.Secret)
	if err != nil {
		return Token{}, err
	}
	return Token{Value: signed, ExpiresAt: exp}, nil
}

// Verify parses and validates a token, returning its claims.
func (s *Signer) Verify(raw string) (Claims, error) {
	claims := &Claims{}
	tok, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}
		return s.cfg.Secret, nil
	}, jwt.WithIssuer(s.cfg.Issuer), jwt.WithExpirationRequired())
	if err != nil || !tok.Valid {
		return Claims{}, ErrInvalidToken
	}
	return *claims, nil
}
