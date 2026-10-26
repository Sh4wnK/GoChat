package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is a GoChat API client. It talks to the REST API, uploads and
// fetches public keys, and opens WebSocket sessions.
type Client struct {
	// BaseURL is the server origin, e.g. http://localhost:8080.
	BaseURL string
	// HTTP is the underlying HTTP client.
	HTTP *http.Client

	apiKey string // JWT access token (after Login)
	// keys guard the E2E keypair.
	keys       bool
	publicKey  string
	privateKey string
}

// New returns a client for a server origin.
func New(baseURL string) *Client {
	return &Client{
		BaseURL: baseURL,
		HTTP:    &http.Client{Timeout: 15 * time.Second},
	}
}

// SetToken stores a JWT for authenticated requests.
func (c *Client) SetToken(token string) { c.apiKey = token }

// Token returns the current JWT ("" if unauthenticated).
func (c *Client) Token() string { return c.apiKey }

// SetKeys installs an E2E keypair without touching the server.
func (c *Client) SetKeys(kp KeyPair) {
	c.publicKey, c.privateKey = kp.PublicKey, kp.PrivateKey
	c.keys = true
}

func (c *Client) keysSet() bool { return c.keys }

// KeyPair returns the current local keypair.
func (c *Client) KeyPair() (KeyPair, bool) {
	if !c.keys {
		return KeyPair{}, false
	}
	return KeyPair{PublicKey: c.publicKey, PrivateKey: c.privateKey}, true
}

// PublicKey returns the local public key ("" if unset).
func (c *Client) PublicKey() string { return c.publicKey }

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s %s: %s", method, path, strings.TrimSpace(string(msg)))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// Register creates an account and returns the new user.
func (c *Client) Register(ctx context.Context, username, password, displayName string) (User, error) {
	req := registerRequest{Username: username, Password: password, DisplayName: displayName}
	var out User
	err := c.do(ctx, http.MethodPost, "/api/v1/users", req, &out)
	return out, err
}

type registerRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	DisplayName string `json:"displayName"`
}

// Login authenticates and stores the returned JWT on the client.
func (c *Client) Login(ctx context.Context, username, password string) (AuthResponse, error) {
	var out AuthResponse
	err := c.do(ctx, http.MethodPost, "/api/v1/auth/login",
		loginRequest{Username: username, Password: password}, &out)
	if err == nil {
		c.SetToken(out.Token)
	}
	return out, err
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// AuthResponse is the login response.
type AuthResponse struct {
	Token   string `json:"token"`
	User    User   `json:"user"`
	Expires string `json:"expiresAt"`
}

// Me returns the authenticated user's profile.
func (c *Client) Me(ctx context.Context) (User, error) {
	var out User
	err := c.do(ctx, http.MethodGet, "/api/v1/users/me", nil, &out)
	return out, err
}

// UpdateProfile updates the display name.
func (c *Client) UpdateProfile(ctx context.Context, displayName string) error {
	return c.do(ctx, http.MethodPatch, "/api/v1/users/me",
		map[string]string{"displayName": displayName}, nil)
}

// DeleteAccount deletes the authenticated account.
func (c *Client) DeleteAccount(ctx context.Context) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/users/me", nil, nil)
}

// ListUsers lists users, newest page first.
func (c *Client) ListUsers(ctx context.Context, limit, offset int) ([]User, error) {
	var out []User
	path := fmt.Sprintf("/api/v1/users?limit=%d&offset=%d", limit, offset)
	err := c.do(ctx, http.MethodGet, path, nil, &out)
	return out, err
}

// GetUser fetches a user by ID.
func (c *Client) GetUser(ctx context.Context, id string) (User, error) {
	var out User
	err := c.do(ctx, http.MethodGet, "/api/v1/users/"+url.PathEscape(id), nil, &out)
	return out, err
}

// UploadPublicKey registers this client's E2E public key with the
// server so other users can encrypt DMs to it.
func (c *Client) UploadPublicKey(ctx context.Context) error {
	if !c.keys {
		return errors.New("client: no keypair; generate or load one first")
	}
	return c.do(ctx, http.MethodPut, "/api/v1/users/me/public-key",
		map[string]string{"publicKey": c.publicKey}, nil)
}

// User is the REST representation of a chat user.
type User struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	PublicKey   string `json:"publicKey,omitempty"`
	CreatedAt   string `json:"createdAt"`
}
