// Package server wires the GoChat REST API, WebSocket endpoint, broker
// fan-out and storage together into a single http.Handler.
package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Sh4wnK/GoChat/internal/auth"
	"github.com/Sh4wnK/GoChat/internal/broker"
	"github.com/Sh4wnK/GoChat/internal/ghttp"
	"github.com/Sh4wnK/GoChat/internal/hub"
	"github.com/Sh4wnK/GoChat/internal/model"
	"github.com/Sh4wnK/GoChat/internal/room"
	"github.com/Sh4wnK/GoChat/internal/userstore"
)

// Config configures a Server.
type Config struct {
	// NodeID identifies this instance in the cluster.
	NodeID string
	// Signer issues/validates JWTs. Required.
	Signer *auth.Signer
	// Store persists users and offline queues. Required.
	Store userstore.Store
	// Rooms tracks rooms, memberships and history. Defaults to a fresh
	// in-memory manager.
	Rooms *room.Manager
	// Broker fans frames to peer nodes. Defaults to a local broker
	// (single node).
	Broker broker.Broker
	// HubCfg tunes hub queue/history bounds.
	HubCfg *hub.Config
	// Log is the logger. Defaults to slog.Default().
	Log *slog.Logger
	// AllowedOrigins are the origins permitted for browser WS/REST
	// requests. "*" allows any origin.
	AllowedOrigins []string
}

// Server holds the REST + WS http handling and the node Service.
type Server struct {
	*Service
	cfg     Config
	handler http.Handler
	br      broker.Broker
}

// New assembles a Server and starts its background broker pump.
// The returned server is a http.Handler via Handler().
func New(ctx context.Context, cfg Config) (*Server, error) {
	if cfg.Signer == nil || cfg.Store == nil {
		return nil, errors.New("server: Signer and Store are required")
	}
	br := cfg.Broker
	if br == nil {
		br = broker.NewLocal("local-node")
	}
	s := &Server{
		cfg: cfg,
		br:  br,
	}
	s.Service = newService(ctx, cfg, br)
	if s.Service == nil {
		return nil, errors.New("server: failed to build service")
	}
	s.handler = s.buildHandler()
	return s, nil
}

// Handler returns the assembled http.Handler.
func (s *Server) Handler() http.Handler { return s.handler }

// Close stops the background broker pump.
func (s *Server) Close() {
	s.Service.Cancel()
	if s.br != nil {
		_ = s.br.Close()
	}
}

// ---------- routing ----------

func (s *Server) buildHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/v1/users", s.handleRegister)
	mux.HandleFunc("GET /api/v1/users", s.auth(s.handleListUsers))
	mux.HandleFunc("GET /api/v1/users/me", s.auth(s.handleMe))
	mux.HandleFunc("PATCH /api/v1/users/me", s.auth(s.handleUpdateProfile))
	mux.HandleFunc("DELETE /api/v1/users/me", s.auth(s.handleDeleteMe))
	mux.HandleFunc("PUT /api/v1/users/me/public-key", s.auth(s.handlePutPublicKey))
	mux.HandleFunc("GET /api/v1/users/me/public-key", s.auth(s.handleGetPublicKey))
	mux.HandleFunc("GET /api/v1/users/{id}", s.auth(s.handleUserByID))
	mux.HandleFunc("GET /api/v1/users/{id}/public-key", s.auth(s.handlePeerPublicKey))
	mux.HandleFunc("GET /ws", s.handleWS)
	mux.Handle("/", s.staticHandler())
	return s.middleware(mux)
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		ghttp.CORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if !ghttp.DenyIfCrossOrigin(s.Log, s.cfg.AllowedOrigins, w, r) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---------- auth middleware ----------

type ctxKeyUser struct{}

// requireUser validates the bearer token and returns the stored record.
func (s *Server) requireUser(w http.ResponseWriter, r *http.Request) (userstore.UserRecord, bool) {
	tok := ghttp.Bearer(r)
	if tok == "" {
		ghttp.Error(w, http.StatusUnauthorized, "missing bearer token")
		return userstore.UserRecord{}, false
	}
	claims, err := s.Signer.Verify(tok)
	if err != nil {
		ghttp.Error(w, http.StatusUnauthorized, "invalid or expired token")
		return userstore.UserRecord{}, false
	}
	rec, err := s.Store.GetUserByID(r.Context(), claims.UserID)
	if err != nil {
		ghttp.Error(w, http.StatusUnauthorized, "unknown account")
		return userstore.UserRecord{}, false
	}
	if !rec.Enabled {
		ghttp.Error(w, http.StatusForbidden, "account disabled")
		return userstore.UserRecord{}, false
	}
	return rec, true
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec, ok := s.requireUser(w, r)
		if !ok {
			return
		}
		ctx := context.WithValue(r.Context(), ctxKeyUser{}, rec.User)
		next(w, r.WithContext(ctx))
	}
}

// ---------- auth handler ----------

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		ghttp.Error(w, http.StatusBadRequest, "malformed request body")
		return
	}
	rec, err := s.Store.GetUserByName(r.Context(), req.Username)
	if err != nil || !rec.Enabled {
		ghttp.Error(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	ok, err := auth.VerifyPassword(req.Password, string(rec.Password))
	if err != nil || !ok {
		ghttp.Error(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	tok, err := s.Signer.Issue(rec.User.ID, rec.User.Username)
	if err != nil {
		ghttp.Error(w, http.StatusInternalServerError, "token issuance failed")
		return
	}
	ghttp.JSON(w, map[string]any{
		"token":     tok.Value,
		"expiresAt": tok.ExpiresAt.Format(time.RFC3339),
		"user":      publicUser(rec),
	})
}

// ---------- user handlers ----------

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		DisplayName string `json:"displayName"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		ghttp.Error(w, http.StatusBadRequest, "malformed request body")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	if len(req.Username) < 3 || len(req.Username) > 32 {
		ghttp.Error(w, http.StatusBadRequest, "username must be 3-32 characters")
		return
	}
	if len(req.Password) < 8 {
		ghttp.Error(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}
	if req.DisplayName == "" {
		req.DisplayName = req.Username
	}
	if len(req.DisplayName) > 64 {
		ghttp.Error(w, http.StatusBadRequest, "displayName too long")
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		ghttp.Error(w, http.StatusBadRequest, "password too long")
		return
	}
	u, err := s.Store.CreateUser(r.Context(), req.Username, req.DisplayName, []byte(hash))
	if err != nil {
		if errors.Is(err, userstore.ErrUsernameTaken) {
			ghttp.Error(w, http.StatusConflict, "username already taken")
			return
		}
		s.Log.Error("create user", "err", err)
		ghttp.Error(w, http.StatusInternalServerError, "could not create user")
		return
	}
	ghttp.JSON(w, userPublicFrom(u))
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	limit, offset := pageParams(r)
	users, err := s.Store.ListUsers(r.Context(), limit, offset)
	if err != nil {
		s.Log.Error("list users", "err", err)
		ghttp.Error(w, http.StatusInternalServerError, "could not list users")
		return
	}
	out := make([]userPublicT, 0, len(users))
	for _, u := range users {
		out = append(out, userPublicFrom(u))
	}
	ghttp.JSON(w, out)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	_ = r
	ghttp.JSON(w, publicUser(rec))
}

func (s *Server) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	var req struct {
		DisplayName string `json:"displayName"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		ghttp.Error(w, http.StatusBadRequest, "malformed request body")
		return
	}
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	if req.DisplayName == "" || len(req.DisplayName) > 64 {
		ghttp.Error(w, http.StatusBadRequest, "displayName must be 1-64 characters")
		return
	}
	if err := s.Store.UpdateProfile(r.Context(), rec.User.ID, req.DisplayName); err != nil {
		ghttp.Error(w, http.StatusInternalServerError, "could not update profile")
		return
	}
	rec.User.DisplayName = req.DisplayName
	ghttp.JSON(w, publicUser(rec))
}

func (s *Server) handleDeleteMe(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	// Disconnect live sessions first.
	for _, c := range s.Hub.Connections(rec.User.ID) {
		dropped := s.Hub.Disconnect(c)
		for _, name := range dropped {
			s.announcePresence(name, c.User, "leave", nil)
		}
		s.wsForceClose(c)
		c.CloseDone()
	}
	if err := s.Store.DeleteUser(r.Context(), rec.User.ID); err != nil && !errors.Is(err, userstore.ErrNotFound) {
		s.Log.Error("delete user", "err", err)
		ghttp.Error(w, http.StatusInternalServerError, "could not delete account")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePutPublicKey(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	var req struct {
		PublicKey string `json:"publicKey"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		ghttp.Error(w, http.StatusBadRequest, "malformed request body")
		return
	}
	if err := validatePublicKey(req.PublicKey); err != nil {
		ghttp.Error(w, http.StatusBadRequest, "invalid public key: "+err.Error())
		return
	}
	if err := s.Store.SetPublicKey(r.Context(), rec.User.ID, req.PublicKey); err != nil {
		ghttp.Error(w, http.StatusInternalServerError, "could not store key")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGetPublicKey(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	_ = rec
	ghttp.JSON(w, map[string]string{"publicKey": rec.PublicKey})
}

func (s *Server) handleUserByID(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	_ = rec
	id := r.PathValue("id")
	target, err := s.Store.GetUserByID(r.Context(), id)
	if err != nil {
		ghttp.Error(w, http.StatusNotFound, "user not found")
		return
	}
	ghttp.JSON(w, publicUser(target))
}

// handlePeerPublicKey returns the E2E public key of another user — the
// only piece a DM sender needs.
func (s *Server) handlePeerPublicKey(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	_ = rec
	id := r.PathValue("id")
	target, err := s.Store.GetUserByID(r.Context(), id)
	if err != nil {
		ghttp.Error(w, http.StatusNotFound, "user not found")
		return
	}
	if target.PublicKey == "" {
		ghttp.Error(w, http.StatusNotFound, "user has no public key")
		return
	}
	ghttp.JSON(w, map[string]string{"publicKey": target.PublicKey})
}

// ---------- JSON helpers ----------

type userPublicT struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	PublicKey   string `json:"publicKey,omitempty"`
	CreatedAt   string `json:"createdAt"`
}

func userPublicFrom(u model.User) userPublicT {
	return userPublicT{
		ID:          u.ID,
		Username:    u.Username,
		DisplayName: u.DisplayName,
		PublicKey:   u.PublicKey,
		CreatedAt:   u.CreatedAt.Format(time.RFC3339),
	}
}

func publicUser(rec userstore.UserRecord) userPublicT {
	return userPublicFrom(rec.User)
}

// validatePublicKey checks a base64 X25519 public key (32 bytes).
func validatePublicKey(key string) error {
	if key == "" {
		return errors.New("empty key")
	}
	raw, err := decodeKey(key)
	if err != nil {
		return errors.New("must be base64")
	}
	if len(raw) != 32 {
		return errors.New("must decode to 32 bytes")
	}
	return nil
}

func decodeKey(s string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(s)
	}
	return raw, err
}

// pageParams reads limit/offset with sane bounds.
func pageParams(r *http.Request) (limit, offset int) {
	q := r.URL.Query()
	limit = atoiDefault(q.Get("limit"), 100)
	offset = atoiDefault(q.Get("offset"), 0)
	if limit < 1 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// ---------- static ----------

// StaticFiles serves the browser client; defaults to ./web on disk,
// overridden by the server binary with the embedded copy.
var StaticFiles fs.FS = os.DirFS("web")

func (s *Server) staticHandler() http.Handler {
	if StaticFiles == nil {
		StaticFiles = os.DirFS("web")
	}
	fs := http.FileServer(http.FS(StaticFiles))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if strings.Contains(p, "..") {
			http.NotFound(w, r)
			return
		}
		if p == "" {
			p = "index.html"
		}
		fs.ServeHTTP(w, r)
	})
}

var _ = slog.LevelInfo
var _ = model.MaxMessageBytes
