// Package userstore defines the UserStore interface and an in-memory
// implementation used by default and in tests.
package userstore

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/Sh4wnK/GoChat/internal/model"
)

var (
	// ErrNotFound is returned when a user does not exist.
	ErrNotFound = errors.New("user not found")
	// ErrUsernameTaken is returned when signing up with a taken username.
	ErrUsernameTaken = errors.New("username already taken")
	// ErrBadCredentials is returned on login with a wrong password.
	ErrBadCredentials = errors.New("invalid credentials")
)

// UserRecord is a stored user including the password hash and public key.
type UserRecord struct {
	User      model.User
	Password  []byte // argon2id hash, never plaintext
	PublicKey string // base64 X25519 public key, "" when unset
	Enabled   bool
}

// Store persists users and their offline message queues.
type Store interface {
	CreateUser(ctx context.Context, username, displayName string, passwordHash []byte) (model.User, error)
	GetUserByName(ctx context.Context, username string) (UserRecord, error)
	GetUserByID(ctx context.Context, id string) (UserRecord, error)
	ListUsers(ctx context.Context, limit, offset int) ([]model.User, error)
	UpdateProfile(ctx context.Context, id, displayName string) error
	SetPublicKey(ctx context.Context, id, key string) error
	SetEnabled(ctx context.Context, id string, enabled bool) error
	DeleteUser(ctx context.Context, id string) error
	EnqueueOffline(ctx context.Context, userID, messageID, payload string) error
	PopOffline(ctx context.Context, userID string) ([]string, error)
}

// InMemory is a mutex-guarded in-memory Store. Not safe to copy.
type InMemory struct {
	mu      sync.RWMutex
	byID    map[string]UserRecord
	byName  map[string]string
	offline map[string][]offlineEntry
	nextID  int
}

// NewInMemory returns an empty in-memory store.
func NewInMemory() *InMemory {
	return &InMemory{
		byID:    make(map[string]UserRecord),
		byName:  make(map[string]string),
		offline: make(map[string][]offlineEntry),
	}
}

func (s *InMemory) CreateUser(_ context.Context, username, displayName string, passwordHash []byte) (model.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byName[username]; ok {
		return model.User{}, ErrUsernameTaken
	}
	s.nextID++
	u := model.User{
		ID:          "u" + itoa(s.nextID),
		Username:    username,
		DisplayName: displayName,
		CreatedAt:   time.Now().UTC(),
	}
	s.byID[u.ID] = UserRecord{User: u, Password: append([]byte(nil), passwordHash...), Enabled: true}
	s.byName[username] = u.ID
	return u, nil
}

func (s *InMemory) GetUserByName(_ context.Context, username string) (UserRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byName[username]
	if !ok {
		return UserRecord{}, ErrNotFound
	}
	return s.getLocked(id)
}

func (s *InMemory) GetUserByID(_ context.Context, id string) (UserRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getLocked(id)
}

func (s *InMemory) getLocked(id string) (UserRecord, error) {
	rec, ok := s.byID[id]
	if !ok {
		return UserRecord{}, ErrNotFound
	}
	rec.Password = append([]byte(nil), rec.Password...)
	return rec, nil
}

func (s *InMemory) ListUsers(_ context.Context, limit, offset int) ([]model.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.User, 0, len(s.byID))
	for _, rec := range s.byID {
		out = append(out, rec.User)
	}
	// Deterministic order by ID.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].ID < out[j-1].ID; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	if offset > len(out) {
		offset = len(out)
	}
	out = out[offset:]
	if limit > 0 && limit < len(out) {
		out = out[:limit]
	}
	return out, nil
}

func (s *InMemory) UpdateProfile(_ context.Context, id, displayName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byID[id]
	if !ok {
		return ErrNotFound
	}
	rec.User.DisplayName = displayName
	s.byID[id] = rec
	return nil
}

func (s *InMemory) SetPublicKey(_ context.Context, id, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byID[id]
	if !ok {
		return ErrNotFound
	}
	rec.PublicKey = key
	rec.User.PublicKey = key
	s.byID[id] = rec
	return nil
}

func (s *InMemory) SetEnabled(_ context.Context, id string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byID[id]
	if !ok {
		return ErrNotFound
	}
	rec.Enabled = enabled
	s.byID[id] = rec
	return nil
}

func (s *InMemory) DeleteUser(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byID[id]
	if !ok {
		return ErrNotFound
	}
	delete(s.byID, id)
	delete(s.byName, rec.User.Username)
	delete(s.offline, id)
	return nil
}

func (s *InMemory) EnqueueOffline(_ context.Context, userID, messageID, payload string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.offline[userID] {
		if e.id == messageID {
			return nil // dedup: this message was already queued
		}
	}
	s.offline[userID] = append(s.offline[userID], offlineEntry{id: messageID, payload: payload})
	return nil
}

// offlineEntry is one queued message plus its dedup id.
type offlineEntry struct {
	id      string
	payload string
}

func (s *InMemory) PopOffline(_ context.Context, userID string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries := s.offline[userID]
	delete(s.offline, userID)
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.payload)
	}
	return out, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
