package room

import (
	"errors"
	"sync"
	"time"

	"github.com/Sh4wnK/GoChat/internal/model"
)

const (
	// HistoryLimit is the maximum number of messages kept per room.
	HistoryLimit = 200
	// PresenceLimit bounds the member list sent in room state to keep
	// join payloads small for very large rooms.
	PresenceLimit = 500
)

var (
	ErrRoomExists    = errors.New("room already exists")
	ErrRoomNotFound  = errors.New("room not found")
	ErrAlreadyMember = errors.New("user already in room")
	ErrNotMember     = errors.New("user is not a member of the room")
)

// Manager tracks rooms, their memberships, and bounded message history.
// The zero value is not usable; use NewManager.
//
// Manager is safe for concurrent use.
type Manager struct {
	mu      sync.RWMutex
	rooms   map[string]*roomState
	ordered []string // room names in creation order
}

type roomState struct {
	topic    string
	created  time.Time
	members  map[string]model.User
	messages []model.Message
}

// NewManager returns an empty room manager.
func NewManager() *Manager {
	return &Manager{rooms: make(map[string]*roomState)}
}

// CreateRoom adds a room. Returns ErrRoomExists if the name is taken.
func (m *Manager) CreateRoom(name, topic string) (model.Room, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.rooms[name]; ok {
		return model.Room{}, ErrRoomExists
	}
	now := time.Now().UTC()
	m.rooms[name] = &roomState{
		topic:   topic,
		created: now,
		members: make(map[string]model.User),
	}
	m.ordered = append(m.ordered, name)
	return model.Room{Name: name, Topic: topic, CreatedAt: now}, nil
}

// DeleteRoom removes a room and all of its history.
func (m *Manager) DeleteRoom(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.rooms[name]; !ok {
		return ErrRoomNotFound
	}
	delete(m.rooms, name)
	for i, n := range m.ordered {
		if n == name {
			m.ordered = append(m.ordered[:i], m.ordered[i+1:]...)
			break
		}
	}
	return nil
}

// Get returns a room by name.
func (m *Manager) Get(name string) (model.Room, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.rooms[name]
	if !ok {
		return model.Room{}, ErrRoomNotFound
	}
	return model.Room{Name: name, Topic: r.topic, CreatedAt: r.created}, nil
}

// List returns all rooms in creation order.
func (m *Manager) List() []model.Room {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.Room, 0, len(m.ordered))
	for _, name := range m.ordered {
		if r, ok := m.rooms[name]; ok {
			out = append(out, model.Room{Name: name, Topic: r.topic, CreatedAt: r.created})
		}
	}
	return out
}

// Join adds a user to a room and returns the current membership and
// recent history. Returns ErrAlreadyMember if the user is present.
func (m *Manager) Join(room string, u model.User) ([]model.User, []model.Message, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rooms[room]
	if !ok {
		return nil, nil, ErrRoomNotFound
	}
	if _, ok := r.members[u.ID]; ok {
		return nil, nil, ErrAlreadyMember
	}
	r.members[u.ID] = u
	return memberList(r), history(r), nil
}

// Leave removes a user from a room. Returns ErrNotMember when the user
// is not present.
func (m *Manager) Leave(room, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rooms[room]
	if !ok {
		return ErrRoomNotFound
	}
	if _, ok := r.members[userID]; !ok {
		return ErrNotMember
	}
	delete(r.members, userID)
	return nil
}

// Members returns the member list of a room.
func (m *Manager) Members(room string) ([]model.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.rooms[room]
	if !ok {
		return nil, ErrRoomNotFound
	}
	return memberList(r), nil
}

// IsMember reports whether the user is in the room.
func (m *Manager) IsMember(room, userID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.rooms[room]
	if !ok {
		return false
	}
	_, ok = r.members[userID]
	return ok
}

// AppendHistory adds a message to a room's bounded history, evicting
// the oldest messages beyond HistoryLimit.
func (m *Manager) AppendHistory(room string, msg model.Message) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rooms[room]
	if !ok {
		return
	}
	r.messages = append(r.messages, msg)
	if len(r.messages) > HistoryLimit {
		r.messages = r.messages[len(r.messages)-HistoryLimit:]
	}
}

// History returns the recent history of a room, oldest first.
func (m *Manager) History(room string) ([]model.Message, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.rooms[room]
	if !ok {
		return nil, ErrRoomNotFound
	}
	return history(r), nil
}

func memberList(r *roomState) []model.User {
	out := make([]model.User, 0, len(r.members))
	// Iteration order is random; users are re-sorted for stable output.
	for _, u := range r.members {
		out = append(out, u)
	}
	// Stable ordering by ID keeps replies deterministic for tests.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].ID < out[j-1].ID; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	if len(out) > PresenceLimit {
		out = out[:PresenceLimit]
	}
	return out
}

func history(r *roomState) []model.Message {
	out := make([]model.Message, len(r.messages))
	copy(out, r.messages)
	return out
}
