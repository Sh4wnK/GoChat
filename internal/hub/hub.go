// Package hub implements the in-process WebSocket hub. It owns room
// subscription state, fans broadcast frames out to room subscribers,
// delivers direct messages to every session of a user, and evicts slow
// consumers whose outbound queue has filled.
//
// The hub deals exclusively in pre-encoded payloads: the server
// serializes protocol frames and hands them to the hub, which is the
// single writer for every subscriber's outbound queue. Fan-out follows
// a shared-channel pattern (one bounded channel per connection), so the
// network writer goroutines never contend on the connection itself.
package hub

import (
	"errors"
	"log/slog"
	"sync"

	"github.com/Sh4wnK/GoChat/internal/model"
	"github.com/Sh4wnK/GoChat/internal/room"
)

// SlowConsumerMax is the default outbound queue bound per connection.
const SlowConsumerMax = 256

// ErrNotSubscribed is returned by operations targeting a room the
// connection is not subscribed to.
var ErrNotSubscribed = errors.New("not subscribed to room")

// Config tunes hub behavior.
type Config struct {
	// HistoryLimit bounds the per-room history kept by the room manager
	// (0 = room.HistoryLimit).
	HistoryLimit int
	// SlowConsumerMax bounds each connection's outbound queue
	// (0 = SlowConsumerMax).
	SlowConsumerMax int
	// OnDrop is invoked when a connection is evicted as a slow
	// consumer. The second argument lists the rooms whose membership the
	// user dropped by being evicted (leave presence should be
	// announced). Called in a goroutine; may be nil.
	OnDrop func(*Conn, []string)
}

// Hub routes payloads between subscribers.
type Hub struct {
	cfg   Config
	log   *slog.Logger
	rooms *room.Manager
	mu    sync.RWMutex
	conns map[string]map[*Conn]struct{} // userID -> connections
	subs  map[string]map[*Conn]struct{} // room -> connections
	next  int64
}

// New creates a Hub over the given room manager.
func New(rooms *room.Manager, log *slog.Logger, cfg Config) *Hub {
	if cfg.HistoryLimit <= 0 {
		cfg.HistoryLimit = room.HistoryLimit
	}
	if cfg.SlowConsumerMax <= 0 {
		cfg.SlowConsumerMax = SlowConsumerMax
	}
	return &Hub{
		cfg:   cfg,
		log:   log,
		rooms: rooms,
		conns: make(map[string]map[*Conn]struct{}),
		subs:  make(map[string]map[*Conn]struct{}),
	}
}

// Conn is a subscriber connection. Payloads are delivered on Out.
type Conn struct {
	ID   int64
	User model.User
	hub  *Hub
	out  chan []byte
	done chan struct{}
	once sync.Once
}

// Done is closed by the owning goroutine when the connection ends.
func (c *Conn) Done() <-chan struct{} { return c.done }

// CloseDone idempotently closes Done.
func (c *Conn) CloseDone() { c.once.Do(func() { close(c.done) }) }

// Out exposes the outbound queue of pre-encoded payloads.
func (c *Conn) Out() <-chan []byte { return c.out }

// Register adds a connection for a user and returns it.
func (h *Hub) Register(u model.User) *Conn {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.next++
	c := &Conn{
		ID:   h.next,
		User: u,
		hub:  h,
		out:  make(chan []byte, h.cfg.SlowConsumerMax),
		done: make(chan struct{}),
	}
	if h.conns[u.ID] == nil {
		h.conns[u.ID] = make(map[*Conn]struct{})
	}
	h.conns[u.ID][c] = struct{}{}
	return c
}

// Join subscribes a connection to a room, adding the user to room
// membership when this is their first session in the room. It returns
// the current member list, the bounded recent history (oldest first),
// and whether the user newly joined (a join presence event should be
// announced). Presence events are the caller's responsibility.
func (h *Hub) Join(name string, c *Conn) (members []model.User, history []model.Message, joinedNew bool, err error) {
	members, err = h.rooms.Members(name)
	if err != nil {
		return nil, nil, false, err // room does not exist
	}
	joinedNew = true
	for _, m := range members {
		if m.ID == c.User.ID {
			joinedNew = false
			break
		}
	}
	if joinedNew {
		if _, _, err := h.rooms.Join(name, c.User); err != nil {
			return nil, nil, false, err
		}
	}
	h.mu.Lock()
	if h.subs[name] == nil {
		h.subs[name] = make(map[*Conn]struct{})
	}
	h.subs[name][c] = struct{}{}
	h.mu.Unlock()
	members, _ = h.rooms.Members(name)
	history, _ = h.rooms.History(name)
	return members, history, joinedNew, nil
}

// Leave unsubscribes a connection from a room, dropping the user's
// membership when this was their last session there. It reports whether
// membership was dropped (a leave presence event should be announced).
func (h *Hub) Leave(name string, c *Conn) (dropped bool, err error) {
	h.mu.Lock()
	set, ok := h.subs[name]
	if !ok {
		h.mu.Unlock()
		return false, ErrNotSubscribed
	}
	if _, present := set[c]; !present {
		h.mu.Unlock()
		return false, ErrNotSubscribed
	}
	delete(set, c)
	if len(set) == 0 {
		delete(h.subs, name)
	}
	dropped = h.lastSessionLocked(name, c.User.ID)
	h.mu.Unlock()
	if !dropped {
		return false, nil
	}
	if err := h.rooms.Leave(name, c.User.ID); err != nil && !errors.Is(err, room.ErrRoomNotFound) {
		return true, err
	}
	return true, nil
}

// Disconnect removes a connection from the hub entirely. It returns the
// rooms whose membership the user dropped, so the caller can announce
// leave presence. Safe to call more than once (second call returns nil).
func (h *Hub) Disconnect(c *Conn) []string {
	h.mu.Lock()
	_, registered := h.conns[c.User.ID][c]
	if !registered {
		h.mu.Unlock()
		return nil
	}
	var dropped []string
	delete(h.conns[c.User.ID], c)
	if len(h.conns[c.User.ID]) == 0 {
		delete(h.conns, c.User.ID)
	}
	for name, set := range h.subs {
		if _, ok := set[c]; !ok {
			continue
		}
		delete(set, c)
		if len(set) == 0 {
			delete(h.subs, name)
		}
		if h.lastSessionLocked(name, c.User.ID) {
			dropped = append(dropped, name)
		}
	}
	h.mu.Unlock()
	for _, name := range dropped {
		_ = h.rooms.Leave(name, c.User.ID) // tolerate room already deleted
	}
	return dropped
}

// DisconnectUser removes every session of a user. Returns the rooms
// whose membership was dropped (deduplicated).
func (h *Hub) DisconnectUser(u model.User) []string {
	var rooms []string
	seen := make(map[string]struct{})
	for _, c := range h.Connections(u.ID) {
		for _, r := range h.Disconnect(c) {
			if _, ok := seen[r]; !ok {
				seen[r] = struct{}{}
				rooms = append(rooms, r)
			}
		}
	}
	return rooms
}

// Connections returns the live connections of a user.
func (h *Hub) Connections(userID string) []*Conn {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]*Conn, 0, len(h.conns[userID]))
	for c := range h.conns[userID] {
		out = append(out, c)
	}
	return out
}

// Connected reports whether the user has at least one live session.
func (h *Hub) Connected(userID string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.conns[userID]) > 0
}

// EvictRoom removes every subscription of a room (used when the room
// is deleted; membership and history are already gone).
func (h *Hub) EvictRoom(name string) {
	h.mu.Lock()
	delete(h.subs, name)
	h.mu.Unlock()
}

// Subscribers returns the number of live subscriptions in a room.
func (h *Hub) Subscribers(name string) int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.subs[name])
}

// BroadcastRaw fans a pre-encoded payload out to every subscriber of a
// room except skip.
func (h *Hub) BroadcastRaw(name string, payload []byte, skip *Conn) {
	h.mu.RLock()
	conns := make([]*Conn, 0, len(h.subs[name]))
	for c := range h.subs[name] {
		if c != skip {
			conns = append(conns, c)
		}
	}
	h.mu.RUnlock()
	for _, c := range conns {
		h.deliver(c, payload)
	}
}

// BroadcastAllRaw fans a pre-encoded payload out to every connection
// except skip.
func (h *Hub) BroadcastAllRaw(payload []byte, skip *Conn) {
	h.mu.RLock()
	conns := make([]*Conn, 0, len(h.conns))
	for _, set := range h.conns {
		for c := range set {
			if c != skip {
				conns = append(conns, c)
			}
		}
	}
	h.mu.RUnlock()
	for _, c := range conns {
		h.deliver(c, payload)
	}
}

// SendToUserRaw delivers a pre-encoded payload to every session of a
// user. Returns the number of sessions that accepted it (0 = offline).
func (h *Hub) SendToUserRaw(userID string, payload []byte) int {
	h.mu.RLock()
	conns := make([]*Conn, 0, len(h.conns[userID]))
	for c := range h.conns[userID] {
		conns = append(conns, c)
	}
	h.mu.RUnlock()
	delivered := 0
	for _, c := range conns {
		if h.deliver(c, payload) {
			delivered++
		}
	}
	return delivered
}

// SendToRaw delivers a pre-encoded payload to a specific connection.
// Used for command replies.
func (h *Hub) SendToRaw(c *Conn, payload []byte) bool {
	return h.deliver(c, payload)
}

// deliver enqueues a payload to a connection's bounded queue. When the
// queue is full the connection is an evicted slow consumer: it is
// removed from every hub map, OnDrop is invoked with the rooms whose
// membership dropped, and false is returned.
func (h *Hub) deliver(c *Conn, payload []byte) bool {
	h.mu.Lock()
	if _, ok := h.conns[c.User.ID][c]; !ok {
		h.mu.Unlock()
		return false
	}
	select {
	case c.out <- payload:
		h.mu.Unlock()
		return true
	default:
	}
	// Slow consumer: evict without blocking.
	var dropped []string
	delete(h.conns[c.User.ID], c)
	if len(h.conns[c.User.ID]) == 0 {
		delete(h.conns, c.User.ID)
	}
	for name, set := range h.subs {
		if _, ok := set[c]; !ok {
			continue
		}
		delete(set, c)
		if len(set) == 0 {
			delete(h.subs, name)
		}
		if h.lastSessionLocked(name, c.User.ID) {
			dropped = append(dropped, name)
		}
	}
	onDrop := h.cfg.OnDrop
	h.mu.Unlock()
	if h.log != nil {
		h.log.Warn("evicting slow consumer", "conn", c.ID, "user", c.User.ID, "queue", len(c.out))
	}
	for _, name := range dropped {
		_ = h.rooms.Leave(name, c.User.ID)
	}
	if onDrop != nil {
		go onDrop(c, dropped)
	}
	return false
}

// lastSessionLocked reports whether the user has no more connections in
// the room. Callers must hold h.mu.
func (h *Hub) lastSessionLocked(name, userID string) bool {
	if set, ok := h.subs[name]; ok {
		for other := range set {
			if other.User.ID == userID {
				return false
			}
		}
	}
	return true
}
