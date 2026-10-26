// Package server wires the GoChat REST API, WebSocket endpoint, broker
// fan-out and storage together.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Sh4wnK/GoChat/internal/auth"
	"github.com/Sh4wnK/GoChat/internal/broker"
	"github.com/Sh4wnK/GoChat/internal/hub"
	"github.com/Sh4wnK/GoChat/internal/model"
	"github.com/Sh4wnK/GoChat/internal/protocol"
	"github.com/Sh4wnK/GoChat/internal/room"
	"github.com/Sh4wnK/GoChat/internal/userstore"
	"github.com/coder/websocket"
	"github.com/google/uuid"
)

// Service is the core node: it owns the hub, fan-out decisions, message
// validation, rate limiting and cross-node publish. It is embedded in
// Server (HTTP+WS wiring) and drives the broker pump.
type Service struct {
	NodeID string
	Hub    *hub.Hub
	Rooms  *room.Manager
	Store  userstore.Store
	Signer *auth.Signer
	Log    *slog.Logger
	B      broker.Broker

	ctx    context.Context
	cancel context.CancelFunc

	// wsConns maps hub connections to their websocket handles so the
	// server can force-close sessions (account deletion, slow consumer).
	wsMu    sync.Mutex
	wsConns map[*hub.Conn]*websocket.Conn

	rateMu   sync.Mutex
	msgLast  map[string]time.Time // userID -> last accepted message
	typingAt map[string]time.Time // "room:user" -> last typing broadcast
}

// newService builds the node service and starts the broker pump. The
// returned service owns the given broker only if createBroker is true.
func newService(ctx context.Context, cfg Config, b broker.Broker) *Service {
	nodeID := cfg.NodeID
	if nodeID == "" {
		nodeID = b.NodeID()
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	if cfg.Signer == nil {
		return nil
	}
	if cfg.Store == nil {
		return nil
	}
	if cfg.Rooms == nil {
		cfg.Rooms = room.NewManager()
	}
	rooms := cfg.Rooms
	if cfg.HubCfg == nil {
		cfg.HubCfg = &hub.Config{}
	}
	h := hub.New(rooms, log, *cfg.HubCfg)
	ctx, cancel := context.WithCancel(ctx)
	s := &Service{
		NodeID:   nodeID,
		Hub:      h,
		Rooms:    rooms,
		Store:    cfg.Store,
		Signer:   cfg.Signer,
		Log:      log,
		B:        b,
		ctx:      ctx,
		cancel:   cancel,
		wsConns:  make(map[*hub.Conn]*websocket.Conn),
		msgLast:  make(map[string]time.Time),
		typingAt: make(map[string]time.Time),
	}
	// Slow consumer eviction: force-close the websocket and announce
	// leave presence for the rooms the user dropped.
	hubCfg := *cfg.HubCfg
	hubCfg.OnDrop = func(c *hub.Conn, dropped []string) {
		s.wsForceClose(c)
		for _, name := range dropped {
			s.announcePresence(name, c.User, "leave", c)
		}
	}
	h = hub.New(rooms, log, hubCfg)
	s.Hub = h
	s.startBrokerPump()
	return s
}

// Cancel stops the background broker pump.
func (s *Service) Cancel() { s.cancel() }

// startBrokerPump routes frames from peer nodes.
func (s *Service) startBrokerPump() {
	if s.B == nil {
		return
	}
	sub := s.B.Subscribe(s.ctx)
	go func() {
		for {
			select {
			case <-s.ctx.Done():
				return
			case m, ok := <-sub:
				if !ok {
					return
				}
				if m.Err != nil {
					s.Log.Warn("broker frame error", "err", m.Err)
					continue
				}
				if m.Origin == s.NodeID {
					continue // never process our own publishes
				}
				s.handleRemote(m.Message)
			}
		}
	}()
}

func (s *Service) handleRemote(m broker.Message) {
	switch m.Kind {
	case "chat":
		s.deliverRoom(m)
	case "dm":
		delivered := s.deliverDM(m)
		if delivered == 0 {
			// Deduplicated by message ID in every store: exactly one
			// node wins the offline insert.
			_ = s.enqueueOffline(m)
		}
	case "presence", "typing":
		s.forwardEvent(m)
	case "room":
		s.applyRoomEvent(m)
	}
}

// forwardEvent rebroadcasts a presence/typing frame to local subscribers.
func (s *Service) forwardEvent(m broker.Message) {
	s.Hub.BroadcastRaw(m.Channel, m.Payload, nil)
}

// applyRoomEvent applies a room lifecycle event from a peer node.
func (s *Service) applyRoomEvent(m broker.Message) {
	var ev model.RoomEvent
	if err := json.Unmarshal(m.Payload, &ev); err != nil {
		return
	}
	switch ev.Type {
	case "created":
		_, _ = s.Rooms.CreateRoom(ev.RoomName, "")
	case "deleted":
		_ = s.Rooms.DeleteRoom(ev.RoomName)
	}
	s.Hub.BroadcastAllRaw(m.Payload, nil)
}

// deliverRoom broadcasts a remote room message frame to local
// subscribers and appends it to local history.
func (s *Service) deliverRoom(m broker.Message) {
	var msg model.Message
	if err := json.Unmarshal(m.Payload, &msg); err != nil {
		return
	}
	_ = msg
	s.Rooms.AppendHistory(m.Channel, protocolMsg(m.Payload))
	s.Hub.BroadcastRaw(m.Channel, m.Payload, nil)
}

// protocolMsg decodes the protocol.Message inside a broadcast frame.
func protocolMsg(framePayload json.RawMessage) model.Message {
	var frame struct {
		Type string           `json:"type"`
		Data protocol.Message `json:"data"`
	}
	if err := json.Unmarshal(framePayload, &frame); err != nil {
		return model.Message{}
	}
	return model.Message{
		ID: frame.Data.ID, Kind: frame.Data.Kind, Room: frame.Data.Room,
		Sender: frame.Data.Sender, SenderName: frame.Data.SenderName,
		Recipient: frame.Data.Recipient, Body: frame.Data.Body,
		CreatedAt: frame.Data.CreatedAt,
	}
}

// deliverDM routes a DM to the recipient's local sessions. Returns the
// number of sessions that accepted it.
func (s *Service) deliverDM(m broker.Message) int {
	var msg model.Message
	if err := json.Unmarshal(m.Payload, &msg); err != nil {
		return 0
	}
	return s.Hub.SendToUserRaw(msg.Recipient, m.Payload)
}

func (s *Service) enqueueOffline(m broker.Message) error {
	var frame struct {
		Type string           `json:"type"`
		Data protocol.Message `json:"data"`
	}
	if err := json.Unmarshal(m.Payload, &frame); err != nil {
		return err
	}
	payload, _ := json.Marshal(frame.Data)
	return s.Store.EnqueueOffline(s.ctx, frame.Data.Recipient, frame.Data.ID, string(payload))
}

// announcePresence broadcasts a join/leave presence event locally and
// publishes it so peer nodes forward it to their subscribers.
func (s *Service) announcePresence(name string, u model.User, typ string, skip *hub.Conn) {
	frame := protocol.Frame{
		Type: protocol.EvPresence,
		Data: mustJSON(protocol.Presence{Type: typ, Room: name, User: protocolUser(u)}),
	}
	payload := mustJSON(frame)
	s.Hub.BroadcastRaw(name, payload, skip)
	if s.B != nil {
		_ = s.B.Publish(s.ctx, broker.Message{
			Channel: "room:" + name,
			Kind:    "presence",
			Payload: payload,
			Origin:  s.NodeID,
		})
	}
}

// publishRoomChat broadcasts a room message locally (echoed to the
// sender so every session shows sent messages) and to peers.
func (s *Service) publishRoomChat(msg model.Message) {
	frame := protocol.Frame{Type: protocol.EvMessage, Data: mustJSON(protocolMessage(msg))}
	payload := mustJSON(frame)
	s.Rooms.AppendHistory(msg.Room, msg)
	s.Hub.BroadcastRaw(msg.Room, payload, nil)
	if s.B != nil {
		_ = s.B.Publish(s.ctx, broker.Message{
			Channel: "room:" + msg.Room,
			Kind:    "chat",
			Payload: payload,
			Origin:  s.NodeID,
		})
	}
}

// routeDM delivers a DM to the recipient's sessions plus the sender's
// own sessions (so senders see their sent DMs on every device),
// publishes it for peer nodes, and falls back to the offline queue when
// the recipient is not online anywhere.
func (s *Service) routeDM(msg model.Message) {
	frame := protocol.Frame{Type: protocol.EvDm, Data: mustJSON(protocolMessage(msg))}
	payload := mustJSON(frame)
	delivered := s.Hub.SendToUserRaw(msg.Recipient, payload)
	if msg.Sender != msg.Recipient {
		s.Hub.SendToUserRaw(msg.Sender, payload) // echo to the sender
	}
	if s.B != nil {
		_ = s.B.Publish(s.ctx, broker.Message{
			Channel: "user:" + msg.Recipient,
			Kind:    "dm",
			Payload: payload,
			Origin:  s.NodeID,
		})
	}
	if delivered == 0 {
		// Everyone online on other nodes also saw zero sessions; the
		// unique (user_id, message_id) constraint makes the enqueue
		// idempotent across nodes.
		_ = s.Store.EnqueueOffline(s.ctx, msg.Recipient, msg.ID, string(mustJSON(protocolMessage(msg))))
	}
}

// rateMessage enforces the per-user message rate limit (5/s).
func (s *Service) rateMessage(userID string) bool {
	now := time.Now()
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	last, ok := s.msgLast[userID]
	if ok && now.Sub(last) < 200*time.Millisecond {
		return false
	}
	s.msgLast[userID] = now
	return true
}

// rateTyping enforces one typing broadcast per user per room per 2s.
func (s *Service) rateTyping(roomID, userID string) bool {
	now := time.Now()
	key := roomID + ":" + userID
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	last, ok := s.typingAt[key]
	if ok && now.Sub(last) < 2*time.Second {
		return false
	}
	s.typingAt[key] = now
	return true
}

// wsRegister stores the websocket handle for a hub connection.
func (s *Service) wsRegister(c *hub.Conn, ws *websocket.Conn) {
	s.wsMu.Lock()
	s.wsConns[c] = ws
	s.wsMu.Unlock()
}

// wsUnregister removes the websocket handle.
func (s *Service) wsUnregister(c *hub.Conn) {
	s.wsMu.Lock()
	delete(s.wsConns, c)
	s.wsMu.Unlock()
}

// wsForceClose closes the websocket behind a hub connection.
func (s *Service) wsForceClose(c *hub.Conn) {
	s.wsMu.Lock()
	ws := s.wsConns[c]
	s.wsMu.Unlock()
	if ws != nil {
		_ = ws.Close(websocket.StatusPolicyViolation, "slow consumer")
	}
}

// sendRaw enqueues a pre-encoded frame reply to a connection.
func (s *Service) sendRaw(c *hub.Conn, frame any) {
	payload := mustJSON(frame)
	s.Hub.SendToRaw(c, payload)
}

// mustJSON marshals a statically-known value, panicking on failure.
func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("server: marshal %T: %v", v, err))
	}
	return b
}

// newMessageID returns a unique message identifier (offline-queue
// dedup key).
func newMessageID() string { return uuid.NewString() }

var errRoomNotFound = room.ErrRoomNotFound

var _ = errors.Is
var _ = auth.ErrInvalidToken
