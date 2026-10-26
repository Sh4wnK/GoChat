package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Sh4wnK/GoChat/internal/protocol"
	"github.com/coder/websocket"
)

// Session is a live WebSocket session. Events are delivered on the
// returned channel; the channel is closed when the connection ends.
type Session struct {
	Events <-chan protocol.Frame

	conn  *websocket.Conn
	done  chan struct{}
	once  sync.Once
	proto sync.Mutex // serializes writes
}

// Dial opens an authenticated WebSocket session. It blocks until the
// server sends its welcome frame (or the context expires).
func (c *Client) Dial(ctx context.Context, token string) (*Session, error) {
	if token == "" {
		token = c.apiKey
	}
	if token == "" {
		return nil, errors.New("client: authentication required (login first or pass a token)")
	}
	wsURL := c.BaseURL
	if len(wsURL) > 5 && wsURL[:5] == "http:" {
		wsURL = "ws:" + wsURL[5:]
	} else if len(wsURL) > 6 && wsURL[:6] == "https:" {
		wsURL = "wss:" + wsURL[6:]
	} else if !hasWScheme(wsURL) {
		wsURL = "ws://" + wsURL
	}
	conn, resp, err := websocket.Dial(ctx, wsURL+"/ws", nil)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("client: dial %s: %s", wsURL+"/ws", resp.Status)
		}
		return nil, err
	}
	// Authenticate as the first frame.
	auth, _ := json.Marshal(protocol.AuthRequest{Token: token})
	if err := conn.Write(ctx, websocket.MessageText, auth); err != nil {
		conn.Close(websocket.StatusInternalError, "auth write failed")
		return nil, err
	}
	// Wait for welcome.
	_, data, err := conn.Read(ctx)
	if err != nil {
		conn.Close(websocket.StatusNormalClosure, "")
		return nil, fmt.Errorf("client: no welcome frame: %w", err)
	}
	var frame protocol.Frame
	if err := json.Unmarshal(data, &frame); err != nil || frame.Type != protocol.EvWelcome {
		conn.Close(websocket.StatusNormalClosure, "")
		return nil, errors.New("client: expected welcome frame")
	}

	events := make(chan protocol.Frame, 64)
	s := &Session{Events: events, conn: conn, done: make(chan struct{})}
	go s.readLoop(events)
	return s, nil
}

func hasWScheme(u string) bool {
	return len(u) > 2 && (u[:2] == "ws" || u[:3] == "ws:" || u[:4] == "wss:")
}

func (s *Session) readLoop(events chan<- protocol.Frame) {
	defer close(events)
	defer s.Close()
	for {
		_, data, err := s.conn.Read(context.Background())
		if err != nil {
			return
		}
		if len(data) > 1<<20 {
			return
		}
		var frame protocol.Frame
		if err := json.Unmarshal(data, &frame); err != nil {
			continue // ignore malformed frames
		}
		select {
		case events <- frame:
		default:
			return // client is the slow consumer: drop connection
		}
	}
}

func (s *Session) send(ctx context.Context, frame protocol.Frame) error {
	data, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	s.proto.Lock()
	defer s.proto.Unlock()
	return s.conn.Write(ctx, websocket.MessageText, data)
}

// Close terminates the session.
func (s *Session) Close() {
	s.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		select {
		case <-s.done:
		case <-ctx.Done():
		}
		_ = s.conn.Close(websocket.StatusNormalClosure, "")
	})
}

// SendMessage sends a chat message to a room, or a DM when recipient is
// non-empty. Messages are rate-limited server-side to one per 200ms.
func (s *Session) SendMessage(ctx context.Context, room, recipient, body string) error {
	return s.send(ctx, protocol.Frame{
		Type: protocol.CmdMessage,
		Data: mustJSON(protocol.ChatMessage{Room: room, Recipient: recipient, Body: body}),
	})
}

// Join subscribes to a room. Returns the room's members and recent
// history via the joined reply (handled by the server before any later
// frames).
func (s *Session) Join(ctx context.Context, room string) error {
	return s.send(ctx, protocol.Frame{Type: protocol.CmdJoin, Data: mustJSON(protocol.Join{Room: room})})
}

// Leave unsubscribes from a room.
func (s *Session) Leave(ctx context.Context, room string) error {
	return s.send(ctx, protocol.Frame{Type: protocol.CmdLeave, Data: mustJSON(protocol.Leave{Room: room})})
}

// Typing sends a typing indicator for a room.
func (s *Session) Typing(ctx context.Context, room string, active bool) error {
	return s.send(ctx, protocol.Frame{Type: protocol.CmdTyping, Data: mustJSON(protocol.Typing{Room: room, Active: active})})
}

// CreateRoom requests a new room.
func (s *Session) CreateRoom(ctx context.Context, name, topic string) error {
	return s.send(ctx, protocol.Frame{Type: protocol.CmdCreateRoom, Data: mustJSON(protocol.CreateRoom{Name: name, Topic: topic})})
}

// DeleteRoom requests room deletion.
func (s *Session) DeleteRoom(ctx context.Context, name string) error {
	return s.send(ctx, protocol.Frame{Type: protocol.CmdDeleteRoom, Data: mustJSON(protocol.DeleteRoom{Name: name})})
}

// ListRooms requests the room list.
func (s *Session) ListRooms(ctx context.Context) error {
	return s.send(ctx, protocol.Frame{Type: protocol.CmdRoomList, Data: json.RawMessage("{}")})
}

// RoomHistory requests a room's recent history.
func (s *Session) RoomHistory(ctx context.Context, room string) error {
	return s.send(ctx, protocol.Frame{Type: protocol.CmdRoomHistory, Data: mustJSON(protocol.Join{Room: room})})
}

// Ping sends a keepalive ping.
func (s *Session) Ping(ctx context.Context) error {
	return s.send(ctx, protocol.Frame{Type: "ping", Data: json.RawMessage("{}")})
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

var _ = http.MethodGet // keep net/http in the import set for docs
var _ = bytes.NewReader
