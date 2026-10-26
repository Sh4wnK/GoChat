package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Sh4wnK/GoChat/internal/broker"
	"github.com/Sh4wnK/GoChat/internal/hub"
	"github.com/Sh4wnK/GoChat/internal/model"
	"github.com/Sh4wnK/GoChat/internal/protocol"
	"github.com/Sh4wnK/GoChat/internal/room"
	"github.com/coder/websocket"
)

const (
	wsReadLimit    = 1 << 20 // 1 MiB max frame
	wsWriteWait    = 10 * time.Second
	wsPongWait     = 60 * time.Second
	wsPingPeriod   = 30 * time.Second
	maxDMPlaintext = 256 // advisory cap documented for clients
)

// handleWS upgrades the connection, authenticates the first frame and
// runs the session until it ends.
func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	// Origin check: browsers must come from an allowed origin.
	origin := r.Header.Get("Origin")
	if origin != "" && !s.originAllowed(origin) {
		s.Log.Warn("ws origin rejected", "origin", origin)
		http.Error(w, "forbidden origin", http.StatusForbidden)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns:     s.originPatterns(),
		InsecureSkipVerify: true,
		CompressionMode:    websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	s.serveWS(conn, r.Context())
}

func (s *Server) originAllowed(origin string) bool {
	for _, a := range s.cfg.AllowedOrigins {
		if a == "*" || strings.EqualFold(a, origin) {
			return true
		}
	}
	// Loopback origins are always fine for the load tester.
	return strings.HasPrefix(origin, "http://127.0.0.1") ||
		strings.HasPrefix(origin, "http://localhost")
}

func (s *Server) originPatterns() []string {
	// "*" matches any origin when set; otherwise rely on our own check.
	if len(s.cfg.AllowedOrigins) == 0 {
		return nil
	}
	patterns := make([]string, 0, len(s.cfg.AllowedOrigins))
	for _, a := range s.cfg.AllowedOrigins {
		if a == "*" {
			return []string{"*"}
		}
		patterns = append(patterns, a)
	}
	return patterns
}

// serveWS authenticates and runs one session.
func (s *Server) serveWS(conn *websocket.Conn, parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	conn.SetReadLimit(wsReadLimit)

	// ---- authentication (first frame must carry a token) ----
	// The Go client sends {"token": ...}; the browser client sends
	// {"type":"auth","data":{"token": ...}}. Both are accepted.
	token, ok := s.readAuthToken(conn)
	if !ok {
		writeFrame(conn, protocol.Frame{Type: protocol.EvError, Data: mustJSON(protocol.Error{
			Code: protocol.ErrForbidden, Message: "missing token"})})
		_ = conn.Close(websocket.StatusPolicyViolation, "missing token")
		return
	}
	claims, err := s.Signer.Verify(token)
	if err != nil {
		writeFrame(conn, protocol.Frame{Type: protocol.EvError, Data: mustJSON(protocol.Error{
			Code: protocol.ErrForbidden, Message: "invalid token"})})
		_ = conn.Close(websocket.StatusPolicyViolation, "invalid token")
		return
	}
	rec, err := s.Store.GetUserByID(ctx, claims.UserID)
	if err != nil || !rec.Enabled {
		_ = conn.Close(websocket.StatusPolicyViolation, "unknown account")
		return
	}

	// ---- register with the hub ----
	hc := s.Hub.Register(rec.User)
	defer func() {
		dropped := s.Hub.Disconnect(hc)
		s.wsUnregister(hc)
		hc.CloseDone()
		for _, name := range dropped {
			s.announcePresence(name, hc.User, "leave", nil)
		}
	}()
	s.wsRegister(hc, conn)

	// ---- welcome + offline queue ----
	s.sendRaw(hc, protocol.Frame{Type: protocol.EvWelcome, Data: mustJSON(protocol.Welcome{
		User: protocolUser(rec.User), Node: s.NodeID})})
	if ids, err := s.Store.PopOffline(ctx, rec.User.ID); err == nil && len(ids) > 0 {
		msgs := make([]protocol.Message, 0, len(ids))
		for _, id := range ids {
			var m protocol.Message
			if json.Unmarshal([]byte(id), &m) == nil {
				msgs = append(msgs, m)
			}
		}
		s.sendRaw(hc, protocol.Frame{Type: protocol.EvOffline, Data: mustJSON(protocol.Offline{Messages: msgs})})
	}

	// ---- keepalive ----
	keepAliveCtx, keepAliveCancel := context.WithCancel(ctx)
	defer keepAliveCancel()
	go func() {
		t := time.NewTicker(wsPingPeriod)
		defer t.Stop()
		for {
			select {
			case <-keepAliveCtx.Done():
				return
			case <-t.C:
				writeCtx, wc := context.WithTimeout(keepAliveCtx, wsWriteWait)
				if err := conn.Ping(writeCtx); err != nil {
					wc()
					return
				}
				wc()
			}
		}
	}()

	// ---- writer pump (single writer per connection) ----
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for {
			select {
			case <-hc.Done():
				return
			case payload := <-hc.Out():
				writeCtx, wc := context.WithTimeout(ctx, wsWriteWait)
				err := conn.Write(writeCtx, websocket.MessageText, payload)
				wc()
				if err != nil {
					return
				}
			}
		}
	}()

	// ---- reader pump ----
	readErr := s.readLoop(ctx, conn, hc, rec.User)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		s.Log.Debug("ws session ended", "user", rec.User.ID, "err", readErr)
	}
	hc.CloseDone()
	<-writerDone
	_ = conn.Close(websocket.StatusNormalClosure, "")
}

// readLoop processes incoming frames until the connection dies.
func (s *Server) readLoop(ctx context.Context, conn *websocket.Conn, hc *hub.Conn, u model.User) error {
	for {
		typ, data, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		if typ != websocket.MessageText {
			continue
		}
		var frame protocol.Frame
		if err := json.Unmarshal(data, &frame); err != nil {
			s.sendError(hc, protocol.ErrBadRequest, "malformed frame")
			continue
		}
		if err := s.handleFrame(ctx, hc, u, frame); err != nil {
			s.Log.Debug("frame handling", "user", u.ID, "type", frame.Type, "err", err)
		}
	}
}

// handleFrame dispatches one client command to the service.
func (s *Server) handleFrame(ctx context.Context, hc *hub.Conn, u model.User, frame protocol.Frame) error {
	switch frame.Type {
	case protocol.CmdJoin:
		return s.cmdJoin(ctx, hc, u, frame)
	case protocol.CmdLeave:
		return s.cmdLeave(ctx, hc, u, frame)
	case protocol.CmdMessage:
		return s.cmdMessage(ctx, hc, u, frame)
	case protocol.CmdTyping:
		return s.cmdTyping(hc, frame)
	case protocol.CmdCreateRoom:
		return s.cmdCreateRoom(hc, u, frame)
	case protocol.CmdDeleteRoom:
		return s.cmdDeleteRoom(hc, u, frame)
	case protocol.CmdRoomList:
		return s.cmdRoomList(hc)
	case protocol.CmdRoomHistory:
		return s.cmdRoomHistory(hc, frame)
	case "ping":
		s.sendRaw(hc, protocol.Frame{Type: protocol.EvPong})
		return nil
	default:
		s.sendError(hc, protocol.ErrBadRequest, "unknown frame type: "+frame.Type)
		return nil
	}
}

func (s *Server) cmdJoin(ctx context.Context, hc *hub.Conn, u model.User, frame protocol.Frame) error {
	var req protocol.Join
	if err := json.Unmarshal(frame.Data, &req); err != nil || req.Room == "" {
		s.sendError(hc, protocol.ErrBadRequest, "join requires a room name")
		return nil
	}
	members, history, joinedNew, err := s.Hub.Join(req.Room, hc)
	if err != nil {
		s.sendError(hc, protocol.ErrNotFound, "room not found: "+req.Room)
		return nil
	}
	if joinedNew {
		s.announcePresence(req.Room, u, "join", hc)
	}
	memberList := make([]protocol.User, 0, len(members))
	for _, m := range members {
		memberList = append(memberList, protocolUser(m))
	}
	histMsgs := make([]protocol.Message, 0, len(history))
	for _, m := range history {
		histMsgs = append(histMsgs, protocolMessage(m))
	}
	s.sendRaw(hc, protocol.Frame{Type: protocol.EvJoined, Data: mustJSON(protocol.Joined{
		Room: req.Room, Members: memberList, History: histMsgs})})
	_ = ctx
	return nil
}

func (s *Server) cmdLeave(ctx context.Context, hc *hub.Conn, u model.User, frame protocol.Frame) error {
	var req protocol.Leave
	if err := json.Unmarshal(frame.Data, &req); err != nil || req.Room == "" {
		s.sendError(hc, protocol.ErrBadRequest, "leave requires a room name")
		return nil
	}
	dropped, err := s.Hub.Leave(req.Room, hc)
	if err != nil {
		s.sendError(hc, protocol.ErrBadRequest, err.Error())
		return nil
	}
	if dropped {
		s.announcePresence(req.Room, u, "leave", hc)
	}
	s.sendRaw(hc, protocol.Frame{Type: protocol.EvLeft, Data: mustJSON(protocol.Left{Room: req.Room})})
	_ = ctx
	return nil
}

func (s *Server) cmdMessage(ctx context.Context, hc *hub.Conn, u model.User, frame protocol.Frame) error {
	var req protocol.ChatMessage
	if err := json.Unmarshal(frame.Data, &req); err != nil {
		s.sendError(hc, protocol.ErrBadRequest, "malformed message")
		return nil
	}
	if req.Room == "" && req.Recipient == "" {
		s.sendError(hc, protocol.ErrBadRequest, "message needs room or recipient")
		return nil
	}
	if !s.rateMessage(u.ID) {
		s.sendError(hc, protocol.ErrRateLimited, "slow down: 5 messages/second max")
		return nil
	}
	msg := model.Message{
		ID:         newMessageID(),
		Kind:       "chat",
		Sender:     u.ID,
		SenderName: u.DisplayName,
		Room:       req.Room,
		Recipient:  req.Recipient,
		Body:       req.Body,
		CreatedAt:  time.Now().UTC(),
	}
	if req.Recipient != "" {
		msg.Kind = "dm"
		if req.Body == "" || len(req.Body) > 4096 {
			s.sendError(hc, protocol.ErrBadRequest, "dm body must be 1-4096 chars")
			return nil
		}
		s.routeDM(msg)
		_ = ctx
		return nil
	}
	// Room chat: must be a member.
	if !s.Rooms.IsMember(req.Room, u.ID) {
		s.sendError(hc, protocol.ErrForbidden, "join the room before sending")
		return nil
	}
	if req.Body == "" || len(req.Body) > 4096 {
		s.sendError(hc, protocol.ErrBadRequest, "message body must be 1-4096 chars")
		return nil
	}
	s.publishRoomChat(msg)
	return nil
}

func (s *Server) cmdTyping(hc *hub.Conn, frame protocol.Frame) error {
	var req protocol.Typing
	if err := json.Unmarshal(frame.Data, &req); err != nil || req.Room == "" {
		s.sendError(hc, protocol.ErrBadRequest, "typing requires a room")
		return nil
	}
	if !s.Rooms.IsMember(req.Room, hc.User.ID) {
		s.sendError(hc, protocol.ErrForbidden, "join the room before typing")
		return nil
	}
	if !s.rateTyping(req.Room, hc.User.ID) {
		return nil // silently drop rate-limited typing pings
	}
	payload := mustJSON(protocol.Frame{Type: protocol.EvTyping, Data: mustJSON(protocol.TypingEvent{
		User: protocolUser(hc.User), Active: req.Active})})
	s.Hub.BroadcastRaw(req.Room, payload, hc)
	if s.B != nil {
		_ = s.B.Publish(s.ctx, broker.Message{
			Channel: "room:" + req.Room,
			Kind:    "typing",
			Payload: payload,
			Origin:  s.NodeID,
		})
	}
	return nil
}

func (s *Server) cmdCreateRoom(hc *hub.Conn, u model.User, frame protocol.Frame) error {
	var req protocol.CreateRoom
	if err := json.Unmarshal(frame.Data, &req); err != nil {
		s.sendError(hc, protocol.ErrBadRequest, "malformed create_room")
		return nil
	}
	req.Name = strings.TrimSpace(req.Name)
	if len(req.Name) < 2 || len(req.Name) > 64 || strings.ContainsAny(req.Name, " \t/#") {
		s.sendError(hc, protocol.ErrBadRequest, "room name must be 2-64 chars, no spaces or /#")
		return nil
	}
	if _, err := s.Rooms.CreateRoom(req.Name, strings.TrimSpace(req.Topic)); err != nil {
		if errors.Is(err, room.ErrRoomExists) {
			s.sendError(hc, protocol.ErrBadRequest, "room already exists")
			return nil
		}
		s.sendError(hc, protocol.ErrBadRequest, err.Error())
		return nil
	}
	evFrame := protocol.Frame{Type: protocol.EvRoomCreated, Data: mustJSON(map[string]string{"name": req.Name})}
	payload := mustJSON(evFrame)
	s.Hub.BroadcastAllRaw(payload, nil)
	if s.B != nil {
		_ = s.B.Publish(s.ctx, broker.Message{
			Channel: "*", Kind: "room", Payload: payload, Origin: s.NodeID,
		})
	}
	return nil
}

func (s *Server) cmdDeleteRoom(hc *hub.Conn, u model.User, frame protocol.Frame) error {
	var req protocol.DeleteRoom
	if err := json.Unmarshal(frame.Data, &req); err != nil {
		s.sendError(hc, protocol.ErrBadRequest, "malformed delete_room")
		return nil
	}
	if err := s.Rooms.DeleteRoom(req.Name); err != nil {
		s.sendError(hc, protocol.ErrNotFound, "room not found")
		return nil
	}
	// Kick all subscribers; membership is gone with the room.
	s.Hub.EvictRoom(req.Name)
	evFrame := protocol.Frame{Type: protocol.EvRoomDeleted, Data: mustJSON(map[string]string{"name": req.Name})}
	payload := mustJSON(evFrame)
	s.Hub.BroadcastAllRaw(payload, nil)
	if s.B != nil {
		_ = s.B.Publish(s.ctx, broker.Message{
			Channel: "*", Kind: "room", Payload: payload, Origin: s.NodeID,
		})
	}
	return nil
}

func (s *Server) cmdRoomList(hc *hub.Conn) error {
	rooms := s.Rooms.List()
	out := make([]protocol.Room, 0, len(rooms))
	for _, r := range rooms {
		out = append(out, protocol.Room{Name: r.Name, Topic: r.Topic, CreatedAt: r.CreatedAt.Format(time.RFC3339)})
	}
	s.sendRaw(hc, protocol.Frame{Type: protocol.EvRooms, Data: mustJSON(protocol.Rooms{Rooms: out})})
	return nil
}

func (s *Server) cmdRoomHistory(hc *hub.Conn, frame protocol.Frame) error {
	var req protocol.Join
	if err := json.Unmarshal(frame.Data, &req); err != nil || req.Room == "" {
		s.sendError(hc, protocol.ErrBadRequest, "room_history requires a room")
		return nil
	}
	msgs, err := s.Rooms.History(req.Room)
	if err != nil {
		s.sendError(hc, protocol.ErrNotFound, "room not found")
		return nil
	}
	out := make([]protocol.Message, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, protocolMessage(m))
	}
	s.sendRaw(hc, protocol.Frame{Type: protocol.EvHistory, Data: mustJSON(protocol.History{
		Room: req.Room, Messages: out})})
	return nil
}

// sendError replies with an error frame.
func (s *Server) sendError(hc *hub.Conn, code, msg string) {
	s.sendRaw(hc, protocol.Frame{Type: protocol.EvError, Data: mustJSON(protocol.Error{
		Code: code, Message: msg})})
}

// readJSON decodes one JSON object from the websocket (text frames).
func readJSON(conn *websocket.Conn, v any) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	typ, data, err := conn.Read(ctx)
	if err != nil {
		return err
	}
	if typ != websocket.MessageText {
		return errors.New("expected text frame")
	}
	return json.Unmarshal(data, v)
}

// readAuthToken reads the first frame and extracts the JWT from either
// the bare or framed shape.
func (s *Server) readAuthToken(conn *websocket.Conn) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	typ, data, err := conn.Read(ctx)
	if err != nil || typ != websocket.MessageText {
		return "", false
	}
	var bare struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(data, &bare); err == nil && bare.Token != "" {
		return bare.Token, true
	}
	var framed struct {
		Type string               `json:"type"`
		Data protocol.AuthRequest `json:"data"`
	}
	if err := json.Unmarshal(data, &framed); err == nil && framed.Type == "auth" && framed.Data.Token != "" {
		return framed.Data.Token, true
	}
	return "", false
}

// writeFrame sends one frame synchronously (used pre-pump).
func writeFrame(conn *websocket.Conn, frame protocol.Frame) error {
	ctx, cancel := context.WithTimeout(context.Background(), wsWriteWait)
	defer cancel()
	return conn.Write(ctx, websocket.MessageText, mustJSON(frame))
}

// protocolUser maps a model user to its protocol view.
func protocolUser(u model.User) protocol.User {
	return protocol.User{ID: u.ID, Username: u.Username, DisplayName: u.DisplayName}
}

// protocolMessage maps a model message to its wire form.
func protocolMessage(m model.Message) protocol.Message {
	return protocol.Message{
		ID: m.ID, Kind: m.Kind, Room: m.Room, Sender: m.Sender,
		SenderName: m.SenderName, Recipient: m.Recipient, Body: m.Body,
		CreatedAt: m.CreatedAt,
	}
}
