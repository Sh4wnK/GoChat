// Package protocol defines the JSON frames exchanged between clients
// and the GoChat WebSocket server, shared by the server, the Go client
// library and the browser client documentation.
package protocol

import (
	"encoding/json"
	"time"
)

// Client frame types (client -> server).
const (
	CmdJoin        = "join"         // {room}
	CmdLeave       = "leave"        // {room}
	CmdMessage     = "message"      // {room?, recipient?, body}
	CmdTyping      = "typing"       // {room, active}
	CmdCreateRoom  = "create_room"  // {name, topic?}
	CmdDeleteRoom  = "delete_room"  // {name}
	CmdRoomList    = "room_list"    // {}
	CmdRoomHistory = "room_history" // {room}
	CmdMembers     = "members"      // {room}
)

// Server frame types (server -> client).
const (
	EvMessage     = "message"      // room chat message
	EvDm          = "dm"           // private message
	EvPresence    = "presence"     // {type: join|leave, user}
	EvTyping      = "typing"       // {user, active}
	EvJoined      = "joined"       // reply to join: {room, members, history}
	EvLeft        = "left"         // reply to leave: {room}
	EvRooms       = "rooms"        // reply to room_list: {rooms}
	EvHistory     = "history"      // reply to room_history: {messages}
	EvMembers     = "members"      // reply to members: {room, members}
	EvRoomCreated = "room_created" // broadcast: {name}
	EvRoomDeleted = "room_deleted" // broadcast: {name}
	EvError       = "error"        // {code, message}
	EvPong        = "pong"
	EvWelcome     = "welcome" // sent on connect: {user, node}
	EvOffline     = "offline" // undelivered DM queue: {messages}
)

// Error codes used in error frames.
const (
	ErrBadRequest  = "bad_request"
	ErrForbidden   = "forbidden"
	ErrNotFound    = "not_found"
	ErrRateLimited = "rate_limited"
)

// AuthRequest is sent as the first frame of every WebSocket connection.
type AuthRequest struct {
	Token string `json:"token"`
}

// Join is sent to subscribe to a room.
type Join struct {
	Room string `json:"room"`
}

// Leave is sent to unsubscribe from a room.
type Leave struct {
	Room string `json:"room"`
}

// ChatMessage is the payload of a message frame. For DMs, Body is
// already the base64 E2E ciphertext; the server never sees plaintext.
type ChatMessage struct {
	Room      string `json:"room,omitempty"`
	Recipient string `json:"recipient,omitempty"`
	Body      string `json:"body"`
}

// Typing is sent when the user starts or stops typing in a room.
type Typing struct {
	Room   string `json:"room"`
	Active bool   `json:"active"`
}

// CreateRoom creates a new room.
type CreateRoom struct {
	Name  string `json:"name"`
	Topic string `json:"topic,omitempty"`
}

// DeleteRoom deletes a room.
type DeleteRoom struct {
	Name string `json:"name"`
}

// Message is a server-delivered chat message (room or DM).
type Message struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"` // "chat" | "dm"
	Room       string    `json:"room,omitempty"`
	Sender     string    `json:"sender"`
	SenderName string    `json:"senderName"`
	Recipient  string    `json:"recipient,omitempty"` // DM: target user
	Body       string    `json:"body"`
	CreatedAt  time.Time `json:"createdAt"`
}

// Presence is a join/leave event.
type Presence struct {
	Type string `json:"type"` // "join" | "leave"
	Room string `json:"room,omitempty"`
	User User   `json:"user"`
}

// TypingEvent is a typing indicator update.
type TypingEvent struct {
	Room   string `json:"room,omitempty"`
	User   User   `json:"user"`
	Active bool   `json:"active"`
}

// User mirrors the REST user representation for presence/typing frames.
type User struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
}

// Joined is the reply to a join command.
type Joined struct {
	Room    string    `json:"room"`
	Members []User    `json:"members"`
	History []Message `json:"history"`
}

// Left is the reply to a leave command.
type Left struct {
	Room string `json:"room"`
}

// Room is a room listing entry.
type Room struct {
	Name      string `json:"name"`
	Topic     string `json:"topic,omitempty"`
	CreatedAt string `json:"createdAt"`
}

// Rooms is the reply to room_list.
type Rooms struct {
	Rooms []Room `json:"rooms"`
}

// History is the reply to room_history.
type History struct {
	Room     string    `json:"room"`
	Messages []Message `json:"messages"`
}

// Members is the reply to members.
type Members struct {
	Room    string `json:"room"`
	Members []User `json:"members"`
}

// Error is an error frame.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Welcome is sent on connect.
type Welcome struct {
	User User   `json:"user"`
	Node string `json:"node"`
}

// Offline delivers queued DMs received while the user was away.
type Offline struct {
	Messages []Message `json:"messages"`
}

// Frame is a generic protocol envelope, used for decoding arbitrary
// server events.
type Frame struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
}
