// Package model defines the core domain types shared by the GoChat
// server, storage backends and the protocol.
package model

import "time"

// Message is a chat message broadcast or delivered through the hub.
type Message struct {
	// ID is a server-assigned unique identifier.
	ID string `json:"id"`
	// Room is the destination room name, or "" for private messages.
	Room string `json:"room"`
	// Sender is the user ID of the sender.
	Sender string `json:"sender"`
	// SenderName is the display name of the sender at send time.
	SenderName string `json:"senderName,omitempty"`
	// Kind classifies the message: "chat" or "dm".
	Kind string `json:"kind"`
	// Body is the message payload. For DMs this is the base64 encoded
	// NaCl box ciphertext produced client-side; the server only relays it.
	Body string `json:"body"`
	// Recipient is the target user ID of a DM ("" for room chat).
	Recipient string `json:"recipient,omitempty"`
	// CreatedAt is the server receive time (UTC).
	CreatedAt time.Time `json:"createdAt"`
}

// PresenceEvent is broadcast to a room when a member joins or leaves.
type PresenceEvent struct {
	Room string `json:"room"`
	User User   `json:"user"`
	Type string `json:"type"` // "join" | "leave"
}

// TypingEvent is broadcast to a room when a member starts typing.
type TypingEvent struct {
	Room   string `json:"room"`
	User   User   `json:"user"`
	Active bool   `json:"active"`
}

// User is a chat user. Key fields mirror the REST user representation.
type User struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"displayName"`
	PublicKey   string    `json:"publicKey,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
}

// Room is a chat room with its current member set.
type Room struct {
	Name      string    `json:"name"`
	Topic     string    `json:"topic,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

// RoomEvent is broadcast on a hub when a room is created or removed.
type RoomEvent struct {
	Type     string `json:"type"` // "created" | "deleted"
	RoomName string `json:"roomName"`
}

// MaxMessageBytes bounds the size of a single chat message.
const MaxMessageBytes = 4096
