// Package broker provides the cross-node fan-out abstraction. The local
// broker is the default single-process implementation; the redis broker
// mirrors room broadcasts onto Redis pub/sub so multiple server replicas
// act as one logical hub.
package broker

import (
	"context"
	"encoding/json"
	"sync"
)

// Message is an opaque event relayed to every node subscribed to a
// channel. Payload is a pre-encoded protocol frame relayed verbatim.
type Message struct {
	// Channel is the hub-level destination: a room name, a user ID
	// (direct messages), or "*" for broadcast events.
	Channel string `json:"channel"`
	// Kind mirrors the protocol message kind ("chat", "dm", "presence",
	// "typing", "user", "room").
	Kind string `json:"kind"`
	// Payload is the JSON-encoded outbound frame to forward verbatim.
	Payload json.RawMessage `json:"payload"`
	// Origin is the sending node identity (used to avoid echoes).
	Origin string `json:"origin"`
}

// Sub is an inbound subscription delivery.
type Sub struct {
	Message
	Err error
}

// Broker fans frames out to all nodes in the cluster.
type Broker interface {
	// Publish sends a message on a channel to every subscriber on every
	// node.
	Publish(ctx context.Context, msg Message) error
	// Subscribe returns a channel receiving messages from peer nodes.
	Subscribe(ctx context.Context) <-chan Sub
	// NodeID returns this node's identity.
	NodeID() string
	Close() error
}

// Local is a same-process broker used by single-node deployments and
// tests. Publish delivers directly to local subscribers.
type Local struct {
	node string
	mu   sync.Mutex
	subs map[string][]chan Sub
}

// NewLocal creates a Local broker.
func NewLocal(node string) *Local {
	return &Local{node: node, subs: make(map[string][]chan Sub)}
}

// Publish delivers the message to every local subscription.
func (b *Local) Publish(_ context.Context, msg Message) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.subs[msg.Channel] {
		select {
		case ch <- Sub{Message: msg}:
		default: // slow local subscriber: drop
		}
	}
	for _, ch := range b.subs["*"] {
		select {
		case ch <- Sub{Message: msg}:
		default:
		}
	}
	return nil
}

// NodeID returns this node's identity.
func (b *Local) NodeID() string { return b.node }

// Subscribe registers a channel that receives every published message.
func (b *Local) Subscribe(_ context.Context) <-chan Sub {
	ch := make(chan Sub, 1024)
	b.mu.Lock()
	b.subs["*"] = append(b.subs["*"], ch)
	b.mu.Unlock()
	return ch
}

// Close is a no-op for the local broker.
func (b *Local) Close() error { return nil }
