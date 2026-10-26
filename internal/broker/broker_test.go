package broker

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestLocalBrokerRoundTrip(t *testing.T) {
	b := NewLocal("node-1")
	defer b.Close()
	sub := b.Subscribe(context.Background())

	msg := Message{Channel: "room:general", Kind: "chat", Payload: json.RawMessage(`{"hi":1}`), Origin: "node-1"}
	if err := b.Publish(context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-sub:
		if string(got.Payload) != `{"hi":1}` || got.Origin != "node-1" {
			t.Fatalf("got %+v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no message delivered")
	}
}

func TestRedisBrokerFanoutAcrossNodes(t *testing.T) {
	mr := miniredis.RunT(t)
	r := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer r.Close()

	ctx := context.Background()
	a := NewRedisWithClient("node-a", r, nil)
	defer a.Close()
	b := NewRedisWithClient("node-b", r, nil)
	defer b.Close()

	subA := a.Subscribe(ctx)
	subB := b.Subscribe(ctx)

	msg := Message{Channel: "room:lobby", Kind: "chat", Payload: json.RawMessage(`{"m":1}`), Origin: "node-a"}
	if err := b.Publish(ctx, msg); err != nil {
		t.Fatal(err)
	}

	// Node A must not receive its own publish (echo suppression).
	select {
	case got := <-subA:
		t.Fatalf("node A received its own message: %+v", got)
	case <-time.After(300 * time.Millisecond):
	}
	// Node B must receive it.
	select {
	case got := <-subB:
		if got.Origin != "node-a" || string(got.Payload) != `{"m":1}` {
			t.Fatalf("node B got %+v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("node B received nothing")
	}
}

func TestLocalMultipleSubscribers(t *testing.T) {
	b := NewLocal("n")
	defer b.Close()
	s1 := b.Subscribe(context.Background())
	s2 := b.Subscribe(context.Background())
	b.Publish(context.Background(), Message{Channel: "*", Kind: "typing", Payload: json.RawMessage(`{}`), Origin: "n"})
	for i, sub := range []<-chan Sub{s1, s2} {
		select {
		case <-sub:
		case <-time.After(5 * time.Second):
			t.Fatalf("subscriber %d got nothing", i)
		}
	}
}
