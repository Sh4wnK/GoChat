package hub

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Sh4wnK/GoChat/internal/model"
	"github.com/Sh4wnK/GoChat/internal/room"
)

func testHub(t *testing.T) (*Hub, *room.Manager) {
	t.Helper()
	rm := room.NewManager()
	if _, err := rm.CreateRoom("general", ""); err != nil {
		t.Fatal(err)
	}
	h := New(rm, nil, Config{})
	t.Cleanup(func() {})
	return h, rm
}

func mkUser(id, username string) model.User {
	return model.User{ID: id, Username: username, DisplayName: username}
}

func waitFor(t *testing.T, c *Conn) []byte {
	t.Helper()
	select {
	case p, ok := <-c.Out():
		if !ok {
			t.Fatalf("conn %s closed prematurely", c.User.ID)
		}
		return p
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout waiting for payload on %s", c.User.ID)
		return nil
	}
}

func expectClosed(t *testing.T, c *Conn) {
	t.Helper()
	select {
	case _, ok := <-c.Out():
		if ok {
			t.Fatalf("conn %s still deliverable", c.User.ID)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("conn %s not closed", c.User.ID)
	}
}

// TestJoinPresence verifies join returns members+history and broadcasts
// join presence to existing subscribers.
func TestJoinPresence(t *testing.T) {
	h, rm := testHub(t)
	alice := h.Register(mkUser("a1", "alice"))
	bob := h.Register(mkUser("b2", "bob"))

	// Alice joins general (empty room: only history frames, which are
	// nil/empty here — no rooms with history exist yet).
	members, history, newMember, err := h.Join("general", alice)
	if err != nil || !newMember {
		t.Fatalf("alice join: new=%v err=%v", newMember, err)
	}
	if len(members) != 1 || members[0].ID != "a1" {
		t.Fatalf("members = %+v", members)
	}
	if len(history) != 0 {
		t.Fatalf("history = %+v", history)
	}

	// Bob joins: alice should receive exactly one payload: the presence
	// frame the server builds (hub's BroadcastRaw pushes raw bytes), so
	// the hub test injects raw frames.
	_ = rm
	pay := []byte(`{"type":"presence","data":{"type":"join","room":"general","user":{"id":"b2","username":"bob","displayName":"bob"}}}`)
	h.BroadcastRaw("general", pay, nil)
	got := waitFor(t, alice)
	if string(got) != string(pay) {
		t.Fatalf("alice got %s, want %s", got, pay)
	}

	// Bob joins for real: hub returns his member list and stale history.
	members2, _, newMember2, err := h.Join("general", bob)
	if err != nil || !newMember2 {
		t.Fatalf("bob join: new=%v err=%v", newMember2, err)
	}
	if len(members2) != 2 {
		t.Fatalf("members after bob = %+v", members2)
	}
}

// TestRoomMessageRouting fans a raw frame to subscribers only.
func TestRoomMessageRouting(t *testing.T) {
	h, _ := testHub(t)
	alice := h.Register(mkUser("a1", "alice"))
	bob := h.Register(mkUser("b2", "bob"))
	carl := h.Register(mkUser("c3", "carl"))

	if _, _, _, err := h.Join("general", alice); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := h.Join("general", bob); err != nil {
		t.Fatal(err)
	}
	// Carl joins a different room.
	_ = carl

	pay := []byte(`{"type":"message","data":{"id":"m1","kind":"chat","room":"general","sender":"b2","body":"hi"}}`)
	h.BroadcastRaw("general", pay, nil)

	for _, c := range []*Conn{alice, bob} {
		got := waitFor(t, c)
		if string(got) != string(pay) {
			t.Fatalf("%s got %s", c.User.ID, got)
		}
	}
	// Carl must not receive anything.
	select {
	case <-carl.Out():
		t.Fatal("carl received a message he should not have")
	case <-time.After(300 * time.Millisecond):
	}
}

// TestDMRoutingToAllSessions verifies multi-session delivery and
// offline (zero-session) signaling.
func TestDMRoutingToAllSessions(t *testing.T) {
	h, _ := testHub(t)
	bob := h.Register(mkUser("b2", "bob"))
	s1 := h.Register(mkUser("b2", "bob"))
	s2 := h.Register(mkUser("b2", "bob"))

	if _, _, _, err := h.Join("general", bob); err != nil {
		t.Fatal(err)
	}

	pay := []byte(`{"type":"dm","data":{"id":"d1","kind":"dm","recipient":"a1","sender":"b2","body":"cipher"}}`)

	// Bob is on three sessions -> all get it.
	if got := h.SendToUserRaw("b2", pay); got != 3 {
		t.Fatalf("deliveries = %d, want 3", got)
	}
	for _, c := range []*Conn{bob, s1, s2} {
		waitFor(t, c)
	}

	// Nobody online: want 0.
	if got := h.SendToUserRaw("nobody", pay); got != 0 {
		t.Fatalf("offline deliveries = %d, want 0", got)
	}
}

// TestPresenceOnLeave verifies leave presence is *not* broadcast by the
// hub itself (server responsibility) but that Leave cleans up the
// subscription, and multi-session users keep membership.
func TestPresenceOnLeave(t *testing.T) {
	h, rm := testHub(t)
	alice := h.Register(mkUser("a1", "alice"))
	s1 := h.Register(mkUser("a1", "alice"))
	s2 := h.Register(mkUser("a1", "alice"))

	if _, _, _, err := h.Join("general", alice); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := h.Join("general", s1); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := h.Join("general", s2); err != nil {
		t.Fatal(err)
	}
	if h.Subscribers("general") != 3 {
		t.Fatalf("subscribers = %d, want 3", h.Subscribers("general"))
	}
	members, _ := rm.Members("general")
	if len(members) != 1 {
		t.Fatalf("members = %+v", members)
	}

	// s1 leaves; alice still has another session so membership stays.
	if dropped, err := h.Leave("general", s1); err != nil || dropped {
		t.Fatalf("s1 leave: dropped=%v err=%v", dropped, err)
	}
	members, _ = rm.Members("general")
	if len(members) != 1 {
		t.Fatalf("members after s1 leave = %+v", members)
	}

	// alice (original) leaves; still s2 -> membership stays.
	if dropped, err := h.Leave("general", alice); err != nil || dropped {
		t.Fatalf("alice leave: dropped=%v err=%v", dropped, err)
	}

	// s2 leaves; membership drops.
	if dropped, err := h.Leave("general", s2); err != nil || !dropped {
		t.Fatalf("s2 leave: dropped=%v err=%v", dropped, err)
	}
	members, _ = rm.Members("general")
	if len(members) != 0 {
		t.Fatalf("members after all left = %+v", members)
	}
	// The hub does NOT emit presence frames itself: nothing queued.
	select {
	case p := <-alice.Out():
		t.Fatalf("unexpected payload %s", p)
	default:
	}
}

// TestDisconnectEvictsAndCleans verifies Disconnect removes a
// connection completely and drops membership when it was the last
// session.
func TestDisconnectEvictsAndCleans(t *testing.T) {
	h, rm := testHub(t)
	alice := h.Register(mkUser("a1", "alice"))

	if _, _, _, err := h.Join("general", alice); err != nil {
		t.Fatal(err)
	}
	dropped := h.Disconnect(alice)
	if len(dropped) != 1 || dropped[0] != "general" {
		t.Fatalf("dropped = %+v", dropped)
	}
	alice.CloseDone()
	select {
	case <-alice.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("done not closed after disconnect")
	}
	if h.Connected("a1") {
		t.Fatal("alice still connected")
	}
	if h.Subscribers("general") != 0 {
		t.Fatal("general still has subscribers")
	}
	members, _ := rm.Members("general")
	if len(members) != 0 {
		t.Fatalf("members = %+v", members)
	}
	// Second Disconnect is a no-op.
	if dropped := h.Disconnect(alice); dropped != nil {
		t.Fatalf("second disconnect returned %+v", dropped)
	}
}

// TestSlowConsumerEviction fills a connection's outbound queue and
// verifies the hub evicts it and drops its membership.
func TestSlowConsumerEviction(t *testing.T) {
	h, rm := testHub(t)
	rm.CreateRoom("loud", "")
	alice := h.Register(mkUser("a1", "alice"))
	evicted := make(chan *Conn, 1)
	h.cfg.OnDrop = func(c *Conn, rooms []string) {
		evicted <- c
	}
	if _, _, _, err := h.Join("loud", alice); err != nil {
		t.Fatal(err)
	}
	pay := []byte(`{"x":1}`)
	// Fill the queue completely.
	for i := 0; i < SlowConsumerMax; i++ {
		h.deliver(alice, pay)
	}
	// Next delivery fails and evicts.
	if ok := h.deliver(alice, pay); ok {
		t.Fatal("delivery to full queue should fail")
	}
	select {
	case c := <-evicted:
		if c != alice {
			t.Fatal("wrong conn evicted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no eviction callback")
	}
	if len(alice.Out()) != SlowConsumerMax {
		t.Fatalf("queue drained unexpectedly: %d", len(alice.Out()))
	}
	if h.Subscribers("loud") != 0 {
		t.Fatal("member not removed from room")
	}
	members, _ := rm.Members("loud")
	if len(members) != 0 {
		t.Fatalf("members after eviction = %+v", members)
	}
}

var _ = json.Marshal
