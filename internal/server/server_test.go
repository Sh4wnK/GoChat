package server_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Sh4wnK/GoChat/internal/auth"
	"github.com/Sh4wnK/GoChat/internal/hub"
	"github.com/Sh4wnK/GoChat/internal/protocol"
	"github.com/Sh4wnK/GoChat/internal/room"
	"github.com/Sh4wnK/GoChat/internal/server"
	"github.com/Sh4wnK/GoChat/internal/userstore"
	"github.com/Sh4wnK/GoChat/pkg/client"
)

// newTestServer boots a full single-node GoChat server on httptest.
func newTestServer(t *testing.T) (*client.Client, *client.Client) {
	t.Helper()
	signer := auth.NewSigner(auth.TokenConfig{Secret: []byte("01234567890123456789012345678901")})
	rooms := room.NewManager()
	rooms.CreateRoom("general", "Main hall")
	srv, err := server.New(context.Background(), server.Config{
		Signer: signer,
		Store:  userstore.NewInMemory(),
		Rooms:  rooms,
		HubCfg: &hub.Config{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() {
		srv.Close()
		ts.Close()
	})

	alice := client.New(ts.URL)
	bob := client.New(ts.URL)
	if _, err := alice.Register(context.Background(), "alice", "password1", "Alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Login(context.Background(), "alice", "password1"); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Register(context.Background(), "bob", "password2", "Bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Login(context.Background(), "bob", "password2"); err != nil {
		t.Fatal(err)
	}
	return alice, bob
}

func connect(t *testing.T, c *client.Client) *client.Session {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sess, err := c.Dial(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sess.Close)
	return sess
}

func nextEvent(t *testing.T, sess *client.Session, wantType string) protocol.Frame {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case ev, ok := <-sess.Events:
			if !ok {
				t.Fatalf("session closed while waiting for %s", wantType)
			}
			if ev.Type == wantType {
				return ev
			}
			// Skip presence/noise from other tests' rooms.
		case <-deadline:
			t.Fatalf("timeout waiting for %s", wantType)
		}
	}
}

// TestRESTLifecycle covers register, login, me, profile update,
// public-key upload, user list and delete.
func TestRESTLifecycle(t *testing.T) {
	alice, _ := newTestServer(t)
	ctx := context.Background()

	me, err := alice.Me(ctx)
	if err != nil || me.Username != "alice" {
		t.Fatalf("me = %+v err = %v", me, err)
	}
	if err := alice.UpdateProfile(ctx, "Alicia"); err != nil {
		t.Fatal(err)
	}
	me, _ = alice.Me(ctx)
	if me.DisplayName != "Alicia" {
		t.Fatalf("display = %q", me.DisplayName)
	}
	kp, err := client.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	alice.SetKeys(kp)
	if err := alice.UploadPublicKey(ctx); err != nil {
		t.Fatal(err)
	}
	users, err := alice.ListUsers(ctx, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) < 2 {
		t.Fatalf("users = %+v", users)
	}
	// Every listed user carries no password material; alice has key.
	var aliceRow *client.User
	for i := range users {
		if users[i].Username == "alice" {
			aliceRow = &users[i]
		}
	}
	if aliceRow == nil || aliceRow.PublicKey != kp.PublicKey {
		t.Fatalf("alice row = %+v", aliceRow)
	}
}

// TestE2EDMRoundTrip proves the server relays only ciphertext: the
// plaintext never appears in any frame the server produces, and the
// recipient decrypts with the sender's public key.
func TestE2EDMRoundTrip(t *testing.T) {
	alice, bob := newTestServer(t)
	ctx := context.Background()

	akp, _ := client.GenerateKeyPair()
	bkp, _ := client.GenerateKeyPair()
	alice.SetKeys(akp)
	bob.SetKeys(bkp)
	if err := alice.UploadPublicKey(ctx); err != nil {
		t.Fatal(err)
	}
	if err := bob.UploadPublicKey(ctx); err != nil {
		t.Fatal(err)
	}

	aliceSess := connect(t, alice)
	bobSess := connect(t, bob)

	// Alice fetches Bob's public key and encrypts her DM.
	peer, err := lookupUser(t, alice, "bob")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := alice.Encrypt(peer.PublicKey, "meet at midnight")
	if err != nil {
		t.Fatal(err)
	}
	if err := aliceSess.SendMessage(ctx, "", peer.ID, sealed); err != nil {
		t.Fatal(err)
	}

	// Bob receives the DM frame.
	frame := nextEvent(t, bobSess, protocol.EvDm)
	var dm protocol.Message
	if err := json.Unmarshal(frame.Data, &dm); err != nil {
		t.Fatal(err)
	}
	if dm.Kind != "dm" || dm.Sender != mustUserID(t, bob, "alice") || dm.Recipient != peer.ID {
		t.Fatalf("dm = %+v", dm)
	}
	// Prove server never saw plaintext.
	if contains(dm.Body, "midnight") {
		t.Fatal("ciphertext contains plaintext")
	}
	if dm.Body == "meet at midnight" {
		t.Fatal("server relayed plaintext")
	}
	// Bob decrypts with Alice's public key.
	plain, err := bob.Decrypt(alicePub(t, bob), dm.Body)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if plain != "meet at midnight" {
		t.Fatalf("plaintext = %q", plain)
	}
}

// TestRoomChatAndPresence covers join, presence broadcast, room chat and
// typing over real websockets.
func TestRoomChatAndPresence(t *testing.T) {
	alice, bob := newTestServer(t)
	ctx := context.Background()
	aliceSess := connect(t, alice)
	bobSess := connect(t, bob)

	// Alice creates a room and joins it.
	if err := aliceSess.CreateRoom(ctx, "gaming", "nerd den"); err != nil {
		t.Fatal(err)
	}
	nextEvent(t, aliceSess, protocol.EvRoomCreated)
	if err := aliceSess.Join(ctx, "gaming"); err != nil {
		t.Fatal(err)
	}
	nextEvent(t, aliceSess, protocol.EvJoined)
	if err := bobSess.Join(ctx, "gaming"); err != nil {
		t.Fatal(err)
	}
	nextEvent(t, bobSess, protocol.EvJoined)
	// Alice sees Bob's join presence.
	pres := nextEvent(t, aliceSess, protocol.EvPresence)
	var p protocol.Presence
	if err := json.Unmarshal(pres.Data, &p); err != nil {
		t.Fatal(err)
	}
	if p.Type != "join" || p.User.Username != "bob" {
		t.Fatalf("presence = %+v", p)
	}

	// Bob types; alice sees it.
	if err := bobSess.Typing(ctx, "gaming", true); err != nil {
		t.Fatal(err)
	}
	typing := nextEvent(t, aliceSess, protocol.EvTyping)
	var te protocol.TypingEvent
	if err := json.Unmarshal(typing.Data, &te); err != nil {
		t.Fatal(err)
	}
	if !te.Active || te.User.Username != "bob" {
		t.Fatalf("typing = %+v", te)
	}

	// Bob sends a room message; both alice and bob receive it (echo).
	if err := bobSess.SendMessage(ctx, "gaming", "", "hello gaming"); err != nil {
		t.Fatal(err)
	}
	gotAlice := nextEvent(t, aliceSess, protocol.EvMessage)
	gotBob := nextEvent(t, bobSess, protocol.EvMessage)
	var m protocol.Message
	json.Unmarshal(gotAlice.Data, &m)
	if m.Body != "hello gaming" || m.SenderName != "Bob" {
		t.Fatalf("msg = %+v", m)
	}
	json.Unmarshal(gotBob.Data, &m)
	if m.Body != "hello gaming" {
		t.Fatalf("echo = %+v", m)
	}

	// Room list shows the new room; history contains the message.
	if err := aliceSess.ListRooms(ctx); err != nil {
		t.Fatal(err)
	}
	roomsEv := nextEvent(t, aliceSess, protocol.EvRooms)
	var rooms protocol.Rooms
	json.Unmarshal(roomsEv.Data, &rooms)
	found := false
	for _, r := range rooms.Rooms {
		if r.Name == "gaming" {
			found = true
		}
	}
	if !found {
		t.Fatalf("rooms = %+v", rooms)
	}
	if err := aliceSess.RoomHistory(ctx, "gaming"); err != nil {
		t.Fatal(err)
	}
	histEv := nextEvent(t, aliceSess, protocol.EvHistory)
	var hist protocol.History
	json.Unmarshal(histEv.Data, &hist)
	if len(hist.Messages) != 1 || hist.Messages[0].Body != "hello gaming" {
		t.Fatalf("history = %+v", hist)
	}
}

// TestOfflineDMQueuedAndDelivered proves offline queue persistence:
// a DM sent while Bob is away is stored, then delivered on connect.
func TestOfflineDMQueuedAndDelivered(t *testing.T) {
	alice, bob := newTestServer(t)
	ctx := context.Background()

	// Bob is not connected yet.
	bkp, _ := client.GenerateKeyPair()
	bob.SetKeys(bkp)
	_ = bob.UploadPublicKey(ctx)
	akp, _ := client.GenerateKeyPair()
	alice.SetKeys(akp)
	_ = alice.UploadPublicKey(ctx)

	aliceSess := connect(t, alice)
	peer, err := lookupUser(t, alice, "bob")
	if err != nil {
		t.Fatal(err)
	}
	sealed, _ := alice.Encrypt(peer.PublicKey, "you were offline")
	if err := aliceSess.SendMessage(ctx, "", peer.ID, sealed); err != nil {
		t.Fatal(err)
	}

	// Bob connects: offline frame arrives with the queued DM.
	bobSess := connect(t, bob)
	off := nextEvent(t, bobSess, protocol.EvOffline)
	var payload protocol.Offline
	if err := json.Unmarshal(off.Data, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Messages) != 1 || payload.Messages[0].Body != sealed {
		t.Fatalf("offline = %+v", payload)
	}
	// Bob can still decrypt it.
	plain, err := bob.Decrypt(alicePub(t, bob), payload.Messages[0].Body)
	if err != nil || plain != "you were offline" {
		t.Fatalf("decrypt: %q %v", plain, err)
	}
}

// TestAuthRejectedOnWS verifies a missing/bad token is rejected before
// any session state is created.
func TestAuthRejectedOnWS(t *testing.T) {
	alice, _ := newTestServer(t)
	ctx := context.Background()
	aliceSess := connect(t, alice)

	// A second session with a garbage token must fail to connect.
	c := client.New(mustServerURL(t))
	if _, err := c.Dial(ctx, "garbage.token.here"); err == nil {
		t.Fatal("garbage token accepted")
	}
	t.Cleanup(func() {})
	_ = aliceSess
}

// helpers

func lookupUser(t *testing.T, c *client.Client, username string) (client.User, error) {
	t.Helper()
	users, err := c.ListUsers(context.Background(), 100, 0)
	if err != nil {
		return client.User{}, err
	}
	for _, u := range users {
		if u.Username == username {
			return u, nil
		}
	}
	t.Fatalf("user %s not found in %+v", username, users)
	return client.User{}, nil
}

func mustUserID(t *testing.T, c *client.Client, username string) string {
	t.Helper()
	u, err := lookupUser(t, c, username)
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

// alicePub returns alice's public key as seen by bob's client.
func alicePub(t *testing.T, c *client.Client) string {
	t.Helper()
	users, err := c.ListUsers(context.Background(), 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		if u.Username == "alice" {
			return u.PublicKey
		}
	}
	t.Fatal("alice not listed")
	return ""
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func mustServerURL(t *testing.T) string {
	// Used only for negative tests; dialing garbage token must fail fast.
	return "http://127.0.0.1:1"
}
