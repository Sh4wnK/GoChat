package userstore

import (
	"context"
	"errors"
	"testing"
)

func TestInMemoryUserLifecycle(t *testing.T) {
	ctx := context.Background()
	s := NewInMemory()

	u, err := s.CreateUser(ctx, "alice", "Alice", []byte("hash"))
	if err != nil {
		t.Fatal(err)
	}
	if u.ID == "" || u.Username != "alice" {
		t.Fatalf("user = %+v", u)
	}
	if _, err := s.CreateUser(ctx, "alice", "x", nil); !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("dup username err = %v", err)
	}

	rec, err := s.GetUserByName(ctx, "alice")
	if err != nil || string(rec.Password) != "hash" {
		t.Fatalf("get by name: %+v %v", rec, err)
	}
	if _, err := s.GetUserByName(ctx, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing user err = %v", err)
	}

	if err := s.UpdateProfile(ctx, u.ID, "Alicia"); err != nil {
		t.Fatal(err)
	}
	rec, _ = s.GetUserByID(ctx, u.ID)
	if rec.User.DisplayName != "Alicia" {
		t.Fatalf("display = %q", rec.User.DisplayName)
	}

	if err := s.SetPublicKey(ctx, u.ID, "dGVzdGtleQ=="); err != nil {
		t.Fatal(err)
	}
	rec, _ = s.GetUserByID(ctx, u.ID)
	if rec.PublicKey != "dGVzdGtleQ==" {
		t.Fatalf("key = %q", rec.PublicKey)
	}

	if err := s.SetEnabled(ctx, u.ID, false); err != nil {
		t.Fatal(err)
	}
	rec, _ = s.GetUserByID(ctx, u.ID)
	if rec.Enabled {
		t.Fatal("user still enabled")
	}
}

func TestInMemoryOfflineQueue(t *testing.T) {
	ctx := context.Background()
	s := NewInMemory()
	u, _ := s.CreateUser(ctx, "bob", "Bob", nil)

	if err := s.EnqueueOffline(ctx, u.ID, "m1", `{"id":"m1"}`); err != nil {
		t.Fatal(err)
	}
	// Duplicate id is deduplicated.
	if err := s.EnqueueOffline(ctx, u.ID, "m1", `{"id":"m1"}`); err != nil {
		t.Fatal(err)
	}
	if err := s.EnqueueOffline(ctx, u.ID, "m2", `{"id":"m2"}`); err != nil {
		t.Fatal(err)
	}
	msgs, err := s.PopOffline(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 || msgs[0] != `{"id":"m1"}` || msgs[1] != `{"id":"m2"}` {
		t.Fatalf("offline = %+v", msgs)
	}
	// Second pop is empty.
	msgs, _ = s.PopOffline(ctx, u.ID)
	if len(msgs) != 0 {
		t.Fatalf("second pop = %+v", msgs)
	}
}

func TestInMemoryDeleteUser(t *testing.T) {
	ctx := context.Background()
	s := NewInMemory()
	u, _ := s.CreateUser(ctx, "carol", "Carol", nil)
	s.EnqueueOffline(ctx, u.ID, "m1", `{}`)

	if err := s.DeleteUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetUserByID(ctx, u.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get deleted err = %v", err)
	}
	if _, err := s.CreateUser(ctx, "carol", "C", nil); err != nil {
		t.Fatalf("recreate after delete: %v", err)
	}
}

func TestListUsersPaging(t *testing.T) {
	ctx := context.Background()
	s := NewInMemory()
	for i := 0; i < 5; i++ {
		s.CreateUser(ctx, "u"+string(rune('a'+i)), "U", nil)
	}
	page, err := s.ListUsers(ctx, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 2 {
		t.Fatalf("page len = %d", len(page))
	}
	if page[0].ID >= page[1].ID {
		t.Fatalf("page not ordered: %+v", page)
	}
	// Offset beyond the end is empty, not an error.
	empty, _ := s.ListUsers(ctx, 10, 100)
	if len(empty) != 0 {
		t.Fatalf("beyond-end page = %+v", empty)
	}
}
