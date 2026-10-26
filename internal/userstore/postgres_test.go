package userstore

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
)

// startEmbedded starts a real PostgreSQL server in a temp dir. Tests are
// skipped when the embedded binary cannot be downloaded (offline CI).
func startEmbedded(t *testing.T) (*embeddedpostgres.EmbeddedPostgres, string) {
	t.Helper()
	port := 15432 + testPortOffset()
	ep := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Port(uint32(port)).
		Version(embeddedpostgres.V16).
		StartTimeout(120 * time.Second))
	if err := ep.Start(); err != nil {
		t.Skipf("embedded postgres unavailable (%v); skipping", err)
	}
	t.Cleanup(func() { _ = ep.Stop() })
	dsn := fmt.Sprintf("postgres://postgres:postgres@127.0.0.1:%d/postgres?sslmode=disable", port)
	return ep, dsn
}

var portCounter int

func testPortOffset() int {
	portCounter++
	return portCounter * 10
}

func TestPostgresUserLifecycle(t *testing.T) {
	_, dsn := startEmbedded(t)
	ctx := context.Background()
	p, err := NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	u, err := p.CreateUser(ctx, "alice", "Alice", []byte("$argon2id$v=19$m=1,t=1,p=1$ab$cd"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.CreateUser(ctx, "alice", "x", nil); !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("dup err = %v", err)
	}
	rec, err := p.GetUserByName(ctx, "alice")
	if err != nil || string(rec.Password) != "$argon2id$v=19$m=1,t=1,p=1$ab$cd" {
		t.Fatalf("rec = %+v err = %v", rec, err)
	}
	if err := p.SetPublicKey(ctx, u.ID, "a2V5"); err != nil {
		t.Fatal(err)
	}
	rec, _ = p.GetUserByID(ctx, u.ID)
	if rec.PublicKey != "a2V5" {
		t.Fatalf("key = %q", rec.PublicKey)
	}
	if err := p.UpdateProfile(ctx, u.ID, "Alicia"); err != nil {
		t.Fatal(err)
	}
	if err := p.DeleteUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := p.GetUserByID(ctx, u.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get deleted err = %v", err)
	}
}

func TestPostgresOfflineQueueDedup(t *testing.T) {
	_, dsn := startEmbedded(t)
	ctx := context.Background()
	p, err := NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	u, _ := p.CreateUser(ctx, "bob", "Bob", nil)
	if err := p.EnqueueOffline(ctx, u.ID, "m1", `{"id":"m1"}`); err != nil {
		t.Fatal(err)
	}
	// Same message id: ON CONFLICT DO NOTHING.
	if err := p.EnqueueOffline(ctx, u.ID, "m1", `{"id":"m1"}`); err != nil {
		t.Fatal(err)
	}
	if err := p.EnqueueOffline(ctx, u.ID, "m2", `{"id":"m2"}`); err != nil {
		t.Fatal(err)
	}
	got, err := p.PopOffline(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != `{"id":"m1"}` || got[1] != `{"id":"m2"}` {
		t.Fatalf("offline = %+v", got)
	}
	got, _ = p.PopOffline(ctx, u.ID)
	if len(got) != 0 {
		t.Fatalf("second pop = %+v", got)
	}
}

func TestPostgresMigrationsIdempotent(t *testing.T) {
	_, dsn := startEmbedded(t)
	ctx := context.Background()
	p, err := NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	p.Close()
	// Boot again over the same schema: must succeed.
	p2, err := NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("second boot: %v", err)
	}
	p2.Close()
}
