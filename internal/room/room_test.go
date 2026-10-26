package room

import (
	"errors"
	"testing"

	"github.com/Sh4wnK/GoChat/internal/model"
)

func u(id string) model.User { return model.User{ID: id, Username: id, DisplayName: id} }

func TestCreateJoinLeave(t *testing.T) {
	m := NewManager()
	r, err := m.CreateRoom("lobby", "main room")
	if err != nil || r.Name != "lobby" {
		t.Fatalf("create: %+v %v", r, err)
	}
	if _, err := m.CreateRoom("lobby", ""); !errors.Is(err, ErrRoomExists) {
		t.Fatalf("duplicate create err = %v", err)
	}
	members, hist, err := m.Join("lobby", u("a1"))
	if err != nil || len(members) != 1 || len(hist) != 0 {
		t.Fatalf("join: %v %v %v", members, hist, err)
	}
	if _, _, err := m.Join("lobby", u("a1")); !errors.Is(err, ErrAlreadyMember) {
		t.Fatalf("double join err = %v", err)
	}
	if _, _, err := m.Join("nope", u("a1")); !errors.Is(err, ErrRoomNotFound) {
		t.Fatalf("join missing room err = %v", err)
	}
	if err := m.Leave("lobby", "a1"); err != nil {
		t.Fatalf("leave: %v", err)
	}
	if err := m.Leave("lobby", "a1"); !errors.Is(err, ErrNotMember) {
		t.Fatalf("double leave err = %v", err)
	}
}

func TestBoundedHistory(t *testing.T) {
	m := NewManager()
	m.CreateRoom("r", "")
	for i := 0; i < HistoryLimit+50; i++ {
		m.Join("r", u(itoa(i)))
		m.AppendHistory("r", model.Message{ID: itoa(i), Room: "r"})
	}
	hist, err := m.History("r")
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != HistoryLimit {
		t.Fatalf("history len = %d, want %d", len(hist), HistoryLimit)
	}
	if hist[0].ID != "50" || hist[len(hist)-1].ID != itoa(HistoryLimit+49) {
		t.Fatalf("history did not evict oldest: first=%s last=%s", hist[0].ID, hist[len(hist)-1].ID)
	}
}

func TestPresenceLimit(t *testing.T) {
	m := NewManager()
	m.CreateRoom("big", "")
	for i := 0; i < PresenceLimit+100; i++ {
		m.Join("big", u(itoa(i)))
	}
	members, _ := m.Members("big")
	if len(members) != PresenceLimit {
		t.Fatalf("members = %d, want %d", len(members), PresenceLimit)
	}
}

func TestDeleteRoom(t *testing.T) {
	m := NewManager()
	m.CreateRoom("tmp", "")
	m.Join("tmp", u("a1"))
	if err := m.DeleteRoom("tmp"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Get("tmp"); !errors.Is(err, ErrRoomNotFound) {
		t.Fatalf("get after delete err = %v", err)
	}
	if err := m.DeleteRoom("tmp"); !errors.Is(err, ErrRoomNotFound) {
		t.Fatalf("double delete err = %v", err)
	}
}

func TestListOrder(t *testing.T) {
	m := NewManager()
	m.CreateRoom("b", "")
	m.CreateRoom("a", "")
	m.CreateRoom("c", "")
	rooms := m.List()
	if rooms[0].Name != "b" || rooms[1].Name != "a" || rooms[2].Name != "c" {
		t.Fatalf("order = %+v", rooms)
	}
	m.DeleteRoom("a")
	rooms = m.List()
	if len(rooms) != 2 || rooms[0].Name != "b" || rooms[1].Name != "c" {
		t.Fatalf("after delete: %+v", rooms)
	}
}

func itoa(n int) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	var buf [32]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = digits[n%10]
		n /= 10
	}
	return string(buf[i:])
}
