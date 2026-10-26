// Command loadtest drives N concurrent authenticated WebSocket clients
// against a GoChat server (distributed or single-node), measures
// end-to-end delivery latency percentiles and reports errors.
//
// Usage:
//
//	loadtest -server http://127.0.0.1:8080 -users 1000 -rooms 50 \
//	        -senders 10 -rate 20 -duration 30s -logins 200
//
// Users are registered and logged in (in batches of -logins to keep the
// load test itself from becoming the bottleneck), each connects one
// WebSocket session and joins a uniformly random room plus the shared
// "general" room. -senders goroutines emit messages at -rate msg/s each
// into their assigned room. Every message carries a client timestamp;
// every receiving client measures the time from send to delivery and
// the harness reports latency percentiles plus delivered/error counts.
//
// Run the server first; point -server at the node (or the nginx/Caddy
// load balancer in cluster mode).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Sh4wnK/GoChat/internal/protocol"
	"github.com/Sh4wnK/GoChat/pkg/client"
)

type config struct {
	server   string
	users    int
	rooms    int
	senders  int
	rate     int
	duration time.Duration
	logins   int
}

var (
	started   = time.Now()
	latMu     sync.Mutex
	latencies []time.Duration
	sent      int64
	delivered int64
	errCount  int64
	sessionMu sync.Mutex
)

func main() {
	cfg := parseFlags()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	fmt.Printf("gochat loadtest: server=%s users=%d rooms=%d senders=%d rate=%d/s duration=%s\n",
		cfg.server, cfg.users, cfg.rooms, cfg.senders, cfg.rate, cfg.duration)
	if cfg.users < 1 || cfg.rooms < 1 {
		fmt.Fprintln(os.Stderr, "users and rooms must be >= 1")
		os.Exit(2)
	}
	if cfg.senders < 1 {
		cfg.senders = 8
	}
	if cfg.senders > cfg.users {
		cfg.senders = cfg.users
	}

	// ----- register + login users in batches -----
	userCh := make(chan *client.Client, cfg.users)
	errCh := make(chan error, cfg.users)
	batch := cfg.logins
	if batch <= 0 {
		batch = 200
	}
	var wg sync.WaitGroup
	for b := 0; b < cfg.users; b += batch {
		n := batch
		if b+n > cfg.users {
			n = cfg.users - b
		}
		wg.Add(1)
		go func(base, n int) {
			defer wg.Done()
			for i := 0; i < n; i++ {
				u := fmt.Sprintf("load_%05d", base+i)
				cc := client.New(cfg.server)
				// Registration may fail because a previous run already
				// created the account (409); login still works.
				if _, err := cc.Register(ctx, u, "password123", u); err != nil {
					if err := loginResilient(ctx, cc, u); err != nil {
						errCh <- fmt.Errorf("user %s: %w", u, err)
					} else {
						userCh <- cc
					}
					continue
				}
				if _, err := cc.Login(ctx, u, "password123"); err != nil {
					errCh <- fmt.Errorf("login %s: %w", u, err)
					continue
				}
				userCh <- cc
			}
		}(b, n)
	}
	wg.Wait()
	close(userCh)
	close(errCh)
	for err := range errCh {
		fmt.Println("setup error:", err)
	}
	var users []*client.Client
	for cc := range userCh {
		users = append(users, cc)
	}
	fmt.Printf("registered+logged in %d users (%s)\n", len(users), time.Since(started).Round(time.Millisecond))
	if len(users) == 0 {
		fmt.Fprintln(os.Stderr, "no users registered; aborting")
		os.Exit(1)
	}

	// ----- create the bench rooms -----
	roomNames := make([]string, cfg.rooms)
	for i := range roomNames {
		roomNames[i] = fmt.Sprintf("bench_%d", i)
	}
	if len(users) > 0 {
		creator := users[0]
		csess, err := creator.Dial(ctx, "")
		if err == nil {
			for _, name := range roomNames {
				if err := csess.CreateRoom(ctx, name, "bench"); err != nil {
					// ignore: maybe the room already exists
				}
			}
			time.Sleep(100 * time.Millisecond) // let replicas observe creation
			csess.Close()
		}
	}

	// ----- connect one session per user, join a random room -----
	sem := make(chan struct{}, 256)
	var dialWG sync.WaitGroup
	var dialOK, dialErr int64
	var sessions []*sessionRec
	for _, cc := range users {
		dialWG.Add(1)
		sem <- struct{}{}
		go func(cc *client.Client) {
			defer dialWG.Done()
			defer func() { <-sem }()
			sess, err := cc.Dial(ctx, "")
			if err != nil {
				atomic.AddInt64(&dialErr, 1)
				return
			}
			room := roomNames[hashStr(cc.PublicKey()+cc.Token())%len(roomNames)]
			if err := sess.Join(ctx, room); err != nil {
				atomic.AddInt64(&dialErr, 1)
				return
			}
			sessionMu.Lock()
			sessions = append(sessions, &sessionRec{sess: sess, room: room})
			sessionMu.Unlock()
			atomic.AddInt64(&dialOK, 1)
		}(cc)
	}
	dialWG.Wait()
	fmt.Printf("connected %d sessions, %d failed (%s)\n", dialOK, dialErr, time.Since(started).Round(time.Millisecond))
	if dialOK == 0 {
		fmt.Fprintln(os.Stderr, "no sessions connected; aborting")
		os.Exit(1)
	}

	// ----- measurement stage -----
	stageCtx, stageCancel := context.WithTimeout(ctx, cfg.duration)
	defer stageCancel()
	t0 := time.Now()
	barrier := make(chan struct{})
	var stageWG sync.WaitGroup

	// Consumers: every client measures delivery of sender-stamped messages.
	for _, rec := range sessions {
		stageWG.Add(1)
		go func(rec *sessionRec) {
			defer stageWG.Done()
			<-barrier
			consume(rec.sess, stageCtx)
		}(rec)
	}
	// Senders: cfg.senders goroutines at cfg.rate msg/s each.
	for i := 0; i < cfg.senders; i++ {
		stageWG.Add(1)
		go func(i int) {
			defer stageWG.Done()
			sessionMu.Lock()
			rec := sessions[i%len(sessions)]
			sessionMu.Unlock()
			<-barrier
			t := time.NewTicker(time.Second / time.Duration(cfg.rate))
			defer t.Stop()
			seq := 0
			for {
				select {
				case <-stageCtx.Done():
					return
				case <-t.C:
					seq++
					body := fmt.Sprintf("bench seq=%d ts=%d", seq, time.Now().UnixMilli())
					if err := rec.sess.SendMessage(stageCtx, rec.room, "", body); err != nil {
						atomic.AddInt64(&errCount, 1)
						return
					}
					atomic.AddInt64(&sent, 1)
				}
			}
		}(i)
	}
	close(barrier)
	stageWG.Wait()

	report(cfg, t0)
}

type sessionRec struct {
	sess *client.Session
	room string
}

func consume(s *client.Session, ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-s.Events:
			if !ok {
				return
			}
			if ev.Type != protocol.EvMessage {
				continue
			}
			var m protocol.Message
			if err := json.Unmarshal(ev.Data, &m); err != nil {
				continue
			}
			var seq int
			var ts int64
			if _, err := fmt.Sscanf(m.Body, "bench seq=%d ts=%d", &seq, &ts); err != nil {
				continue
			}
			lat := time.Since(time.UnixMilli(ts))
			if lat < 0 {
				continue // sender clock skew between machines
			}
			atomic.AddInt64(&delivered, 1)
			latMu.Lock()
			latencies = append(latencies, lat)
			latMu.Unlock()
		}
	}
}

// loginResilient logs in an existing account (register returned 409).
func loginResilient(ctx context.Context, cc *client.Client, username string) error {
	if _, err := cc.Login(ctx, username, "password123"); err != nil {
		return fmt.Errorf("login %s: %w", username, err)
	}
	return nil
}

func hashStr(s string) int {
	h := 0
	for _, r := range s {
		h = h*31 + int(r)
	}
	if h < 0 {
		h = -h
	}
	return h
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.server, "server", "http://127.0.0.1:8080", "server base URL")
	flag.IntVar(&cfg.users, "users", 1000, "number of concurrent clients")
	flag.IntVar(&cfg.rooms, "rooms", 50, "number of rooms to distribute clients across")
	flag.IntVar(&cfg.senders, "senders", 8, "number of concurrent message senders")
	flag.IntVar(&cfg.rate, "rate", 20, "messages per second per sender")
	flag.DurationVar(&cfg.duration, "duration", 30*time.Second, "measurement window")
	flag.IntVar(&cfg.logins, "logins", 200, "registration/login batch size")
	flag.Parse()
	return cfg
}

func report(cfg config, t0 time.Time) {
	elapsed := time.Since(t0)
	latMu.Lock()
	defer latMu.Unlock()
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	pct := func(q float64) time.Duration {
		if len(latencies) == 0 {
			return 0
		}
		idx := int(math.Ceil(q*float64(len(latencies)))) - 1
		if idx < 0 {
			idx = 0
		}
		return latencies[idx]
	}
	fmt.Printf("\n--- results (%s elapsed, %d concurrent clients) ---\n", elapsed.Round(time.Millisecond), cfg.users)
	// Each sent message is fanned out to every subscriber of its room,
	// so "delivery events" = sum over receivers; the useful rate is
	// events/time.
	eventsPerSec := float64(delivered) / elapsed.Seconds()
	fmt.Printf("messages sent: %d, delivery events observed: %d (%.0f events/s), send errors: %d\n",
		sent, delivered, eventsPerSec, errCount)
	if len(latencies) > 0 {
		fmt.Printf("delivery latency p50   %s\n", pct(0.50).Round(time.Microsecond))
		fmt.Printf("delivery latency p90   %s\n", pct(0.90).Round(time.Microsecond))
		fmt.Printf("delivery latency p95   %s\n", pct(0.95).Round(time.Microsecond))
		fmt.Printf("delivery latency p99   %s\n", pct(0.99).Round(time.Microsecond))
		fmt.Printf("delivery latency max   %s\n", latencies[len(latencies)-1].Round(time.Microsecond))
	} else {
		fmt.Println("no latency samples (did messages get delivered?)")
	}
}
