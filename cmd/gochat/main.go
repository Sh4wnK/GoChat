// Command gochat runs the GoChat server: REST API, WebSocket hub and
// the embedded browser client.
//
// Configuration comes from environment variables (see README):
//
//	GOCHAT_ADDR          listen address (default :8080)
//	GOCHAT_JWT_SECRET    HMAC signing secret, >= 32 bytes (random when unset)
//	GOCHAT_DATABASE_URL  PostgreSQL DSN; unset = in-memory store
//	GOCHAT_REDIS_ADDR    Redis address for cluster mode; unset = local broker
//	GOCHAT_ALLOWED_ORIGINS comma-separated CORS allowlist ("*" = any)
package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"errors"
	"flag"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Sh4wnK/GoChat/internal/auth"
	"github.com/Sh4wnK/GoChat/internal/broker"
	"github.com/Sh4wnK/GoChat/internal/hub"
	"github.com/Sh4wnK/GoChat/internal/room"
	"github.com/Sh4wnK/GoChat/internal/server"
	"github.com/Sh4wnK/GoChat/internal/userstore"
)

//go:embed web
var webFS embed.FS

func main() {
	var (
		addr      = flag.String("addr", envOr("GOCHAT_ADDR", ":8080"), "listen address")
		jwtSecret = flag.String("jwt-secret", envOr("GOCHAT_JWT_SECRET", ""), "JWT signing secret (env GOCHAT_JWT_SECRET)")
		dbURL     = flag.String("db", envOr("GOCHAT_DATABASE_URL", ""), "PostgreSQL DSN (env GOCHAT_DATABASE_URL); empty = in-memory")
		redisAddr = flag.String("redis", envOr("GOCHAT_REDIS_ADDR", ""), "Redis address (env GOCHAT_REDIS_ADDR); empty = single node")
		origins   = flag.String("origins", envOr("GOCHAT_ALLOWED_ORIGINS", "*"), "comma-separated allowed origins")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(log)

	// ----- storage -----
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var store userstore.Store
	if *dbURL != "" {
		pg, err := userstore.NewPostgres(ctx, *dbURL)
		if err != nil {
			log.Error("postgres connection failed", "err", err)
			os.Exit(1)
		}
		defer pg.Close()
		store = pg
		log.Info("using postgres store")
	} else {
		store = userstore.NewInMemory()
		log.Info("using in-memory store (GOCHAT_DATABASE_URL unset)")
	}

	// ----- signing key -----
	secret := []byte(*jwtSecret)
	if len(secret) < 32 {
		secret = randomSecret()
		log.Warn("GOCHAT_JWT_SECRET unset or too short; generated an ephemeral secret (sessions invalidate on restart)", "len", len(secret))
	}
	signer := auth.NewSigner(auth.TokenConfig{
		Secret: secret,
		TTL:    24 * time.Hour,
		Issuer: "gochat",
	})

	// ----- broker (cluster mode) -----
	var br broker.Broker
	if *redisAddr != "" {
		r := broker.NewRedis(*redisAddr, log)
		pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := r.Ping(pingCtx)
		cancel()
		if err != nil {
			log.Error("redis unreachable", "addr", *redisAddr, "err", err)
			os.Exit(1)
		}
		br = r
		log.Info("cluster mode: redis broker", "addr", *redisAddr)
	} else {
		br = broker.NewLocal("local-node")
		log.Info("single node: local broker")
	}

	// ----- server -----
	rooms := room.NewManager()
	rooms.CreateRoom("general", "Welcome to GoChat!")

	web, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Error("embed web", "err", err)
		os.Exit(1)
	}
	server.StaticFiles = web

	srv, err := server.New(ctx, server.Config{
		NodeID:         hostID(),
		Signer:         signer,
		Store:          store,
		Rooms:          rooms,
		Broker:         br,
		HubCfg:         &hub.Config{},
		Log:            log,
		AllowedOrigins: splitCSV(*origins),
	})
	if err != nil {
		log.Error("server init", "err", err)
		os.Exit(1)
	}
	defer srv.Close()

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Info("gochat listening", "addr", *addr, "node", hostID())
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("listen", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	log.Info("shutdown complete")
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

// hostID returns a stable per-boot node identifier.
func hostID() string {
	host, _ := os.Hostname()
	return host + "-" + shortID()
}

func shortID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randomSecret() []byte {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
