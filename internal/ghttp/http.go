// Package ghttp provides the brief HTTP helpers used by the server:
// JSON responses, JSON error responses, bearer token extraction and
// cross-origin checking.
package ghttp

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
)

// Origin returns the effective Origin header ("" when missing).
func Origin(req *http.Request) string {
	return req.Header.Get("Origin")
}

// DenyIfCrossOrigin rejects cross-origin requests when the Origin header
// is not in the configured allowlist. Returns true when processing may
// continue; false when a 403 has been written and the request should be
// aborted. Requests without an Origin header (non-browser clients) pass.
func DenyIfCrossOrigin(log *slog.Logger, allowed []string, w http.ResponseWriter, req *http.Request) bool {
	origin := Origin(req)
	if origin == "" {
		return true
	}
	for _, a := range allowed {
		if a == "*" || strings.EqualFold(origin, a) {
			return true
		}
	}
	log.Warn("blocked cross-origin request", "origin", origin, "path", req.URL.Path)
	Error(w, http.StatusForbidden, "cross-origin request denied")
	return false
}

// JSON writes v as a JSON response.
func JSON(w http.ResponseWriter, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		Error(w, http.StatusInternalServerError, "serialization failed")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// Error writes a JSON error response with the given HTTP status.
// The body carries {"error": <code>, "message": <msg>}.
func Error(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(fmtErr(status, msg))
}

func fmtErr(status int, msg string) []byte {
	code := "error"
	switch status {
	case http.StatusBadRequest:
		code = "bad_request"
	case http.StatusUnauthorized:
		code = "unauthorized"
	case http.StatusForbidden:
		code = "forbidden"
	case http.StatusNotFound:
		code = "not_found"
	case http.StatusConflict:
		code = "conflict"
	case http.StatusTooManyRequests:
		code = "rate_limited"
	case http.StatusInternalServerError:
		code = "internal"
	}
	b, _ := json.Marshal(map[string]string{"error": code, "message": msg})
	return b
}

// Bearer extracts the Bearer token from the Authorization header.
func Bearer(req *http.Request) string {
	v := req.Header.Get("Authorization")
	if len(v) < 8 || !strings.HasPrefix(v, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(v[7:])
}

// CORS writes permissive CORS headers for API tooling.
func CORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
}
