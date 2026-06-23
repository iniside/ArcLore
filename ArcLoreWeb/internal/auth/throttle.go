package auth

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// bucket is one client's token-bucket state for the login throttle. tokens are
// refilled lazily on each allow() call from the elapsed time since last.
type bucket struct {
	tokens float64
	last   time.Time
}

// loginThrottle is a per-IP token-bucket rate limiter for the unsafe auth POSTs
// (login + first-run setup). It mirrors arc-lore-auth's web.go rateLimiter: a
// fixed burst capacity refilled one token per refill interval, with a bounded
// map that is periodically trimmed of stale buckets so memory can't grow
// unbounded under a flood of distinct (or spoofed) keys.
//
// This sits at the web tier, in FRONT of arc-lore-auth, because arc-lore-auth's
// own per-IP limiter keys on the caller IP — which for browser logins is always
// the web server's single IP, collapsing every browser into one shared bucket.
// Keying here on the browser's RemoteAddr (or X-Forwarded-For behind a trusted
// proxy) restores per-browser brute-force defense.
type loginThrottle struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	burst    int
	refill   time.Duration
	lastTrim time.Time
}

// newLoginThrottle builds a throttle with the given burst capacity and refill
// interval (one token per refill).
func newLoginThrottle(burst int, refill time.Duration) *loginThrottle {
	return &loginThrottle{
		buckets:  make(map[string]*bucket),
		burst:    burst,
		refill:   refill,
		lastTrim: time.Now(),
	}
}

// allow refills the key's bucket by elapsed/refill (capped at burst), consumes
// one token, and reports whether the request is permitted. It also trims stale
// buckets when the map grows or the last trim is old, bounding memory.
func (t *loginThrottle) allow(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	t.maybeTrim(now)

	b := t.buckets[key]
	if b == nil {
		b = &bucket{tokens: float64(t.burst), last: now}
		t.buckets[key] = b
	} else {
		elapsed := now.Sub(b.last)
		b.tokens += elapsed.Seconds() / t.refill.Seconds()
		if b.tokens > float64(t.burst) {
			b.tokens = float64(t.burst)
		}
		b.last = now
	}

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// maybeTrim drops fully-refilled (idle) buckets when the map has grown past a
// soft threshold or the last trim is older than a few refill intervals. Called
// under t.mu.
func (t *loginThrottle) maybeTrim(now time.Time) {
	if len(t.buckets) < 1024 && now.Sub(t.lastTrim) < 10*t.refill {
		return
	}
	for k, b := range t.buckets {
		// A bucket idle long enough to be back at full capacity carries no
		// state worth keeping — its key would start fresh anyway.
		refilled := b.tokens + now.Sub(b.last).Seconds()/t.refill.Seconds()
		if refilled >= float64(t.burst) {
			delete(t.buckets, k)
		}
	}
	t.lastTrim = now
}

// clientIP resolves the throttle key for a request. By default it is the host
// part of RemoteAddr (the direct peer). When trustXFF is set and the request
// carries a non-empty X-Forwarded-For, the leftmost (original client) entry is
// used instead — only safe behind a known proxy, as XFF is client-spoofable.
func clientIP(r *http.Request, trustXFF bool) string {
	if trustXFF {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first := strings.TrimSpace(strings.Split(xff, ",")[0])
			if first != "" {
				return first
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Middleware guards a handler chain: requests from a key that has exhausted its
// bucket get a 429 and are dropped; everything else passes through.
func (t *loginThrottle) Middleware(trustXFF bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !t.allow(clientIP(r, trustXFF)) {
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte("too many login attempts — slow down"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// NewLoginThrottle is the exported constructor used by the server to build the
// per-browser login/setup rate limiter.
func NewLoginThrottle(burst int, refill time.Duration) *LoginThrottle {
	return (*LoginThrottle)(newLoginThrottle(burst, refill))
}

// LoginThrottle is the exported handle over the unexported loginThrottle so the
// main package can construct one and mount its Middleware.
type LoginThrottle loginThrottle

// Middleware exposes the throttle as chi/net-http middleware. trustXFF selects
// the X-Forwarded-For key resolution (set when behind a trusted proxy).
func (t *LoginThrottle) Middleware(trustXFF bool) func(http.Handler) http.Handler {
	return (*loginThrottle)(t).Middleware(trustXFF)
}
