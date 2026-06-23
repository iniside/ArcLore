package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// sessionStatus is the lifecycle state of an interactive-login session.
type sessionStatus int

const (
	sessionPending sessionStatus = iota
	sessionComplete
)

// authSession is one interactive-login handshake in flight.
//
//   - clientState correlates the CLI's StartAuthSession with its GetAuthSession
//     polls (a sanity check, NOT the security boundary — session_code is the secret).
//   - mintedToken / username / expiresAtMs are populated by the web /login POST
//     when it flips the session pending → complete.
type authSession struct {
	clientState string
	status      sessionStatus
	username    string
	mintedToken string
	expiresAtMs int64
	created     time.Time
}

// SessionStore is the SINGLE shared store for interactive-login sessions. ONE
// instance is constructed in main.go and injected into BOTH the gRPC server and
// (Step 3) the HTTP handler set: the gRPC Start/GetAuthSession methods and the
// web /login POST must read/write the SAME map, or the handshake never closes
// (split-brain). It is therefore a concrete type behind a mutex — never a
// package-level var.
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]*authSession
	ttl      time.Duration
}

// NewSessionStore builds an empty store with the given session TTL. ttl<=0 falls
// back to the 600s default.
func NewSessionStore(ttl time.Duration) *SessionStore {
	if ttl <= 0 {
		ttl = 600 * time.Second
	}
	return &SessionStore{
		sessions: make(map[string]*authSession),
		ttl:      ttl,
	}
}

// newSessionCode returns a 32-byte (256-bit) crypto-random, base64url-encoded
// capability secret. 256 bits is well past the ≥128-bit floor.
func newSessionCode() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating session code: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// expired reports whether s has aged past the store TTL (relative to now).
func (st *SessionStore) expired(s *authSession, now time.Time) bool {
	return now.Sub(s.created) > st.ttl
}

// Create registers a new pending session bound to clientState and returns its
// session_code (the capability secret).
func (st *SessionStore) Create(clientState string) (string, error) {
	code, err := newSessionCode()
	if err != nil {
		return "", err
	}

	st.mu.Lock()
	defer st.mu.Unlock()
	st.sessions[code] = &authSession{
		clientState: clientState,
		status:      sessionPending,
		created:     time.Now(),
	}
	return code, nil
}

// Get returns a SHALLOW COPY of the session for the web layer to validate
// (pending + unexpired) before showing/accepting the login form. A copy avoids
// handing the caller a pointer into the locked map. Expired sessions report
// ok=false (and are not returned).
func (st *SessionStore) Get(code string) (*authSession, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()

	s, ok := st.sessions[code]
	if !ok {
		return nil, false
	}
	if st.expired(s, time.Now()) {
		delete(st.sessions, code)
		return nil, false
	}
	cp := *s
	return &cp, true
}

// Complete flips a pending session to complete, stamping the minted token,
// username, and expiry (milliseconds). It errors on unknown/expired sessions and
// on a session that is not pending (already completed → cannot re-complete).
func (st *SessionStore) Complete(code, username, token string, expiresAtMs int64) error {
	st.mu.Lock()
	defer st.mu.Unlock()

	s, ok := st.sessions[code]
	if !ok {
		return fmt.Errorf("unknown session")
	}
	if st.expired(s, time.Now()) {
		delete(st.sessions, code)
		return fmt.Errorf("session expired")
	}
	if s.status != sessionPending {
		return fmt.Errorf("session not pending")
	}

	s.status = sessionComplete
	s.username = username
	s.mintedToken = token
	s.expiresAtMs = expiresAtMs
	return nil
}

// Take is the single-use consume on the CLI poll path. Under ONE lock it:
//   - looks the session up; not found / expired / not yet complete → ok=false;
//   - rejects a clientState mismatch (CLI-correlation sanity check) → ok=false;
//   - on a complete + matching session: returns the token + expiry AND deletes
//     the session, all atomically.
//
// The single-lock guarantee is the point: a concurrent Take or the eviction
// sweep can never double-deliver the token nor wipe it between read and delete.
func (st *SessionStore) Take(code, clientState string) (token string, expiresAtMs int64, ok bool) {
	st.mu.Lock()
	defer st.mu.Unlock()

	s, found := st.sessions[code]
	if !found {
		return "", 0, false
	}
	if st.expired(s, time.Now()) {
		delete(st.sessions, code)
		return "", 0, false
	}
	if s.clientState != clientState {
		// Correlation mismatch — keep the session (a legitimate poll with the
		// right state may still arrive) but do not deliver.
		return "", 0, false
	}
	if s.status != sessionComplete {
		// Pending — keep polling.
		return "", 0, false
	}

	token = s.mintedToken
	expiresAtMs = s.expiresAtMs
	delete(st.sessions, code) // single-use: consumed on first successful delivery.
	return token, expiresAtMs, true
}

// sweepExpired evicts every session older than the TTL. Returns the count
// removed (for logging/tests). Two-pass: collect dead keys under the lock, then
// delete — never mutate the map while ranging it for removal decisions.
func (st *SessionStore) sweepExpired() int {
	now := time.Now()

	st.mu.Lock()
	defer st.mu.Unlock()

	dead := make([]string, 0)
	for code, s := range st.sessions {
		if st.expired(s, now) {
			dead = append(dead, code)
		}
	}
	for _, code := range dead {
		delete(st.sessions, code)
	}
	return len(dead)
}

// StartEvictionLoop runs a background sweep every TTL/2 (min 30s) until stop is
// closed. Call once from the daemon.
func (st *SessionStore) StartEvictionLoop(stop <-chan struct{}) {
	interval := st.ttl / 2
	if interval < 30*time.Second {
		interval = 30 * time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				st.sweepExpired()
			}
		}
	}()
}
