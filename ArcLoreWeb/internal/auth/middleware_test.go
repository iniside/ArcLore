package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alexedwards/scs/v2"
)

// loginSession performs a synthetic login by running a handler under
// sessions.LoadAndSave that stores the supplied identity fields, and returns
// the session cookie so the next request can carry it.
func loginSession(t *testing.T, sessions *scs.SessionManager, sub, name, token string, expiresAt int64, isAdmin bool) *http.Cookie {
	t.Helper()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		StoreIdentity(sessions, w, r, sub, name, token, expiresAt, isAdmin)
		w.WriteHeader(http.StatusOK)
	})
	handler := sessions.LoadAndSave(inner)

	r := httptest.NewRequest("GET", "/login-callback", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	for _, c := range w.Result().Cookies() {
		if c.Name == "session" {
			return c
		}
	}
	t.Fatal("loginSession: no session cookie in response")
	return nil
}

// doRequireAuth runs r (which must already carry a session cookie) through
// sessions.LoadAndSave → RequireAuth → a trivial 200 inner handler and
// returns the recorded response.
func doRequireAuth(sessions *scs.SessionManager, r *http.Request) *httptest.ResponseRecorder {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := sessions.LoadAndSave(RequireAuth(sessions)(inner))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

// TestRequireAuth_NoSession redirects to /auth/login when no session is present.
func TestRequireAuth_NoSession(t *testing.T) {
	sessions := NewSessionManager(false, "")
	r := httptest.NewRequest("GET", "/protected", nil)
	w := doRequireAuth(sessions, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("no session: want 303, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/auth/login" {
		t.Errorf("no session: want redirect to /auth/login, got %q", loc)
	}
}

// TestRequireAuth_FreshSession passes through when the token expiry is in the
// future (or zero/unset).
func TestRequireAuth_FreshSession(t *testing.T) {
	sessions := NewSessionManager(false, "")
	futureExp := time.Now().Add(1 * time.Hour).Unix()
	cookie := loginSession(t, sessions, "alice", "Alice", "tok", futureExp, false)

	r := httptest.NewRequest("GET", "/protected", nil)
	r.AddCookie(cookie)
	w := doRequireAuth(sessions, r)
	if w.Code != http.StatusOK {
		t.Fatalf("fresh session: want 200, got %d", w.Code)
	}
}

// TestRequireAuth_ExpiredSession destroys the session and redirects to
// /auth/login when the stored token expiry is in the past.
func TestRequireAuth_ExpiredSession(t *testing.T) {
	sessions := NewSessionManager(false, "")
	pastExp := time.Now().Add(-1 * time.Minute).Unix()
	cookie := loginSession(t, sessions, "bob", "Bob", "expired-tok", pastExp, false)

	r := httptest.NewRequest("GET", "/protected", nil)
	r.AddCookie(cookie)
	w := doRequireAuth(sessions, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("expired session: want 303 redirect, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/auth/login" {
		t.Errorf("expired session: want redirect to /auth/login, got %q", loc)
	}
}

// TestRequireAuth_ZeroExpiry passes through when token_expiry is zero (legacy
// or dev sessions that never stored an expiry).
func TestRequireAuth_ZeroExpiry(t *testing.T) {
	sessions := NewSessionManager(false, "")
	// expiresAt=0 means "no expiry stored" — must not evict.
	cookie := loginSession(t, sessions, "carol", "Carol", "no-exp-tok", 0, false)

	r := httptest.NewRequest("GET", "/protected", nil)
	r.AddCookie(cookie)
	w := doRequireAuth(sessions, r)
	if w.Code != http.StatusOK {
		t.Fatalf("zero-expiry session: want 200 (pass-through), got %d", w.Code)
	}
}
