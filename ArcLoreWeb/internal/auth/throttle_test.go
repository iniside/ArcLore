package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// --- allow() ---

func TestThrottleAllow_BurstThenDeny(t *testing.T) {
	const burst = 2
	lt := newLoginThrottle(burst, 10*time.Millisecond)

	for i := 0; i < burst; i++ {
		if !lt.allow("key1") {
			t.Fatalf("call %d/%d: expected allow, got deny", i+1, burst)
		}
	}
	if lt.allow("key1") {
		t.Fatal("burst+1 call: expected deny, got allow")
	}
}

func TestThrottleAllow_RefillPermitsAgain(t *testing.T) {
	const burst = 2
	refill := 10 * time.Millisecond
	lt := newLoginThrottle(burst, refill)

	// exhaust
	for i := 0; i < burst; i++ {
		lt.allow("key1")
	}
	if lt.allow("key1") {
		t.Fatal("should be denied after exhaustion")
	}

	// wait for at least one token to refill
	time.Sleep(refill * 2)

	if !lt.allow("key1") {
		t.Fatal("expected allow after refill wait, got deny")
	}
}

func TestThrottleAllow_KeysAreIndependent(t *testing.T) {
	const burst = 1
	lt := newLoginThrottle(burst, 10*time.Millisecond)

	// exhaust key A
	if !lt.allow("keyA") {
		t.Fatal("keyA first call should allow")
	}
	if lt.allow("keyA") {
		t.Fatal("keyA burst+1 should deny")
	}

	// key B is unaffected
	if !lt.allow("keyB") {
		t.Fatal("keyB should be allowed (independent bucket)")
	}
}

// --- clientIP() ---

func TestClientIP_RemoteAddrNoTrust(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "1.2.3.4:5678"
	r.Header.Set("X-Forwarded-For", "9.9.9.9")

	got := clientIP(r, false)
	if got != "1.2.3.4" {
		t.Fatalf("want 1.2.3.4, got %s", got)
	}
}

func TestClientIP_XFFWithTrust(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "1.2.3.4:5678"
	r.Header.Set("X-Forwarded-For", "5.6.7.8, 9.9.9.9")

	got := clientIP(r, true)
	if got != "5.6.7.8" {
		t.Fatalf("want 5.6.7.8 (leftmost XFF), got %s", got)
	}
}

func TestClientIP_XFFTrustButNoHeader_FallsBackToRemoteAddr(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "1.2.3.4:5678"
	// no X-Forwarded-For

	got := clientIP(r, true)
	if got != "1.2.3.4" {
		t.Fatalf("want 1.2.3.4 (RemoteAddr fallback), got %s", got)
	}
}

// --- Middleware() ---

func newOKHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestThrottleMiddleware_AllowsThenReturns429(t *testing.T) {
	const burst = 2
	lt := newLoginThrottle(burst, 10*time.Millisecond)
	mw := lt.Middleware(false)(newOKHandler())

	for i := 0; i < burst; i++ {
		r := httptest.NewRequest("POST", "/auth/login", nil)
		r.RemoteAddr = "10.0.0.1:1234"
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("call %d/%d: want 200, got %d", i+1, burst, w.Code)
		}
	}

	r := httptest.NewRequest("POST", "/auth/login", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("burst+1: want 429, got %d", w.Code)
	}
}

func TestThrottleMiddleware_DifferentRemoteAddrOwnBucket(t *testing.T) {
	const burst = 1
	lt := newLoginThrottle(burst, 10*time.Millisecond)
	mw := lt.Middleware(false)(newOKHandler())

	// exhaust bucket for client A
	reqA := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/auth/login", nil)
		r.RemoteAddr = "10.0.0.1:1234"
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, r)
		return w
	}
	if reqA().Code != http.StatusOK {
		t.Fatal("client A first call: want 200")
	}
	if reqA().Code != http.StatusTooManyRequests {
		t.Fatal("client A second call: want 429")
	}

	// client B has its own bucket — should still pass
	r := httptest.NewRequest("POST", "/auth/login", nil)
	r.RemoteAddr = "10.0.0.2:1234"
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("client B: want 200, got %d", w.Code)
	}
}
