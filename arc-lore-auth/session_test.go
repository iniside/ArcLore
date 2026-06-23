package main

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ── Create → Complete → Take happy path ──────────────────────────────────────

func TestSessionCreateCompleteTake(t *testing.T) {
	st := NewSessionStore(0) // default TTL

	code, err := st.Create("state-abc")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if code == "" {
		t.Fatal("Create returned empty code")
	}

	if err := st.Complete(code, "alice", "tok-xxx", 9_999_999_000); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	token, expMs, ok := st.Take(code, "state-abc")
	if !ok {
		t.Fatal("Take returned ok=false; want ok=true")
	}
	if token != "tok-xxx" {
		t.Fatalf("Take returned token %q; want %q", token, "tok-xxx")
	}
	if expMs != 9_999_999_000 {
		t.Fatalf("Take returned expiresAtMs %d; want %d", expMs, 9_999_999_000)
	}
}

// ── Single-use: second Take must return ok=false ──────────────────────────────

func TestSessionTakeSingleUse(t *testing.T) {
	st := NewSessionStore(0)

	code, err := st.Create("state-su")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.Complete(code, "bob", "tok-bob", 1_000_000_000); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	_, _, ok1 := st.Take(code, "state-su")
	if !ok1 {
		t.Fatal("first Take returned ok=false")
	}

	_, _, ok2 := st.Take(code, "state-su")
	if ok2 {
		t.Fatal("second Take returned ok=true; session should be consumed after first Take")
	}
}

// ── client_state mismatch → ok=false, session is NOT consumed ────────────────

func TestSessionTakeClientStateMismatch(t *testing.T) {
	st := NewSessionStore(0)

	code, err := st.Create("right-state")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.Complete(code, "carol", "tok-carol", 1_000_000_000); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	// Wrong client_state — must not deliver the token.
	_, _, ok := st.Take(code, "wrong-state")
	if ok {
		t.Fatal("Take with mismatched client_state returned ok=true; want ok=false")
	}

	// The session must still be consumable with the correct state.
	_, _, ok2 := st.Take(code, "right-state")
	if !ok2 {
		t.Fatal("Take with correct client_state after a mismatch returned ok=false; session should survive")
	}
}

// ── Unknown code → ok=false ───────────────────────────────────────────────────

func TestSessionTakeUnknownCode(t *testing.T) {
	st := NewSessionStore(0)
	_, _, ok := st.Take("no-such-code", "any-state")
	if ok {
		t.Fatal("Take with unknown code returned ok=true; want ok=false")
	}
}

// ── Pending session (not yet completed) → Take returns ok=false ──────────────

func TestSessionTakePending(t *testing.T) {
	st := NewSessionStore(0)
	code, err := st.Create("state-pend")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Do NOT call Complete.
	_, _, ok := st.Take(code, "state-pend")
	if ok {
		t.Fatal("Take on pending session returned ok=true; want ok=false (still polling)")
	}
}

// ── Get on pending + unexpired session returns a copy ────────────────────────

func TestSessionGet(t *testing.T) {
	st := NewSessionStore(0)
	code, err := st.Create("state-get")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	sess, ok := st.Get(code)
	if !ok {
		t.Fatal("Get on fresh session returned ok=false")
	}
	if sess == nil {
		t.Fatal("Get returned nil session")
	}
	if sess.status != sessionPending {
		t.Fatalf("Get returned status %v; want sessionPending", sess.status)
	}
}

// ── Expiry: expired sessions are treated as gone ─────────────────────────────

func TestSessionExpiry(t *testing.T) {
	// 50 ms TTL — enough to expire in the test without a long sleep.
	shortTTL := 50 * time.Millisecond
	st := NewSessionStore(shortTTL)

	code, err := st.Create("state-exp")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.Complete(code, "diana", "tok-diana", 1_000_000_000); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	// Sleep past the TTL.
	time.Sleep(shortTTL + 20*time.Millisecond)

	// Get must report gone.
	_, okGet := st.Get(code)
	if okGet {
		t.Fatal("Get returned ok=true for an expired session; want ok=false")
	}

	// Take must also report gone.
	_, _, okTake := st.Take(code, "state-exp")
	if okTake {
		t.Fatal("Take returned ok=true for an expired session; want ok=false")
	}
}

// ── Complete on expired session must error ────────────────────────────────────

func TestSessionCompleteExpired(t *testing.T) {
	shortTTL := 50 * time.Millisecond
	st := NewSessionStore(shortTTL)

	code, err := st.Create("state-cexp")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	time.Sleep(shortTTL + 20*time.Millisecond)

	err = st.Complete(code, "eve", "tok-eve", 1_000_000_000)
	if err == nil {
		t.Fatal("Complete on expired session should return error; got nil")
	}
}

// ── Complete twice must error on the second call ──────────────────────────────

func TestSessionCompleteTwice(t *testing.T) {
	st := NewSessionStore(0)
	code, err := st.Create("state-c2")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.Complete(code, "frank", "tok-frank", 1_000_000_000); err != nil {
		t.Fatalf("first Complete: %v", err)
	}
	if err := st.Complete(code, "frank", "tok-frank2", 2_000_000_000); err == nil {
		t.Fatal("second Complete should return 'not pending' error; got nil")
	}
}

// ── sweepExpired removes expired sessions and returns correct count ───────────

func TestSweepExpired(t *testing.T) {
	shortTTL := 50 * time.Millisecond
	st := NewSessionStore(shortTTL)

	// Two sessions that will expire.
	for range [2]struct{}{} {
		if _, err := st.Create("state-sweep"); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}
	// One session added after the sleep (should NOT be swept).
	time.Sleep(shortTTL + 20*time.Millisecond)
	if _, err := st.Create("state-alive"); err != nil {
		t.Fatalf("Create (alive): %v", err)
	}

	swept := st.sweepExpired()
	if swept != 2 {
		t.Fatalf("sweepExpired returned %d; want 2", swept)
	}
}

// ── Concurrency: N goroutines race to Take a completed session ────────────────
// Exactly one should succeed; all others get ok=false.

func TestSessionConcurrentTakeSingleWinner(t *testing.T) {
	st := NewSessionStore(0)

	code, err := st.Create("state-race")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.Complete(code, "grace", "tok-grace", 1_000_000_000); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	const goroutines = 20
	var wins atomic.Int32
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for range [goroutines]struct{}{} {
		go func() {
			defer wg.Done()
			_, _, ok := st.Take(code, "state-race")
			if ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()

	if wins.Load() != 1 {
		t.Fatalf("concurrent Take: %d goroutines won; want exactly 1", wins.Load())
	}
}

// ── Interactive flow integration: Create → Complete (via store) → Take ────────
// Simulates the CLI poll pattern without a real HTTP server.

func TestSessionInteractiveFlow(t *testing.T) {
	st := NewSessionStore(0)

	// Step 1: CLI calls StartAuthSession → obtains session code.
	code, err := st.Create("cli-state-42")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Step 2: Browser POSTs to /login → web layer calls Complete.
	// We simulate this directly (no HTTP server needed here).
	if err := st.Complete(code, "henry", "tok-henry", 5_000_000_000); err != nil {
		t.Fatalf("Complete (simulated web POST): %v", err)
	}

	// Step 3: CLI polls GetAuthSession → Take delivers token.
	token, expMs, ok := st.Take(code, "cli-state-42")
	if !ok {
		t.Fatal("Take in interactive flow returned ok=false")
	}
	if token != "tok-henry" {
		t.Fatalf("Take returned token %q; want %q", token, "tok-henry")
	}
	if expMs != 5_000_000_000 {
		t.Fatalf("Take returned expiresAtMs %d; want %d", expMs, 5_000_000_000)
	}

	// Step 4: A second poll must get nothing (single-use).
	_, _, ok2 := st.Take(code, "cli-state-42")
	if ok2 {
		t.Fatal("second Take in interactive flow returned ok=true; token must be consumed")
	}
}
