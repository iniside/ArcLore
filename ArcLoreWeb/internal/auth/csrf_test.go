package auth

// CrossOriginProtection wiring regression tests.
//
// These tests document and lock the exact stdlib behaviour of
// http.CrossOriginProtection (Go 1.25) as it is wired in main.go:
//
//   cop := http.NewCrossOriginProtection()
//   cop.SetDenyHandler(...)
//   router.Use(cop.Handler)
//
// Rules confirmed against the live stdlib (see probe in Step 4 comments):
//   - GET is a safe method → always 200, even with a cross-origin Origin header.
//   - POST with Sec-Fetch-Site: same-origin                     → 200 (pass)
//   - POST with Sec-Fetch-Site: cross-site                      → 403 (deny)
//   - POST with a cross-origin Origin header (no Sec-Fetch-Site) → 403 (deny)
//   - POST with a same-origin Origin header (host matches)      → 200 (pass)
//   - POST with no browser headers at all (curl / API client)   → 200 (pass)

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func newCSRFHandler() http.Handler {
	cop := http.NewCrossOriginProtection()
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("cross-origin request blocked"))
	}))
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return cop.Handler(inner)
}

func TestCrossOriginProtection_GetPassesEvenCrossOrigin(t *testing.T) {
	h := newCSRFHandler()
	r := httptest.NewRequest("GET", "http://myhost.example/page", nil)
	r.Header.Set("Origin", "http://evil.example")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("GET cross-origin: want 200, got %d", w.Code)
	}
}

func TestCrossOriginProtection_PostCrossOriginHeaderDenied(t *testing.T) {
	h := newCSRFHandler()
	r := httptest.NewRequest("POST", "http://myhost.example/form", nil)
	r.Header.Set("Origin", "http://evil.example")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("POST cross-origin Origin: want 403, got %d", w.Code)
	}
}

func TestCrossOriginProtection_PostSameOriginHeaderPasses(t *testing.T) {
	h := newCSRFHandler()
	r := httptest.NewRequest("POST", "http://myhost.example/form", nil)
	r.Header.Set("Origin", "http://myhost.example")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("POST same-origin Origin: want 200, got %d", w.Code)
	}
}

func TestCrossOriginProtection_PostSecFetchSiteSameOriginPasses(t *testing.T) {
	h := newCSRFHandler()
	r := httptest.NewRequest("POST", "http://myhost.example/form", nil)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("POST Sec-Fetch-Site same-origin: want 200, got %d", w.Code)
	}
}

func TestCrossOriginProtection_PostSecFetchSiteCrossSiteDenied(t *testing.T) {
	h := newCSRFHandler()
	r := httptest.NewRequest("POST", "http://myhost.example/form", nil)
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("POST Sec-Fetch-Site cross-site: want 403, got %d", w.Code)
	}
}

func TestCrossOriginProtection_PostNoBrowserHeadersPasses(t *testing.T) {
	// Non-browser clients (curl, API consumers) send no Sec-Fetch-Site or Origin.
	// The stdlib treats header-less requests as same-origin/non-browser and allows them.
	h := newCSRFHandler()
	r := httptest.NewRequest("POST", "http://myhost.example/form", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("POST no browser headers: want 200 (non-browser pass), got %d", w.Code)
	}
}
