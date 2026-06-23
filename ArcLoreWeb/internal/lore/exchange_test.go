package lore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// newTestClient builds a Client with only the auth/exchange machinery wired —
// no gRPC conns. exchangeFn and clock are injected so AuthzToken's cache/expiry
// logic can be exercised without any network.
func newTestClient(
	nowMs int64,
	exchange func(ctx context.Context, identityToken string, resource string) (string, int64, error),
) *Client {
	c := &Client{
		authzCache: make(map[string]authzEntry),
		clock:      func() time.Time { return time.UnixMilli(nowMs) },
	}
	c.exchangeFn = exchange
	return c
}

func TestResourceAuthzTokenEmptyIdentityNoExchange(t *testing.T) {
	calls := 0
	c := newTestClient(0, func(context.Context, string, string) (string, int64, error) {
		calls++
		return "should-not-happen", 0, nil
	})

	token, err := c.ResourceAuthzToken(context.Background(), "", WildcardResource)
	if err != nil {
		t.Fatalf("ResourceAuthzToken: unexpected error: %v", err)
	}
	if token != "" {
		t.Fatalf("ResourceAuthzToken: want empty passthrough token, got %q", token)
	}
	if calls != 0 {
		t.Fatalf("ResourceAuthzToken: empty identity must not exchange, got %d calls", calls)
	}
}

func TestResourceAuthzTokenFirstCallExchangesAndCaches(t *testing.T) {
	const nowMs int64 = 1_000_000
	calls := 0
	c := newTestClient(nowMs, func(context.Context, string, string) (string, int64, error) {
		calls++
		return "authz-token", nowMs + 10*time.Minute.Milliseconds(), nil
	})

	token, err := c.ResourceAuthzToken(context.Background(), "identity", WildcardResource)
	if err != nil {
		t.Fatalf("ResourceAuthzToken: unexpected error: %v", err)
	}
	if token != "authz-token" {
		t.Fatalf("ResourceAuthzToken: want exchanged token, got %q", token)
	}
	if calls != 1 {
		t.Fatalf("ResourceAuthzToken: want exactly 1 exchange, got %d", calls)
	}
	entry, ok := c.authzCache[WildcardResource]
	if !ok || entry.token != "authz-token" {
		t.Fatalf("ResourceAuthzToken: token not cached for resource, cache=%+v", c.authzCache)
	}
}

func TestResourceAuthzTokenSecondCallWithinValidityUsesCache(t *testing.T) {
	const nowMs int64 = 2_000_000
	calls := 0
	c := newTestClient(nowMs, func(context.Context, string, string) (string, int64, error) {
		calls++
		return "authz-token", nowMs + 10*time.Minute.Milliseconds(), nil
	})

	if _, err := c.ResourceAuthzToken(context.Background(), "identity", WildcardResource); err != nil {
		t.Fatalf("ResourceAuthzToken first: %v", err)
	}
	token, err := c.ResourceAuthzToken(context.Background(), "identity", WildcardResource)
	if err != nil {
		t.Fatalf("ResourceAuthzToken second: %v", err)
	}
	if token != "authz-token" {
		t.Fatalf("ResourceAuthzToken: want cached token, got %q", token)
	}
	if calls != 1 {
		t.Fatalf("ResourceAuthzToken: second call within validity must not re-exchange, got %d calls", calls)
	}
}

func TestResourceAuthzTokenExpiredWithinSkewReExchanges(t *testing.T) {
	const nowMs int64 = 3_000_000
	calls := 0
	// First exchange returns a token whose expiry is only 30s out — INSIDE the
	// 60s skew window, so the next call must treat it as expired and re-exchange.
	exp := nowMs + 30*time.Second.Milliseconds()
	c := newTestClient(nowMs, func(context.Context, string, string) (string, int64, error) {
		calls++
		if calls == 1 {
			return "near-expiry", exp, nil
		}
		return "fresh-token", nowMs + time.Hour.Milliseconds(), nil
	})

	first, err := c.ResourceAuthzToken(context.Background(), "identity", WildcardResource)
	if err != nil {
		t.Fatalf("ResourceAuthzToken first: %v", err)
	}
	if first != "near-expiry" {
		t.Fatalf("ResourceAuthzToken first: want near-expiry, got %q", first)
	}

	second, err := c.ResourceAuthzToken(context.Background(), "identity", WildcardResource)
	if err != nil {
		t.Fatalf("ResourceAuthzToken second: %v", err)
	}
	if second != "fresh-token" {
		t.Fatalf("ResourceAuthzToken: want re-exchanged fresh token, got %q", second)
	}
	if calls != 2 {
		t.Fatalf("ResourceAuthzToken: within-skew token must re-exchange, got %d calls", calls)
	}
}

func TestAuthURLToTarget(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"ucs-auth://host.example", "host.example:443"},
		{"https://host.example", "host.example:443"},
		{"https://host.example:41337", "host.example:41337"},
		{"host.example:41337", "host.example:41337"},
		{"host.example", "host.example:443"},
	}
	for _, tc := range cases {
		got, err := authURLToTarget(tc.in)
		if err != nil {
			t.Fatalf("authURLToTarget(%q): unexpected error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("authURLToTarget(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	if _, err := authURLToTarget(""); err == nil {
		t.Fatalf("authURLToTarget(\"\"): want error, got nil")
	}
}

// TestClassifyExchangeErrTLSUnknownAuthority checks that an x509 unknown-authority
// error (the most common self-signed-cert failure) is classified as ErrAuthServerUnreachable.
func TestClassifyExchangeErrTLSUnknownAuthority(t *testing.T) {
	// Fabricate an x509.UnknownAuthorityError wrapped in a tls.CertificateVerificationError.
	x509Err := x509.UnknownAuthorityError{}
	tlsErr := &tls.CertificateVerificationError{Err: x509Err}

	result := ClassifyExchangeErr(tlsErr)
	if !errors.Is(result, ErrAuthServerUnreachable) {
		t.Fatalf("ClassifyExchangeErr(tls.CertificateVerificationError): want errors.Is ErrAuthServerUnreachable, got %v", result)
	}
	if errors.Is(result, ErrAuthDenied) {
		t.Fatalf("ClassifyExchangeErr(tls.CertificateVerificationError): must NOT be ErrAuthDenied")
	}
}

// TestClassifyExchangeErrX509UnknownAuthority checks the bare x509.UnknownAuthorityError path.
func TestClassifyExchangeErrX509UnknownAuthority(t *testing.T) {
	x509Err := x509.UnknownAuthorityError{}

	result := ClassifyExchangeErr(x509Err)
	if !errors.Is(result, ErrAuthServerUnreachable) {
		t.Fatalf("ClassifyExchangeErr(x509.UnknownAuthorityError): want errors.Is ErrAuthServerUnreachable, got %v", result)
	}
}

// TestClassifyExchangeErrGRPCUnavailable checks that codes.Unavailable (connection
// refused / handshake failure surfaced by gRPC) is classified as ErrAuthServerUnreachable.
func TestClassifyExchangeErrGRPCUnavailable(t *testing.T) {
	grpcErr := status.Error(codes.Unavailable, "connection refused")

	result := ClassifyExchangeErr(grpcErr)
	if !errors.Is(result, ErrAuthServerUnreachable) {
		t.Fatalf("ClassifyExchangeErr(Unavailable): want errors.Is ErrAuthServerUnreachable, got %v", result)
	}
	if errors.Is(result, ErrAuthDenied) {
		t.Fatalf("ClassifyExchangeErr(Unavailable): must NOT be ErrAuthDenied")
	}
}

// TestClassifyExchangeErrGRPCPermissionDenied checks that codes.PermissionDenied
// is classified as ErrAuthDenied (NOT ErrAuthServerUnreachable).
func TestClassifyExchangeErrGRPCPermissionDenied(t *testing.T) {
	grpcErr := status.Error(codes.PermissionDenied, "insufficient grants")

	result := ClassifyExchangeErr(grpcErr)
	if errors.Is(result, ErrAuthServerUnreachable) {
		t.Fatalf("ClassifyExchangeErr(PermissionDenied): must NOT be ErrAuthServerUnreachable")
	}
	if !errors.Is(result, ErrAuthDenied) {
		t.Fatalf("ClassifyExchangeErr(PermissionDenied): want errors.Is ErrAuthDenied, got %v", result)
	}
}

// TestClassifyExchangeErrGRPCUnauthenticated checks that codes.Unauthenticated
// is classified as ErrAuthDenied.
func TestClassifyExchangeErrGRPCUnauthenticated(t *testing.T) {
	grpcErr := status.Error(codes.Unauthenticated, "missing token")

	result := ClassifyExchangeErr(grpcErr)
	if !errors.Is(result, ErrAuthDenied) {
		t.Fatalf("ClassifyExchangeErr(Unauthenticated): want errors.Is ErrAuthDenied, got %v", result)
	}
}

// TestClassifyExchangeErrNil checks that nil is returned unchanged.
func TestClassifyExchangeErrNil(t *testing.T) {
	result := ClassifyExchangeErr(nil)
	if result != nil {
		t.Fatalf("ClassifyExchangeErr(nil): want nil, got %v", result)
	}
}

// TestClassifyExchangeErrUnknownPassthrough checks that an unclassified error
// is returned as-is (no sentinel wrapping).
func TestClassifyExchangeErrUnknownPassthrough(t *testing.T) {
	plain := errors.New("some other error")
	result := ClassifyExchangeErr(plain)
	if errors.Is(result, ErrAuthServerUnreachable) {
		t.Fatalf("ClassifyExchangeErr(unknown): must NOT be ErrAuthServerUnreachable")
	}
	if errors.Is(result, ErrAuthDenied) {
		t.Fatalf("ClassifyExchangeErr(unknown): must NOT be ErrAuthDenied")
	}
	if result != plain {
		t.Fatalf("ClassifyExchangeErr(unknown): want original error returned, got %v", result)
	}
}

// TestResourceAuthzTokenClassifiesExchangeErr checks that ResourceAuthzToken
// propagates the classified error (ErrAuthServerUnreachable wrapping) when the
// exchange function returns a transport-class failure.
func TestResourceAuthzTokenClassifiesExchangeErr(t *testing.T) {
	transportErr := status.Error(codes.Unavailable, "dial tcp: connection refused")
	c := newTestClient(0, func(context.Context, string, string) (string, int64, error) {
		return "", 0, ClassifyExchangeErr(transportErr)
	})

	_, err := c.ResourceAuthzToken(context.Background(), "identity", WildcardResource)
	if err == nil {
		t.Fatal("ResourceAuthzToken: want error, got nil")
	}
	if !errors.Is(err, ErrAuthServerUnreachable) {
		t.Fatalf("ResourceAuthzToken: want errors.Is ErrAuthServerUnreachable, got %v", err)
	}
}
