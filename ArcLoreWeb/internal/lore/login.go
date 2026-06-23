package lore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	gen "arcloreweb/gen"
)

// randomClientState returns a 256-bit cryptographically-random hex string used
// as the UrcAuthApi client_state. The auth service echoes it back through the
// browser login flow; an unguessable value binds our poll to our own login,
// so it MUST come from crypto/rand (never math/rand).
func randomClientState() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("lore: client_state generation: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// StartAuthSession begins a native UCS login session via
// UrcAuthApi.StartAuthSession on the cached (TLS, no -bin) auth conn.
//
// It generates a fresh random client_state, sends it, and returns the
// server-issued session code, the browser login URL, and the client_state it
// generated. The caller stores sessionCode + clientState in its session and
// feeds both back into PollAuthSession until login completes.
func (c *Client) StartAuthSession(ctx context.Context) (sessionCode, loginURL, clientState string, err error) {
	authClient, err := c.authClientForURL(ctx)
	if err != nil {
		return "", "", "", err
	}

	clientState, err = randomClientState()
	if err != nil {
		return "", "", "", err
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := authClient.StartAuthSession(ctx, &gen.StartAuthSessionRequest{
		ClientState: clientState,
	})
	if err != nil {
		return "", "", "", fmt.Errorf("lore: StartAuthSession: %w", err)
	}
	return resp.GetSessionCode(), resp.GetLoginUrl(), clientState, nil
}

// PollAuthSession polls UrcAuthApi.GetAuthSession once for a pending login.
//
// While the user has not finished the browser login the response carries no
// user_token: done is false and the token fields are empty (a normal "keep
// waiting" result, not an error). Once login completes the response carries the
// UserToken: done is true with the identity JWT, the URC user id/name, and the
// token's epoch-millisecond expiry.
func (c *Client) PollAuthSession(
	ctx context.Context,
	sessionCode, clientState string,
) (identityToken, userID, userName string, expiresMs int64, done bool, err error) {
	authClient, err := c.authClientForURL(ctx)
	if err != nil {
		return "", "", "", 0, false, err
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := authClient.GetAuthSession(ctx, &gen.GetAuthSessionRequest{
		SessionCode: sessionCode,
		ClientState: clientState,
	})
	if err != nil {
		return "", "", "", 0, false, fmt.Errorf("lore: GetAuthSession: %w", err)
	}

	token := resp.GetUserToken()
	if token == nil || token.GetUserToken() == "" {
		// Login still pending — no token yet.
		return "", "", "", 0, false, nil
	}
	return token.GetUserToken(), token.GetUserId(), token.GetUserName(), token.GetExpiresAt(), true, nil
}
