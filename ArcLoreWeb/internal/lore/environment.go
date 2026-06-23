package lore

import (
	"context"
	"fmt"

	environmentv1 "arcloreweb/gen/lore/environment/v1"
)

// GetEnvironment queries the server's EnvironmentService on the main gRPC conn
// for its published environment, returning the auth service URL
// (Environment.Endpoint.auth_url, e.g. "ucs-auth://host").
//
// The call is unauthenticated: no WithLoreCall scope is attached, so the auth
// interceptor no-ops (no Bearer / -bin headers) — EnvironmentGet is an
// authn-only endpoint that does not require a token or repository scope.
func (c *Client) GetEnvironment(ctx context.Context) (authURL string, err error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.environments.EnvironmentGet(ctx, &environmentv1.EnvironmentGetRequest{})
	if err != nil {
		return "", fmt.Errorf("lore: EnvironmentGet: %w", err)
	}
	return resp.GetEnvironment().GetEndpoint().GetAuthUrl(), nil
}
