// Package mgmt is the HTTP/JSON client for arc-lore-auth's management API
// (the /api/* surface). It mirrors the outbound-HTTP pattern in
// internal/lore/blob.go: http.NewRequestWithContext, an explicit Bearer header
// where required, a json-decoded response body, and a typed error that carries
// the HTTP status so callers can map 401/403/409.
//
// The public endpoints (Status/Setup/Login) drive ArcLoreWeb's native login +
// first-run gate; the admin endpoints (token arg) back the Step 7 management
// screens.
package mgmt

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client talks to arc-lore-auth's /api/* JSON surface. base is the scheme+host
// root (e.g. "http://authhost:8080"); per-call deadlines come from timeout.
type Client struct {
	base       string
	httpClient *http.Client
	timeout    time.Duration
}

// New builds a Client. The trailing slash on base is trimmed so path joins are
// predictable. timeout bounds every request via a per-call context deadline.
func New(base string, timeout time.Duration) *Client {
	return &Client{
		base:       strings.TrimRight(base, "/"),
		httpClient: &http.Client{Timeout: timeout},
		timeout:    timeout,
	}
}

// APIError is the typed error returned for a non-2xx response. Status is the
// HTTP status code (so callers can branch on 401/403/409); Message is the
// server's {"error": …} text when present, else the raw body.
type APIError struct {
	Status  int
	Message string
}

// Error implements error.
func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("mgmt: %d %s: %s", e.Status, http.StatusText(e.Status), e.Message)
	}
	return fmt.Sprintf("mgmt: %d %s", e.Status, http.StatusText(e.Status))
}

// ── request/response payloads (mirror arc-lore-auth api.go) ─────────────────────

// StatusResp is the public /api/status body.
type StatusResp struct {
	HasUsers         bool `json:"has_users"`
	RegistrationOpen bool `json:"registration_open"`
}

// AuthResp is the shared setup/login token body. ExpiresAt is Unix SECONDS.
type AuthResp struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
	UserID    string `json:"user_id"`
	Name      string `json:"name"`
	IsAdmin   bool   `json:"is_admin"`
}

// UserResp is one user row (no password hash is ever returned by the API).
type UserResp struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	IsAdmin     bool   `json:"is_admin"`
	Created     int64  `json:"created"`
}

// ResourceResp is one registered repo (resource) row.
type ResourceResp struct {
	ResourceID string `json:"resource_id"`
	Name       string `json:"name"`
	Created    int64  `json:"created"`
}

// ── core request helper ─────────────────────────────────────────────────────────

// do builds and sends a request to {base}{path}. When body is non-nil it is
// JSON-encoded; when token is non-empty an Authorization: Bearer header is set.
// On a 2xx response it decodes into out (when out is non-nil). On a non-2xx it
// reads the body, extracts {"error": …} when present, and returns an *APIError
// carrying the status.
func (c *Client) do(ctx context.Context, method, path, token string, body, out any) error {
	var reqBody io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("mgmt: encode request body: %w", err)
		}
		reqBody = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reqBody)
	if err != nil {
		return fmt.Errorf("mgmt: build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("mgmt: %s %s: %w", method, path, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{Status: resp.StatusCode, Message: readErrorMessage(resp.Body)}
	}

	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("mgmt: decode response: %w", err)
		}
	}
	return nil
}

// readErrorMessage reads a (small) response body and pulls the {"error": …}
// field when present; otherwise it returns the trimmed raw body.
func readErrorMessage(body io.Reader) string {
	raw, err := io.ReadAll(io.LimitReader(body, 1<<16))
	if err != nil {
		return ""
	}
	var env struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(raw, &env) == nil && env.Error != "" {
		return env.Error
	}
	return strings.TrimSpace(string(raw))
}

// ── public endpoints ────────────────────────────────────────────────────────────

// Status reports whether the instance has users yet and whether registration is
// open. PUBLIC (no token).
func (c *Client) Status(ctx context.Context) (StatusResp, error) {
	var out StatusResp
	err := c.do(ctx, http.MethodGet, "/api/status", "", nil, &out)
	return out, err
}

// Setup creates the first admin and returns an auto-login token. PUBLIC; the
// server returns 409 once setup has already run.
func (c *Client) Setup(ctx context.Context, username, password, displayName string) (AuthResp, error) {
	var out AuthResp
	body := map[string]string{
		"username":     username,
		"password":     password,
		"display_name": displayName,
	}
	err := c.do(ctx, http.MethodPost, "/api/setup", "", body, &out)
	return out, err
}

// Login verifies credentials and returns an authz token. PUBLIC; the server
// returns 401 on any credential failure.
func (c *Client) Login(ctx context.Context, username, password string) (AuthResp, error) {
	var out AuthResp
	body := map[string]string{
		"username": username,
		"password": password,
	}
	err := c.do(ctx, http.MethodPost, "/api/login", "", body, &out)
	return out, err
}

// Register creates a non-admin account and returns an auto-login token. PUBLIC;
// the server returns 403 when registration is closed, 409 on a duplicate
// username, and 400 on a validation failure.
func (c *Client) Register(ctx context.Context, username, password string) (AuthResp, error) {
	var out AuthResp
	body := map[string]string{
		"username": username,
		"password": password,
	}
	err := c.do(ctx, http.MethodPost, "/api/register", "", body, &out)
	return out, err
}

// ChangeMyPassword changes the calling user's own password. token is the
// caller's authz Bearer (any authed user). The server returns 401 when the
// current password is wrong and 400 on a validation failure.
func (c *Client) ChangeMyPassword(ctx context.Context, token, current, newPassword string) error {
	body := map[string]string{
		"current": current,
		"new":     newPassword,
	}
	return c.do(ctx, http.MethodPost, "/api/me/password", token, body, nil)
}

// ── admin endpoints (token = an admin's authz Bearer) ───────────────────────────

// SetRegistration opens or closes public registration. ADMIN.
func (c *Client) SetRegistration(ctx context.Context, token string, open bool) error {
	body := map[string]bool{"open": open}
	return c.do(ctx, http.MethodPost, "/api/admin/registration", token, body, nil)
}

// ListUsers returns every user row. ADMIN.
func (c *Client) ListUsers(ctx context.Context, token string) ([]UserResp, error) {
	var out []UserResp
	err := c.do(ctx, http.MethodGet, "/api/users", token, nil, &out)
	return out, err
}

// CreateUser adds a user. ADMIN. 409 on an existing username.
func (c *Client) CreateUser(ctx context.Context, token, username, password, displayName string, isAdmin bool) (UserResp, error) {
	var out UserResp
	body := map[string]any{
		"username":     username,
		"password":     password,
		"display_name": displayName,
		"is_admin":     isAdmin,
	}
	err := c.do(ctx, http.MethodPost, "/api/users", token, body, &out)
	return out, err
}

// DeleteUser removes a user. ADMIN. 409 when it would remove the last admin.
func (c *Client) DeleteUser(ctx context.Context, token, username string) error {
	return c.do(ctx, http.MethodDelete, "/api/users/"+url.PathEscape(username), token, nil, nil)
}

// SetPassword replaces a user's password. ADMIN.
func (c *Client) SetPassword(ctx context.Context, token, username, password string) error {
	body := map[string]string{"password": password}
	return c.do(ctx, http.MethodPost, "/api/users/"+url.PathEscape(username)+"/password", token, body, nil)
}

// SetAdmin flips a user's admin flag. ADMIN. 409 when it would demote the last
// admin.
func (c *Client) SetAdmin(ctx context.Context, token, username string, isAdmin bool) error {
	body := map[string]bool{"is_admin": isAdmin}
	return c.do(ctx, http.MethodPost, "/api/users/"+url.PathEscape(username)+"/admin", token, body, nil)
}

// ListResources returns every registered repo (resource). ADMIN.
func (c *Client) ListResources(ctx context.Context, token string) ([]ResourceResp, error) {
	var out []ResourceResp
	err := c.do(ctx, http.MethodGet, "/api/resources", token, nil, &out)
	return out, err
}

// ImportResource registers an existing repository (by 32-hex id, or urc-prefixed)
// as a resource and grants the calling admin owner. ADMIN. Used to surface a repo
// that exists on lore-server but has no resource row here. Idempotent.
func (c *Client) ImportResource(ctx context.Context, token, resourceID, name string) (ResourceResp, error) {
	body := map[string]string{
		"resource_id": resourceID,
		"name":        name,
	}
	var out ResourceResp
	err := c.do(ctx, http.MethodPost, "/api/resources", token, body, &out)
	return out, err
}

// RemoveResource deletes a resource row (and cascades its grants) via the mgmt
// API. ADMIN. Idempotent on the server side (absent resource is not an error).
func (c *Client) RemoveResource(ctx context.Context, token, resourceID string) error {
	body := map[string]string{"resource_id": resourceID}
	return c.do(ctx, http.MethodDelete, "/api/resources", token, body, nil)
}

// Grants returns a user's grants as resource_id -> []permission. ADMIN. An
// unknown user yields an empty map (not an error).
func (c *Client) Grants(ctx context.Context, token, username string) (map[string][]string, error) {
	var out map[string][]string
	err := c.do(ctx, http.MethodGet, "/api/users/"+url.PathEscape(username)+"/grants", token, nil, &out)
	return out, err
}

// AddGrant grants permission to username on resourceID. ADMIN.
func (c *Client) AddGrant(ctx context.Context, token, username, resourceID, permission string) error {
	body := map[string]string{
		"username":    username,
		"resource_id": resourceID,
		"permission":  permission,
	}
	return c.do(ctx, http.MethodPost, "/api/grants", token, body, nil)
}

// RemoveGrant revokes permission from username on resourceID. ADMIN. Idempotent.
func (c *Client) RemoveGrant(ctx context.Context, token, username, resourceID, permission string) error {
	body := map[string]string{
		"username":    username,
		"resource_id": resourceID,
		"permission":  permission,
	}
	return c.do(ctx, http.MethodDelete, "/api/grants", token, body, nil)
}
