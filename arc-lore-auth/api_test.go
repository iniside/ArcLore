package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// apiTestServer spins up the full mux (as main.go wires it) over httptest and
// returns the base URL + the backing store (so a test can seed resources
// directly) + a stop func. attachWeb is required so registerRoutes mounts the API.
func apiTestServer(t *testing.T) (base string, store *Store, stop func()) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	const kid = "test-kid"
	jwkSet, err := buildJWKSet(priv, kid)
	if err != nil {
		t.Fatalf("buildJWKSet: %v", err)
	}
	store = openTestStore(t)

	srv, err := newAuthServer(testConfig(), priv, kid, jwkSet)
	if err != nil {
		t.Fatalf("newAuthServer: %v", err)
	}
	srv.attachWeb(NewSessionStore(time.Minute), store)

	mux := http.NewServeMux()
	srv.registerRoutes(mux)
	ts := httptest.NewServer(mux)
	return ts.URL, store, ts.Close
}

// doAPI sends method+path with an optional JSON body and bearer token, decodes
// the JSON response into out (if non-nil), and returns status + raw body.
func doAPI(t *testing.T, base, method, path, bearer string, body any, out any) (int, []byte) {
	t.Helper()

	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, base+path, reader)
	if err != nil {
		t.Fatalf("NewRequest %s %s: %v", method, path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do %s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body %s %s: %v", method, path, err)
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("unmarshal %s %s body %q: %v", method, path, string(raw), err)
		}
	}
	return resp.StatusCode, raw
}

func TestManagementAPIFlow(t *testing.T) {
	base, store, stop := apiTestServer(t)
	defer stop()

	// 1. status on an empty store.
	var status struct {
		HasUsers         bool `json:"has_users"`
		RegistrationOpen bool `json:"registration_open"`
	}
	if code, _ := doAPI(t, base, http.MethodGet, "/api/status", "", nil, &status); code != http.StatusOK {
		t.Fatalf("status: got %d want 200", code)
	}
	if status.HasUsers {
		t.Fatalf("status.has_users: got true want false")
	}
	if status.RegistrationOpen {
		t.Fatalf("status.registration_open: got true want false (absent key defaults closed)")
	}

	// 2. setup creates the first admin and auto-logs in.
	const rootPass = "rootpassword123"
	var setup apiTokenResp
	code, _ := doAPI(t, base, http.MethodPost, "/api/setup", "", apiSetupReq{
		Username: "root", Password: rootPass, DisplayName: "Root",
	}, &setup)
	if code != http.StatusCreated {
		t.Fatalf("setup: got %d want 201", code)
	}
	if setup.Token == "" {
		t.Fatalf("setup: empty token")
	}
	if !setup.IsAdmin {
		t.Fatalf("setup: is_admin got false want true")
	}
	if setup.UserID != "root" {
		t.Fatalf("setup: user_id got %q want root", setup.UserID)
	}
	adminToken := setup.Token

	// 3. setup again is a conflict.
	if code, _ := doAPI(t, base, http.MethodPost, "/api/setup", "", apiSetupReq{
		Username: "root2", Password: "anotherpassword1", DisplayName: "Root2",
	}, nil); code != http.StatusConflict {
		t.Fatalf("setup-again: got %d want 409", code)
	}

	// 4. login with correct creds.
	var login apiTokenResp
	if code, _ := doAPI(t, base, http.MethodPost, "/api/login", "", apiLoginReq{
		Username: "root", Password: rootPass,
	}, &login); code != http.StatusOK {
		t.Fatalf("login: got %d want 200", code)
	}
	if login.Token == "" {
		t.Fatalf("login: empty token")
	}
	if !login.IsAdmin {
		t.Fatalf("login: is_admin got false want true")
	}

	// 5. login with wrong password.
	if code, _ := doAPI(t, base, http.MethodPost, "/api/login", "", apiLoginReq{
		Username: "root", Password: "wrongpass",
	}, nil); code != http.StatusUnauthorized {
		t.Fatalf("login-bad: got %d want 401", code)
	}

	// 6. create a non-admin user.
	const alicePass = "alicepassword123"
	if code, _ := doAPI(t, base, http.MethodPost, "/api/users", adminToken, apiCreateUserReq{
		Username: "alice", Password: alicePass, DisplayName: "Alice", IsAdmin: false,
	}, nil); code != http.StatusCreated {
		t.Fatalf("create-user: got %d want 201", code)
	}

	// 7. list users — 2 users, and no hash leaks.
	var users []apiUserResp
	code, rawUsers := doAPI(t, base, http.MethodGet, "/api/users", adminToken, nil, &users)
	if code != http.StatusOK {
		t.Fatalf("list-users: got %d want 200", code)
	}
	if len(users) != 2 {
		t.Fatalf("list-users: got %d users want 2", len(users))
	}
	if strings.Contains(string(rawUsers), "argon2") {
		t.Fatalf("list-users: body leaks a hash: %s", string(rawUsers))
	}

	// 8. auth gates: no token -> 401, non-admin token -> 403.
	if code, _ := doAPI(t, base, http.MethodGet, "/api/users", "", nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("list-users no-token: got %d want 401", code)
	}
	var aliceLogin apiTokenResp
	if code, _ := doAPI(t, base, http.MethodPost, "/api/login", "", apiLoginReq{
		Username: "alice", Password: alicePass,
	}, &aliceLogin); code != http.StatusOK {
		t.Fatalf("alice-login: got %d want 200", code)
	}
	if code, _ := doAPI(t, base, http.MethodGet, "/api/users", aliceLogin.Token, nil, nil); code != http.StatusForbidden {
		t.Fatalf("list-users alice: got %d want 403", code)
	}

	// 9. resource + grant lifecycle (seed the resource directly through the store).
	if _, err := store.UpsertResource("urc-test", "Test Repo"); err != nil {
		t.Fatalf("UpsertResource: %v", err)
	}
	if code, _ := doAPI(t, base, http.MethodPost, "/api/grants", adminToken, apiGrantReq{
		Username: "alice", ResourceID: "urc-test", Permission: "read",
	}, nil); code != http.StatusCreated {
		t.Fatalf("grant-add: got %d want 201", code)
	}
	var grants map[string][]string
	if code, _ := doAPI(t, base, http.MethodGet, "/api/users/alice/grants", adminToken, nil, &grants); code != http.StatusOK {
		t.Fatalf("grants-get: got %d want 200", code)
	}
	if perms := grants["urc-test"]; len(perms) != 1 || perms[0] != "read" {
		t.Fatalf("grants-get: urc-test got %v want [read]", grants["urc-test"])
	}
	if code, _ := doAPI(t, base, http.MethodDelete, "/api/grants", adminToken, apiGrantReq{
		Username: "alice", ResourceID: "urc-test", Permission: "read",
	}, nil); code != http.StatusOK {
		t.Fatalf("grant-remove: got %d want 200", code)
	}
	var grants2 map[string][]string
	if code, _ := doAPI(t, base, http.MethodGet, "/api/users/alice/grants", adminToken, nil, &grants2); code != http.StatusOK {
		t.Fatalf("grants-get-2: got %d want 200", code)
	}
	if _, present := grants2["urc-test"]; present {
		t.Fatalf("grants-get-2: urc-test still present after remove: %v", grants2)
	}

	// 10. last-admin demote is blocked.
	if code, _ := doAPI(t, base, http.MethodPost, "/api/users/root/admin", adminToken, apiSetAdminReq{
		IsAdmin: false,
	}, nil); code != http.StatusConflict {
		t.Fatalf("demote-last-admin: got %d want 409", code)
	}

	// 11. last-admin delete is blocked.
	if code, _ := doAPI(t, base, http.MethodDelete, "/api/users/root", adminToken, nil, nil); code != http.StatusConflict {
		t.Fatalf("delete-last-admin: got %d want 409", code)
	}
}

// TestAPIPasswordPolicyEnforced verifies that POST /api/users rejects passwords
// shorter than 12 characters with 400, and accepts one that meets the minimum.
func TestAPIPasswordPolicyEnforced(t *testing.T) {
	base, _, stop := apiTestServer(t)
	defer stop()

	// Seed the first admin so the token can be obtained.
	var setup apiTokenResp
	if code, _ := doAPI(t, base, http.MethodPost, "/api/setup", "", apiSetupReq{
		Username: "admin", Password: "adminpassword1", DisplayName: "Admin",
	}, &setup); code != http.StatusCreated {
		t.Fatalf("setup: got %d want 201", code)
	}
	adminToken := setup.Token

	// Short passwords (< 12 chars) must be rejected with 400.
	shortPasswords := []string{"", "a", "tooshort"}
	for _, pw := range shortPasswords {
		code, _ := doAPI(t, base, http.MethodPost, "/api/users", adminToken, apiCreateUserReq{
			Username: "testuser", Password: pw, DisplayName: "Test", IsAdmin: false,
		}, nil)
		if code != http.StatusBadRequest {
			t.Errorf("POST /api/users with password %q: got %d want 400", pw, code)
		}
	}

	// A password meeting the 12-char minimum must be accepted.
	if code, _ := doAPI(t, base, http.MethodPost, "/api/users", adminToken, apiCreateUserReq{
		Username: "testuser", Password: "validpassword1", DisplayName: "Test", IsAdmin: false,
	}, nil); code != http.StatusCreated {
		t.Fatalf("POST /api/users with valid password: got %d want 201", code)
	}
}
