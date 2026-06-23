package main

// api_selfservice_test.go — tests for the self-service endpoints added in Steps 1
// and 2: public POST /api/register, admin POST /api/admin/registration toggle, and
// authenticated POST /api/me/password.
//
// The harness mirrors api_test.go exactly: apiTestServer + doAPI + real Store
// (temp SQLite). No mocks, no hand-minted tokens — every auth token comes from a
// real /api/setup or /api/login response so the full requireAPIAuth/requireAPIAdmin
// gate path is exercised.

import (
	"net/http"
	"testing"
)

// setupAdmin creates the first admin user via /api/setup and returns the admin token.
// The server must be freshly spun up (empty store).
func setupAdmin(t *testing.T, base string) string {
	t.Helper()
	var resp apiTokenResp
	code, _ := doAPI(t, base, http.MethodPost, "/api/setup", "", apiSetupReq{
		Username: "admin", Password: "adminpassword1", DisplayName: "Admin",
	}, &resp)
	if code != http.StatusCreated {
		t.Fatalf("setup: got %d want 201", code)
	}
	if resp.Token == "" {
		t.Fatalf("setup: empty token")
	}
	return resp.Token
}

// loginAs logs in with username+password and returns the token.
func loginAs(t *testing.T, base, username, password string) (string, bool) {
	t.Helper()
	var resp apiTokenResp
	code, _ := doAPI(t, base, http.MethodPost, "/api/login", "", apiLoginReq{
		Username: username, Password: password,
	}, &resp)
	return resp.Token, code == http.StatusOK
}

// ── /api/register ─────────────────────────────────────────────────────────────

// TestAPIRegisterClosed verifies that POST /api/register returns 403 when
// registration is closed (which is the default after CreateFirstAdmin/setup).
func TestAPIRegisterClosed(t *testing.T) {
	base, _, stop := apiTestServer(t)
	defer stop()

	// Create the first admin — this closes registration.
	adminToken := setupAdmin(t, base)
	_ = adminToken

	code, _ := doAPI(t, base, http.MethodPost, "/api/register", "", apiRegisterReq{
		Username: "newuser", Password: "newuserpassword1",
	}, nil)
	if code != http.StatusForbidden {
		t.Fatalf("register closed: got %d want 403", code)
	}
}

// TestAPIRegisterOpenAndCreate verifies the full toggle + register flow:
//  1. Admin re-opens registration via POST /api/admin/registration.
//  2. POST /api/register with valid creds succeeds (201).
//  3. The created user is NOT an admin.
//  4. A subsequent /api/login with those creds works.
func TestAPIRegisterOpenAndCreate(t *testing.T) {
	base, store, stop := apiTestServer(t)
	defer stop()

	adminToken := setupAdmin(t, base)

	// Registration is closed after setup — toggle it open.
	var toggleResp map[string]bool
	code, _ := doAPI(t, base, http.MethodPost, "/api/admin/registration", adminToken,
		apiRegistrationReq{Open: true}, &toggleResp)
	if code != http.StatusOK {
		t.Fatalf("toggle open: got %d want 200", code)
	}
	if !toggleResp["registration_open"] {
		t.Fatalf("toggle open: response registration_open=false, want true")
	}

	// Register a new user.
	const newUser = "newbie"
	const newPass = "newbiepassword1"
	var regResp apiTokenResp
	code, _ = doAPI(t, base, http.MethodPost, "/api/register", "", apiRegisterReq{
		Username: newUser, Password: newPass,
	}, &regResp)
	if code != http.StatusCreated {
		t.Fatalf("register: got %d want 201", code)
	}
	if regResp.Token == "" {
		t.Fatalf("register: got empty token")
	}
	if regResp.IsAdmin {
		t.Fatalf("register: new user is_admin=true, want false")
	}
	if regResp.UserID != newUser {
		t.Fatalf("register: user_id=%q want %q", regResp.UserID, newUser)
	}

	// Confirm the user exists in the store and is NOT an admin.
	u, err := store.GetUser(newUser)
	if err != nil {
		t.Fatalf("GetUser after register: %v", err)
	}
	if u.IsAdmin {
		t.Fatalf("GetUser: registered user has IsAdmin=true, want false")
	}

	// Login with the new credentials must succeed.
	_, ok := loginAs(t, base, newUser, newPass)
	if !ok {
		t.Fatalf("login after register: want 200 got non-200")
	}
}

// TestAPIRegisterDuplicate verifies that registering with a username that already
// exists returns 409.
func TestAPIRegisterDuplicate(t *testing.T) {
	base, _, stop := apiTestServer(t)
	defer stop()

	adminToken := setupAdmin(t, base)

	// Open registration.
	doAPI(t, base, http.MethodPost, "/api/admin/registration", adminToken,
		apiRegistrationReq{Open: true}, nil)

	// First registration — should succeed.
	code, _ := doAPI(t, base, http.MethodPost, "/api/register", "", apiRegisterReq{
		Username: "dupuser", Password: "dupuserpassword1",
	}, nil)
	if code != http.StatusCreated {
		t.Fatalf("first register: got %d want 201", code)
	}

	// Second registration with the same name — should conflict.
	code, _ = doAPI(t, base, http.MethodPost, "/api/register", "", apiRegisterReq{
		Username: "dupuser", Password: "dupuserpassword2",
	}, nil)
	if code != http.StatusConflict {
		t.Fatalf("duplicate register: got %d want 409", code)
	}
}

// TestAPIRegisterValidation checks that short passwords and out-of-range usernames
// return 400.
func TestAPIRegisterValidation(t *testing.T) {
	base, _, stop := apiTestServer(t)
	defer stop()

	adminToken := setupAdmin(t, base)
	doAPI(t, base, http.MethodPost, "/api/admin/registration", adminToken,
		apiRegistrationReq{Open: true}, nil)

	cases := []struct {
		name     string
		username string
		password string
	}{
		{"short password", "validuser", "tooshort"},                                  // < 12 chars
		{"empty password", "validuser", ""},                                          // empty
		{"short username", "ab", "longpasswordyes1"},                                 // < 3 chars
		{"long username", "abcdefghijklmnopqrstuvwxyz123456789", "longpasswordyes1"}, // > 32 chars
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _ := doAPI(t, base, http.MethodPost, "/api/register", "", apiRegisterReq{
				Username: tc.username, Password: tc.password,
			}, nil)
			if code != http.StatusBadRequest {
				t.Fatalf("%s: got %d want 400", tc.name, code)
			}
		})
	}
}

// ── /api/admin/registration ───────────────────────────────────────────────────

// TestAPIAdminRegistrationNonAdmin verifies that a valid but non-admin token is
// rejected with 403 on POST /api/admin/registration.
func TestAPIAdminRegistrationNonAdmin(t *testing.T) {
	base, _, stop := apiTestServer(t)
	defer stop()

	adminToken := setupAdmin(t, base)

	// Create a non-admin user via the admin API.
	doAPI(t, base, http.MethodPost, "/api/users", adminToken, apiCreateUserReq{
		Username: "regularjoe", Password: "regularjoepassword1", DisplayName: "Joe", IsAdmin: false,
	}, nil)

	// Log in as the non-admin.
	joeToken, ok := loginAs(t, base, "regularjoe", "regularjoepassword1")
	if !ok {
		t.Fatalf("login joe: want 200")
	}

	// Attempt to toggle registration with the non-admin token.
	code, _ := doAPI(t, base, http.MethodPost, "/api/admin/registration", joeToken,
		apiRegistrationReq{Open: true}, nil)
	if code != http.StatusForbidden {
		t.Fatalf("non-admin toggle: got %d want 403", code)
	}
}

// ── /api/me/password ──────────────────────────────────────────────────────────

// TestAPIMePasswordHappyPath is the key acceptance test: it proves that the
// login-issued authz token (not a hand-minted token) is accepted by the
// requireAPIAuth gate on POST /api/me/password. Specifically:
//  1. Create and log in as a regular user to get AuthResp.Token.
//  2. POST /api/me/password {current, new} with that token → 200.
//  3. Subsequent login with the NEW password succeeds.
//  4. Subsequent login with the OLD password fails (401).
func TestAPIMePasswordHappyPath(t *testing.T) {
	base, _, stop := apiTestServer(t)
	defer stop()

	adminToken := setupAdmin(t, base)

	// Create a non-admin user.
	const username = "pwchanger"
	const oldPw = "oldpassword123"
	const newPw = "newpassword456"

	code, _ := doAPI(t, base, http.MethodPost, "/api/users", adminToken, apiCreateUserReq{
		Username: username, Password: oldPw, DisplayName: "PW Changer", IsAdmin: false,
	}, nil)
	if code != http.StatusCreated {
		t.Fatalf("create user: got %d want 201", code)
	}

	// Log in to obtain the real authz token (token-class acceptance test).
	userToken, ok := loginAs(t, base, username, oldPw)
	if !ok {
		t.Fatalf("login: want 200")
	}

	// Change the password using the login-issued token.
	code, _ = doAPI(t, base, http.MethodPost, "/api/me/password", userToken, apiMePasswordReq{
		Current: oldPw,
		New:     newPw,
	}, nil)
	if code != http.StatusOK {
		t.Fatalf("me/password happy path: got %d want 200", code)
	}

	// New password must work.
	_, ok = loginAs(t, base, username, newPw)
	if !ok {
		t.Fatalf("login with new password: want 200 got non-200")
	}

	// Old password must be rejected.
	_, ok = loginAs(t, base, username, oldPw)
	if ok {
		t.Fatalf("login with OLD password after change: want non-200 got 200")
	}
}

// TestAPIMePasswordWrongCurrent verifies that supplying the wrong current password
// returns 401.
func TestAPIMePasswordWrongCurrent(t *testing.T) {
	base, _, stop := apiTestServer(t)
	defer stop()

	adminToken := setupAdmin(t, base)

	const username = "wrongcurrenttest"
	const pw = "correctpassword1"
	doAPI(t, base, http.MethodPost, "/api/users", adminToken, apiCreateUserReq{
		Username: username, Password: pw, DisplayName: "WC", IsAdmin: false,
	}, nil)

	token, ok := loginAs(t, base, username, pw)
	if !ok {
		t.Fatalf("login: want 200")
	}

	code, _ := doAPI(t, base, http.MethodPost, "/api/me/password", token, apiMePasswordReq{
		Current: "wrongpassword99",
		New:     "brandnewpassword1",
	}, nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("wrong current: got %d want 401", code)
	}
}

// TestAPIMePasswordSamePassword verifies that setting the new password equal to
// the current one returns 400.
func TestAPIMePasswordSamePassword(t *testing.T) {
	base, _, stop := apiTestServer(t)
	defer stop()

	adminToken := setupAdmin(t, base)

	const username = "samepwtest"
	const pw = "mypassword1234"
	doAPI(t, base, http.MethodPost, "/api/users", adminToken, apiCreateUserReq{
		Username: username, Password: pw, DisplayName: "SP", IsAdmin: false,
	}, nil)

	token, ok := loginAs(t, base, username, pw)
	if !ok {
		t.Fatalf("login: want 200")
	}

	code, _ := doAPI(t, base, http.MethodPost, "/api/me/password", token, apiMePasswordReq{
		Current: pw,
		New:     pw, // same as current
	}, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("new==current: got %d want 400", code)
	}
}

// TestAPIMePasswordTooShort verifies that a new password under 12 characters
// returns 400.
func TestAPIMePasswordTooShort(t *testing.T) {
	base, _, stop := apiTestServer(t)
	defer stop()

	adminToken := setupAdmin(t, base)

	const username = "shortpwtest"
	const pw = "mypassword1234"
	doAPI(t, base, http.MethodPost, "/api/users", adminToken, apiCreateUserReq{
		Username: username, Password: pw, DisplayName: "SH", IsAdmin: false,
	}, nil)

	token, ok := loginAs(t, base, username, pw)
	if !ok {
		t.Fatalf("login: want 200")
	}

	code, _ := doAPI(t, base, http.MethodPost, "/api/me/password", token, apiMePasswordReq{
		Current: pw,
		New:     "tooshort", // < 12 chars
	}, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("new too short: got %d want 400", code)
	}
}

// TestAPIMePasswordRateLimited verifies that the per-user token bucket on
// POST /api/me/password caps a single user at burst=5, while a second user's
// bucket is independent (the first user's exhaustion does not spill over).
//
// Strategy: send wrong-current-password requests (→ 401) repeatedly until we
// observe a 429.  The bucket starts full at 5; the 6th rapid request must 429.
// No real sleep is needed — the bucket starts full and we fire rapidly enough
// that no tokens refill between calls.
func TestAPIMePasswordRateLimited(t *testing.T) {
	base, _, stop := apiTestServer(t)
	defer stop()

	adminToken := setupAdmin(t, base)

	// ── user A: exhaust the burst ──────────────────────────────────────────────

	const userA = "ratelimitA"
	const pwA = "passwordforA123"
	doAPI(t, base, http.MethodPost, "/api/users", adminToken, apiCreateUserReq{
		Username: userA, Password: pwA, DisplayName: "RL A", IsAdmin: false,
	}, nil)
	tokenA, ok := loginAs(t, base, userA, pwA)
	if !ok {
		t.Fatalf("login userA: want 200")
	}

	// Fire 8 rapid wrong-current-password requests.  Burst is 5, so requests
	// 1-5 consume the bucket (returning 401 — wrong current), and request 6+
	// must return 429 (rate limited, never reaches VerifyHash).
	const attempts = 8
	got429 := false
	gotNon429 := false
	for i := range attempts {
		code, _ := doAPI(t, base, http.MethodPost, "/api/me/password", tokenA, apiMePasswordReq{
			Current: "wrongcurrentpassword",
			New:     "doesnotmatter12",
		}, nil)
		if code == http.StatusTooManyRequests {
			got429 = true
		} else {
			gotNon429 = true
		}
		t.Logf("attempt %d: %d", i+1, code)
	}
	if !got429 {
		t.Fatalf("expected at least one 429 within %d rapid attempts for userA", attempts)
	}
	if !gotNon429 {
		t.Fatalf("expected at least one non-429 (burst should allow first requests) for userA")
	}

	// ── user B: independent bucket — should NOT be rate-limited ───────────────

	const userB = "ratelimitB"
	const pwB = "passwordforB456"
	doAPI(t, base, http.MethodPost, "/api/users", adminToken, apiCreateUserReq{
		Username: userB, Password: pwB, DisplayName: "RL B", IsAdmin: false,
	}, nil)
	tokenB, ok := loginAs(t, base, userB, pwB)
	if !ok {
		t.Fatalf("login userB: want 200")
	}

	// User B's first request with the correct current password should be 200
	// (the bucket for userB is fresh — userA's exhaustion is irrelevant).
	const newPwB = "brandnewpassword789"
	code, _ := doAPI(t, base, http.MethodPost, "/api/me/password", tokenB, apiMePasswordReq{
		Current: pwB,
		New:     newPwB,
	}, nil)
	if code != http.StatusOK {
		t.Fatalf("userB first pw-change: got %d want 200 (per-user buckets must be independent)", code)
	}
}

// TestAPIMePasswordNoBearer asserts that POST /api/me/password without any
// Authorization header returns 401, proving the endpoint is guarded by
// requireAPIAuth (not public).
func TestAPIMePasswordNoBearer(t *testing.T) {
	base, _, stop := apiTestServer(t)
	defer stop()

	// No token passed (empty bearer string).
	code, _ := doAPI(t, base, http.MethodPost, "/api/me/password", "", apiMePasswordReq{
		Current: "anything",
		New:     "newpassword1234",
	}, nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("no bearer: got %d want 401", code)
	}
}

// TestAPIRegistrationStatusReflectsToggle verifies that /api/status reflects the
// registration_open field correctly after an admin toggle.
func TestAPIRegistrationStatusReflectsToggle(t *testing.T) {
	base, _, stop := apiTestServer(t)
	defer stop()

	adminToken := setupAdmin(t, base)

	getStatus := func() bool {
		t.Helper()
		var s struct {
			RegistrationOpen bool `json:"registration_open"`
		}
		code, _ := doAPI(t, base, http.MethodGet, "/api/status", "", nil, &s)
		if code != http.StatusOK {
			t.Fatalf("status: got %d want 200", code)
		}
		return s.RegistrationOpen
	}

	// After setup: registration closed.
	if getStatus() {
		t.Fatalf("after setup: registration_open should be false")
	}

	// Toggle open.
	doAPI(t, base, http.MethodPost, "/api/admin/registration", adminToken,
		apiRegistrationReq{Open: true}, nil)
	if !getStatus() {
		t.Fatalf("after toggle open: registration_open should be true")
	}

	// Toggle closed again.
	doAPI(t, base, http.MethodPost, "/api/admin/registration", adminToken,
		apiRegistrationReq{Open: false}, nil)
	if getStatus() {
		t.Fatalf("after toggle closed: registration_open should be false")
	}
}
