package main

// api.go — JSON management API (Phase 2 mgmt Step 5). A stdlib net/http surface
// (Go 1.22 method+wildcard patterns) for the ArcLore management UI / CLI:
// first-run setup, login (token issue), and admin-gated user/resource/grant CRUD.
//
// SECURITY MODEL:
//   - PUBLIC endpoints: GET /api/status, POST /api/setup, POST /api/login.
//     setup + login are rate-limited per-IP (reuse s.loginRL) to bound argon2 DoS.
//   - ADMIN endpoints: everything else. Gated by requireAPIAdmin — a valid authn
//     bearer token (RS256 + token_version, via authService.VerifyAuthn) whose
//     subject is an admin.
//     401 = no/invalid token; 403 = valid token but not an admin.
//   - The argon2/DB-ordering invariant (store.go) holds here too: every hash op is
//     computed inside s.withHashSem, never under a Store call/DB conn.
//
// NOTE ON NAMING: the API admin gate is requireAPIAdmin (NOT requireAdmin) — the
// web.go interactive surface already owns the method name
// `requireAdmin(w,r) bool`, and Go forbids two methods of the same name on
// *authServer. The plan referred to it as requireAdmin; this is the only
// deviation, forced by the existing web.go method.

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
)

// validPermissions is the closed set of permission strings the API accepts on a
// grant. Mirrors the lore RBAC vocabulary (read/write/owner/admin) plus the
// wildcard-only verbs (obliterate/migrate) that admins carry.
var validPermissions = map[string]struct{}{
	"read":       {},
	"write":      {},
	"owner":      {},
	"admin":      {},
	"obliterate": {},
	"migrate":    {},
}

// isValidPermission reports whether p is one of the allowed permission strings.
func isValidPermission(p string) bool {
	_, ok := validPermissions[strings.TrimSpace(p)]
	return ok
}

// ── JSON helpers ──────────────────────────────────────────────────────────────

// writeJSON serialises v as the response body with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeAPIError writes a {"error": msg} body with the given status code.
func writeAPIError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// decodeJSON decodes the request body into dst. On a decode error it writes a 400
// {"error":"invalid JSON body"} and returns false.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

// ── auth (bearer authn token → admin check) ────────────────────────────────────

// bearerToken extracts the bearer token from the Authorization header, stripping
// a case-insensitive "Bearer " prefix. Returns "" when absent.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	const prefix = "bearer "
	if len(h) >= len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

// apiAuthedHandler is an HTTP handler that also receives the verified claims.
type apiAuthedHandler func(http.ResponseWriter, *http.Request, *arcLoreClaims)

// requireAPIAuth verifies the bearer authn token (authService.VerifyAuthn —
// JWT checks + token_version revocation) and passes the claims to next. 401 on
// a missing, invalid, or revoked token.
func (s *authServer) requireAPIAuth(next apiAuthedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bearer := bearerToken(r)
		if bearer == "" {
			writeAPIError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		// (C2) Store-backed verify: rejects a token whose token_version is stale
		// vs the subject's current row (revoked by a password/admin change), not
		// just JWT-invalid tokens.
		claims, err := s.svc.VerifyAuthn(bearer)
		if err != nil {
			writeAPIError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		next(w, r, claims)
	}
}

// requireAPIAdmin verifies the bearer token (like requireAPIAuth) AND that the
// token's subject is an admin user. 401 = no/invalid token; 403 = valid token
// whose subject is unknown or not an admin.
//
// (Named requireAPIAdmin, not requireAdmin — see the package note: web.go owns
// the `requireAdmin(w,r) bool` method name.)
func (s *authServer) requireAPIAdmin(next apiAuthedHandler) http.HandlerFunc {
	return s.requireAPIAuth(func(w http.ResponseWriter, r *http.Request, claims *arcLoreClaims) {
		u, err := s.users.GetUser(claims.Subject)
		if err != nil {
			writeAPIError(w, http.StatusForbidden, "forbidden")
			return
		}
		if !u.IsAdmin {
			writeAPIError(w, http.StatusForbidden, "forbidden")
			return
		}
		next(w, r, claims)
	})
}

// ── route registration ────────────────────────────────────────────────────────

// registerAPIRoutes mounts the JSON management API. Called from registerRoutes
// inside the `if s.sessions != nil` block (the API needs the attachWeb state).
func (s *authServer) registerAPIRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/status", s.handleAPIStatus)
	mux.HandleFunc("POST /api/setup", s.handleAPISetup)
	mux.HandleFunc("POST /api/login", s.handleAPILogin)
	mux.HandleFunc("POST /api/register", s.handleAPIRegister)

	mux.HandleFunc("POST /api/me/password", s.requireAPIAuth(s.handleAPIMePassword))

	mux.HandleFunc("POST /api/admin/registration", s.requireAPIAdmin(s.handleAPIRegistrationToggle))

	mux.HandleFunc("GET /api/users", s.requireAPIAdmin(s.handleAPIUsersList))
	mux.HandleFunc("POST /api/users", s.requireAPIAdmin(s.handleAPIUsersCreate))
	mux.HandleFunc("DELETE /api/users/{username}", s.requireAPIAdmin(s.handleAPIUsersDelete))
	mux.HandleFunc("POST /api/users/{username}/password", s.requireAPIAdmin(s.handleAPIUsersSetPassword))
	mux.HandleFunc("POST /api/users/{username}/admin", s.requireAPIAdmin(s.handleAPIUsersSetAdmin))

	mux.HandleFunc("GET /api/resources", s.requireAPIAdmin(s.handleAPIResources))
	mux.HandleFunc("POST /api/resources", s.requireAPIAdmin(s.handleAPIResourceCreate))
	mux.HandleFunc("DELETE /api/resources", s.requireAPIAdmin(s.handleAPIResourceDelete))

	mux.HandleFunc("GET /api/users/{username}/grants", s.requireAPIAdmin(s.handleAPIUserGrants))
	mux.HandleFunc("POST /api/grants", s.requireAPIAdmin(s.handleAPIGrantAdd))
	mux.HandleFunc("DELETE /api/grants", s.requireAPIAdmin(s.handleAPIGrantRemove))
}

// ── request/response payloads ──────────────────────────────────────────────────

type apiSetupReq struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
}

type apiLoginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type apiCreateUserReq struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
	IsAdmin     bool   `json:"is_admin"`
}

type apiSetPasswordReq struct {
	Password string `json:"password"`
}

type apiSetAdminReq struct {
	IsAdmin bool `json:"is_admin"`
}

type apiGrantReq struct {
	Username   string `json:"username"`
	ResourceID string `json:"resource_id"`
	Permission string `json:"permission"`
}

// apiRegistrationReq is the body of POST /api/admin/registration.
type apiRegistrationReq struct {
	Open bool `json:"open"`
}

// apiRegisterReq is the body of the PUBLIC POST /api/register.
type apiRegisterReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// apiMePasswordReq is the body of the self-service POST /api/me/password.
type apiMePasswordReq struct {
	Current string `json:"current"`
	New     string `json:"new"`
}

// apiUserResp is the explicit user shape returned to clients — it has NO argon2
// field, so a stored hash can never serialise out of the API.
type apiUserResp struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	IsAdmin     bool   `json:"is_admin"`
	Created     int64  `json:"created"`
}

func userToResp(u User) apiUserResp {
	return apiUserResp{
		Username:    u.Username,
		DisplayName: u.DisplayName,
		IsAdmin:     u.IsAdmin,
		Created:     u.Created,
	}
}

// apiTokenResp is the shared shape for setup/login: a freshly minted authz token
// plus identity. expires_at is in Unix SECONDS.
type apiTokenResp struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"` // Unix SECONDS
	UserID    string `json:"user_id"`
	Name      string `json:"name"`
	IsAdmin   bool   `json:"is_admin"`
}

type apiResourceResp struct {
	ResourceID string `json:"resource_id"`
	Name       string `json:"name"`
	Created    int64  `json:"created"`
}

// ── public endpoints ───────────────────────────────────────────────────────────

// handleAPIStatus reports whether the instance has been set up and whether
// registration is open. PUBLIC.
func (s *authServer) handleAPIStatus(w http.ResponseWriter, _ *http.Request) {
	hasUsers, err := s.users.HasUsers()
	if err != nil {
		log.Printf("api: status has users: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal error")
		return
	}
	regOpen, err := s.users.RegistrationOpen()
	if err != nil {
		log.Printf("api: status registration open: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{
		"has_users":         hasUsers,
		"registration_open": regOpen,
	})
}

// handleAPISetup creates the very first admin (CreateFirstAdmin) and auto-logs in
// by minting an authz token. PUBLIC, rate-limited. 409 if setup already ran.
func (s *authServer) handleAPISetup(w http.ResponseWriter, r *http.Request) {
	if !s.loginRL.allow(clientIP(r)) {
		writeAPIError(w, http.StatusTooManyRequests, "too many requests")
		return
	}
	var req apiSetupReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := validatePassword(req.Password); err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Hash INSIDE the argon2 semaphore — never under a Store call.
	var hash string
	var hashErr error
	s.withHashSem(func() {
		hash, hashErr = HashPassword(req.Password)
	})
	if hashErr != nil {
		writeAPIError(w, http.StatusInternalServerError, "could not hash password")
		return
	}

	// The realistic CreateFirstAdmin failure is username validation (400); DB
	// errors are rare and also surface here as 400 with the error text.
	created, err := s.users.CreateFirstAdmin(req.Username, req.DisplayName, hash)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !created {
		writeAPIError(w, http.StatusConflict, "setup already completed")
		return
	}

	// Auto-login: mint a token for the new admin.
	norm := normalizeUsername(req.Username)
	resp, ok := s.mintTokenResponse(w, norm, "")
	if !ok {
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

// handleAPILogin verifies credentials and mints an authz token. PUBLIC,
// rate-limited. 401 with a GENERIC message on any credential failure.
func (s *authServer) handleAPILogin(w http.ResponseWriter, r *http.Request) {
	if !s.loginRL.allow(clientIP(r)) {
		writeAPIError(w, http.StatusTooManyRequests, "too many requests")
		return
	}
	var req apiLoginReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.Password) > 1024 {
		writeAPIError(w, http.StatusBadRequest, "password too long")
		return
	}

	// Read the stored hash (DB conn released), THEN compare inside the semaphore —
	// never derive a hash under the DB conn (argon2/DB-ordering invariant).
	//
	// Timing-oracle fix: when the user is not found (hashErr != nil) we still run
	// argon2 against dummyArgon2Hash so unknown-user and wrong-password paths do
	// the same work. The VerifyPassword result is discarded on the not-found path;
	// credsOK is still gated on hashErr == nil so an unknown user can never authn.
	hash, hashErr := s.users.VerifyHash(req.Username)
	var credsOK bool
	s.withHashSem(func() {
		h := hash
		if hashErr != nil {
			h = dummyArgon2Hash
		}
		ok := VerifyPassword(h, req.Password)
		credsOK = hashErr == nil && ok
	})
	if !credsOK {
		writeAPIError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	norm := normalizeUsername(req.Username)
	u, _ := s.users.GetUser(norm)
	resp, ok := s.mintTokenResponse(w, norm, u.DisplayName)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// mintTokenResponse resolves effective grants for norm, mints an authz token, and
// builds the shared token response. displayName "" falls back to norm. On any
// failure it writes a 500 and returns ok=false. is_admin comes from the resolved
// user row.
func (s *authServer) mintTokenResponse(w http.ResponseWriter, norm, displayName string) (apiTokenResp, bool) {
	name := displayName
	if name == "" {
		name = norm
	}
	token, expSec, _, err := s.svc.MintFor(norm, name)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "could not mint token")
		return apiTokenResp{}, false
	}
	// is_admin: re-read the row (effectiveResources proved it exists).
	u, _ := s.users.GetUser(norm)
	return apiTokenResp{
		Token:     token,
		ExpiresAt: expSec, // Unix SECONDS
		UserID:    norm,
		Name:      name,
		IsAdmin:   u.IsAdmin,
	}, true
}

// handleAPIRegister creates a NON-ADMIN user via open self-registration and
// auto-logs-in by minting an authz token (like setup). PUBLIC, but server-gated:
// it returns 403 unless registration is open, regardless of the UI. Rate-limited
// per-IP via s.loginRL (a collective backstop — the web tier throttles per
// browser). The new user gets ZERO grants, so it sees no repos until an admin (or
// the CLI) grants access.
func (s *authServer) handleAPIRegister(w http.ResponseWriter, r *http.Request) {
	if !s.loginRL.allow(clientIP(r)) {
		writeAPIError(w, http.StatusTooManyRequests, "too many requests")
		return
	}
	var req apiRegisterReq
	if !decodeJSON(w, r, &req) {
		return
	}

	// Server-side gate — NEVER rely on the UI to hide the form.
	open, err := s.users.RegistrationOpen()
	if err != nil {
		log.Printf("api: register check registration open: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !open {
		writeAPIError(w, http.StatusForbidden, "registration is closed")
		return
	}

	// Username: an EXTRA 3-32 length check on top of validateUsername (which only
	// enforces charset + 1-64). AddUser re-validates charset/normalisation.
	norm := normalizeUsername(req.Username)
	if len(norm) < 3 || len(norm) > 32 {
		writeAPIError(w, http.StatusBadRequest, "username must be 3-32 characters")
		return
	}
	if err := validatePassword(req.Password); err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Derive the hash ONLY inside the argon2 semaphore — never under a Store call.
	var hash string
	var addErr error
	s.withHashSem(func() {
		var hErr error
		hash, hErr = HashPassword(req.Password)
		if hErr != nil {
			addErr = hErr
			return
		}
		addErr = s.users.AddUser(norm, norm, hash, false)
	})
	if addErr != nil {
		switch {
		case errors.Is(addErr, ErrUserExists):
			writeAPIError(w, http.StatusConflict, "username already taken")
		default:
			if isUsernameValidationErr(addErr) {
				writeAPIError(w, http.StatusBadRequest, addErr.Error())
			} else {
				log.Printf("api: register add user: %v", addErr)
				writeAPIError(w, http.StatusInternalServerError, "internal error")
			}
		}
		return
	}

	// Auto-login: mint a token for the new user (a zero-grant non-admin still
	// mints a valid token — effectiveResources returns ok + an empty list).
	resp, ok := s.mintTokenResponse(w, norm, norm)
	if !ok {
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

// handleAPIMePassword lets ANY authenticated user change their OWN password
// (self-service — NOT admin-gated). The caller is identified solely by the
// verified token subject; the current password MUST be re-verified so a stolen
// session cannot silently take over the account.
//
// Ordering mirrors handleAPIUsersSetPassword + handleAPILogin and respects the
// argon2/DB-ordering invariant: VerifyHash (a DB read) runs OUTSIDE the hash
// semaphore (conn released); VerifyPassword + HashPassword (the argon2 ops) run
// INSIDE it, sequentially; SetPassword (a DB write) also runs inside the sem but
// only AFTER hashing has finished — so argon2.IDKey never executes under an open
// DB conn. The current session is intentionally left valid (this is the auth
// server; the web tier owns sessions).
func (s *authServer) handleAPIMePassword(w http.ResponseWriter, r *http.Request, claims *arcLoreClaims) {
	name := claims.Subject
	var req apiMePasswordReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if !s.pwChangeRL.allow(claims.Subject) {
		writeAPIError(w, http.StatusTooManyRequests, "too many requests")
		return
	}

	// Read the stored hash with the DB conn released, BEFORE entering the sem.
	// Any read failure (incl. ErrUserNotFound) collapses to a generic 401 — the
	// "current password incorrect" message deliberately does not distinguish a
	// missing user from a wrong password.
	if err := validatePassword(req.New); err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}

	hash, vErr := s.users.VerifyHash(name)
	if vErr != nil {
		writeAPIError(w, http.StatusUnauthorized, "current password incorrect")
		return
	}

	// Capture status+msg from inside the sem; 0 status means success.
	var status int
	var msg string
	s.withHashSem(func() {
		if !VerifyPassword(hash, req.Current) {
			status, msg = http.StatusUnauthorized, "current password incorrect"
			return
		}
		if req.New == req.Current {
			status, msg = http.StatusBadRequest, "new password must differ from current"
			return
		}
		newHash, hErr := HashPassword(req.New)
		if hErr != nil {
			status, msg = http.StatusInternalServerError, "could not hash password"
			return
		}
		if setErr := s.users.SetPassword(name, newHash); setErr != nil {
			log.Printf("api: me password set: %v", setErr)
			status, msg = http.StatusInternalServerError, "internal error"
			return
		}
	})
	if status != 0 {
		writeAPIError(w, status, msg)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"updated": name})
}

// handleAPIRegistrationToggle flips whether self-registration is open. ADMIN.
func (s *authServer) handleAPIRegistrationToggle(w http.ResponseWriter, r *http.Request, _ *arcLoreClaims) {
	var req apiRegistrationReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.users.SetRegistrationOpen(req.Open); err != nil {
		log.Printf("api: registration toggle: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"registration_open": req.Open})
}

// ── admin: users ───────────────────────────────────────────────────────────────

// handleAPIUsersList returns all users (no hash field). ADMIN.
func (s *authServer) handleAPIUsersList(w http.ResponseWriter, _ *http.Request, _ *arcLoreClaims) {
	users, err := s.users.ListUsers()
	if err != nil {
		log.Printf("api: list users: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal error")
		return
	}
	out := make([]apiUserResp, 0, len(users))
	for _, u := range users {
		out = append(out, userToResp(u))
	}
	writeJSON(w, http.StatusOK, out)
}

// handleAPIUsersCreate adds a user. ADMIN. 409 on existing, 400 on bad username.
func (s *authServer) handleAPIUsersCreate(w http.ResponseWriter, r *http.Request, _ *arcLoreClaims) {
	var req apiCreateUserReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := validatePassword(req.Password); err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}

	var hash string
	var addErr error
	s.withHashSem(func() {
		var hErr error
		hash, hErr = HashPassword(req.Password)
		if hErr != nil {
			addErr = hErr
			return
		}
		addErr = s.users.AddUser(req.Username, req.DisplayName, hash, req.IsAdmin)
	})
	if addErr != nil {
		switch {
		case errors.Is(addErr, ErrUserExists):
			writeAPIError(w, http.StatusConflict, "user already exists")
		default:
			// validateUsername failures are not a typed sentinel; treat any
			// non-ErrUserExists error from AddUser as a 400 validation error
			// when it stems from the username, else 500. AddUser only returns
			// validateUsername errors or DB errors; the former is far more likely.
			if isUsernameValidationErr(addErr) {
				writeAPIError(w, http.StatusBadRequest, addErr.Error())
			} else {
				log.Printf("api: create user add user: %v", addErr)
				writeAPIError(w, http.StatusInternalServerError, "internal error")
			}
		}
		return
	}

	u, err := s.users.GetUser(req.Username)
	if err != nil {
		log.Printf("api: create user get user: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusCreated, userToResp(u))
}

// isUsernameValidationErr reports whether err is a validateUsername rejection
// (empty or charset). validateUsername returns plain errors.New / fmt.Errorf, so
// we match on their stable message fragments rather than a sentinel.
func isUsernameValidationErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "username must not be empty") ||
		strings.Contains(msg, "invalid username")
}

// handleAPIUsersDelete deletes a user, refusing to remove the last admin. ADMIN.
func (s *authServer) handleAPIUsersDelete(w http.ResponseWriter, r *http.Request, _ *arcLoreClaims) {
	name := r.PathValue("username")

	u, err := s.users.GetUser(name)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeAPIError(w, http.StatusNotFound, "user not found")
			return
		}
		log.Printf("api: delete user get user: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if u.IsAdmin {
		n, err := s.users.CountAdmins()
		if err != nil {
			log.Printf("api: delete user count admins: %v", err)
			writeAPIError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if n <= 1 {
			writeAPIError(w, http.StatusConflict, "cannot delete the last admin")
			return
		}
	}

	if err := s.users.DeleteUser(name); err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeAPIError(w, http.StatusNotFound, "user not found")
			return
		}
		log.Printf("api: delete user: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": normalizeUsername(name)})
}

// handleAPIUsersSetPassword replaces a user's password. ADMIN.
func (s *authServer) handleAPIUsersSetPassword(w http.ResponseWriter, r *http.Request, _ *arcLoreClaims) {
	name := r.PathValue("username")
	var req apiSetPasswordReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := validatePassword(req.Password); err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}

	var hash string
	var setErr error
	s.withHashSem(func() {
		var hErr error
		hash, hErr = HashPassword(req.Password)
		if hErr != nil {
			setErr = hErr
			return
		}
		setErr = s.users.SetPassword(name, hash)
	})
	if setErr != nil {
		if errors.Is(setErr, ErrUserNotFound) {
			writeAPIError(w, http.StatusNotFound, "user not found")
			return
		}
		log.Printf("api: set password: %v", setErr)
		writeAPIError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"updated": normalizeUsername(name)})
}

// handleAPIUsersSetAdmin flips a user's admin flag, refusing to demote the last
// admin. ADMIN.
func (s *authServer) handleAPIUsersSetAdmin(w http.ResponseWriter, r *http.Request, _ *arcLoreClaims) {
	name := r.PathValue("username")
	var req apiSetAdminReq
	if !decodeJSON(w, r, &req) {
		return
	}

	if !req.IsAdmin {
		// Demotion: block if this would remove the last admin.
		u, err := s.users.GetUser(name)
		if err != nil {
			if errors.Is(err, ErrUserNotFound) {
				writeAPIError(w, http.StatusNotFound, "user not found")
				return
			}
			log.Printf("api: set admin get user: %v", err)
			writeAPIError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if u.IsAdmin {
			n, err := s.users.CountAdmins()
			if err != nil {
				log.Printf("api: set admin count admins: %v", err)
				writeAPIError(w, http.StatusInternalServerError, "internal error")
				return
			}
			if n <= 1 {
				writeAPIError(w, http.StatusConflict, "cannot demote the last admin")
				return
			}
		}
	}

	if err := s.users.SetAdmin(name, req.IsAdmin); err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeAPIError(w, http.StatusNotFound, "user not found")
			return
		}
		log.Printf("api: set admin: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"username": normalizeUsername(name),
		"is_admin": req.IsAdmin,
	})
}

// ── admin: resources ───────────────────────────────────────────────────────────

// handleAPIResources lists every registered resource. ADMIN.
func (s *authServer) handleAPIResources(w http.ResponseWriter, _ *http.Request, _ *arcLoreClaims) {
	resources, err := s.users.ListResources()
	if err != nil {
		log.Printf("api: list resources: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal error")
		return
	}
	out := make([]apiResourceResp, 0, len(resources))
	for _, r := range resources {
		out = append(out, apiResourceResp{
			ResourceID: r.ResourceID,
			Name:       r.Name,
			Created:    r.Created,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// apiResourceCreateReq is the body of POST /api/resources.
type apiResourceCreateReq struct {
	ResourceID string `json:"resource_id"` // raw 32-hex repo id, or already urc-prefixed
	Name       string `json:"name"`        // optional display name
}

// apiResourceDeleteReq is the body of DELETE /api/resources.
type apiResourceDeleteReq struct {
	ResourceID string `json:"resource_id"` // raw 32-hex repo id, or already urc-prefixed
}

// normalizeResourceID accepts a repository id as raw 32-hex (the value shown in
// the admin Repos "Repository ID" column) or already "urc-"-prefixed, and
// returns the canonical "urc-<32hex>" form resources are keyed by. It rejects
// the wildcard and anything that is not exactly 32 hex chars.
func normalizeResourceID(in string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(in))
	s = strings.TrimPrefix(s, "urc-")
	if len(s) != 32 {
		return "", errors.New("repository id must be 32 hex chars (the value in the admin Repos ID column)")
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return "", errors.New("repository id must be hexadecimal")
		}
	}
	return "urc-" + s, nil
}

// handleAPIResourceCreate registers (imports) an existing repository as a
// resource and grants the calling admin owner. ADMIN. This surfaces repos that
// exist on lore-server but have no resource row here — e.g. created before this
// control plane existed, or after a DB reset — so they appear in RepositoryList
// (which, with auth enabled, is built solely from the caller's concrete resource
// grants; the urc-* wildcard does NOT expand there). Idempotent: re-importing
// updates the name (UpsertResource) and re-grants owner (INSERT OR IGNORE).
func (s *authServer) handleAPIResourceCreate(w http.ResponseWriter, r *http.Request, claims *arcLoreClaims) {
	var req apiResourceCreateReq
	if !decodeJSON(w, r, &req) {
		return
	}
	id, err := normalizeResourceID(req.ResourceID)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Resource row first (GrantOwner has a FK on it).
	if _, err := s.users.UpsertResource(id, strings.TrimSpace(req.Name)); err != nil {
		log.Printf("api: create resource upsert: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := s.users.GrantOwner(claims.Subject, id); err != nil {
		log.Printf("api: create resource grant owner: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusCreated, apiResourceResp{
		ResourceID: id,
		Name:       strings.TrimSpace(req.Name),
	})
}

// handleAPIResourceDelete removes a resource row (and cascades its grants) from
// arc-lore-auth. Admin-gated via requireAPIAdmin; intentionally direct (not via
// rebac) because the caller is a verified global admin operating on the control
// plane, not a lore-server-originated authorization check. Idempotent: a missing
// resource row is not an error (store.DeleteResource is idempotent).
func (s *authServer) handleAPIResourceDelete(w http.ResponseWriter, r *http.Request, _ *arcLoreClaims) {
	var req apiResourceDeleteReq
	if !decodeJSON(w, r, &req) {
		return
	}
	id, err := normalizeResourceID(req.ResourceID)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.users.DeleteResource(id); err != nil {
		log.Printf("api: delete resource: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"removed": id})
}

// ── admin: grants ──────────────────────────────────────────────────────────────

// handleAPIUserGrants returns a user's grants as resource_id -> permissions.
// ADMIN. An unknown user yields an empty map (not an error).
func (s *authServer) handleAPIUserGrants(w http.ResponseWriter, r *http.Request, _ *arcLoreClaims) {
	name := r.PathValue("username")
	grants, err := s.users.GrantsFor(name)
	if err != nil {
		log.Printf("api: user grants: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, grants)
}

// handleAPIGrantAdd grants a permission to a user on a resource. ADMIN. Validates
// the permission, the user, and the resource before AddGrant.
func (s *authServer) handleAPIGrantAdd(w http.ResponseWriter, r *http.Request, _ *arcLoreClaims) {
	var req apiGrantReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if !isValidPermission(req.Permission) {
		writeAPIError(w, http.StatusBadRequest, "invalid permission")
		return
	}

	// User must exist.
	if _, err := s.users.GetUser(req.Username); err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeAPIError(w, http.StatusNotFound, "user not found")
			return
		}
		log.Printf("api: add grant get user: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Resource must exist.
	resources, err := s.users.ListResources()
	if err != nil {
		log.Printf("api: add grant list resources: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal error")
		return
	}
	wantID := strings.TrimSpace(req.ResourceID)
	found := false
	for _, res := range resources {
		if res.ResourceID == wantID {
			found = true
			break
		}
	}
	if !found {
		writeAPIError(w, http.StatusNotFound, "resource not found")
		return
	}

	if err := s.users.AddGrant(req.Username, req.ResourceID, req.Permission); err != nil {
		log.Printf("api: add grant: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"granted": map[string]string{
			"username":    normalizeUsername(req.Username),
			"resource_id": wantID,
			"permission":  strings.TrimSpace(req.Permission),
		},
	})
}

// handleAPIGrantRemove revokes a permission. ADMIN. Idempotent (RemoveGrant).
func (s *authServer) handleAPIGrantRemove(w http.ResponseWriter, r *http.Request, _ *arcLoreClaims) {
	var req apiGrantReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if !isValidPermission(req.Permission) {
		writeAPIError(w, http.StatusBadRequest, "invalid permission")
		return
	}
	if err := s.users.RemoveGrant(req.Username, req.ResourceID, req.Permission); err != nil {
		log.Printf("api: remove grant: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"removed": map[string]string{
			"username":    normalizeUsername(req.Username),
			"resource_id": strings.TrimSpace(req.ResourceID),
			"permission":  strings.TrimSpace(req.Permission),
		},
	})
}
