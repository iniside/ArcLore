package main

// web.go — interactive browser login (/login) and the user-admin pages
// (/admin*). These handlers WRITE credentials and COMPLETE auth sessions, so
// they are the security-sensitive surface of arc-lore-auth.
//
// ──────────────────────────────────────────────────────────────────────────────
// CLEARTEXT CAVEAT (read this before deploying):
//
// These pages are served over PLAIN HTTP (the same listener as JWKS). Passwords
// typed into /login and /admin therefore cross the network IN CLEARTEXT. This is
// acceptable ONLY on a trusted LAN. TLS on the web pages (ACME / a fronting
// reverse proxy) is an explicit out-of-scope follow-up.
//
// Consequence for cookies: we do NOT set the `Secure` flag on the CSRF or
// admin-unlock cookies. A `Secure` cookie is dropped by the browser over http://
// — setting it would silently break CSRF/admin entirely while looking safer. We
// use HttpOnly + SameSite=Lax instead (HttpOnly blocks JS theft; SameSite=Lax
// blocks cross-site form posts). The pages also carry a visible cleartext
// warning banner so the operator/artist knows the channel is unencrypted.
// ──────────────────────────────────────────────────────────────────────────────

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ── tunables ────────────────────────────────────────────────────────────────

const (
	// hashSemCap bounds concurrent argon2 IDKey calls reachable from HTTP. Each
	// call costs ~64 MiB; capping at 4 bounds the worst-case spike to ~256 MiB.
	hashSemCap = 4

	// CSRF cookie/field name + token byte length (128-bit).
	csrfCookieName = "arc_csrf"
	csrfTokenLen   = 16

	// admin-unlock cookie name + lifetime.
	adminCookieName = "arc_admin"
	adminCookieTTL  = 30 * time.Minute

	// rate-limit: tokens per IP and refill cadence for the POST endpoints.
	rlBurst       = 8
	rlRefillEvery = 6 * time.Second // one token back every 6s → ~10/min steady
)

// attachWeb injects the shared session + user stores and constructs the web
// layer's supporting state (argon2 semaphore, rate limiters, admin gate). Called
// from main.go with the SAME pointers the gRPC server holds.
func (s *authServer) attachWeb(sessions *SessionStore, users StoreInterface) {
	s.sessions = sessions
	s.users = users
	// Build the single mint site from the fields the server already holds.
	s.svc = &authService{cfg: s.cfg, priv: s.priv, kid: s.kid, store: users}
	s.hashSem = make(chan struct{}, hashSemCap)
	s.loginRL = newRateLimiter(rlBurst, rlRefillEvery)
	s.adminRL = newRateLimiter(rlBurst, rlRefillEvery)
	s.pwChangeRL = newRateLimiter(5, 30*time.Second)
	s.adminAuth = newAdminGate()
}

// withHashSem runs fn while holding one argon2 semaphore slot, blocking until a
// slot is free. Every password-hash op reachable from HTTP (Verify on /login,
// Add/SetPassword on /admin) goes through here so a flood of logins cannot fan
// out unbounded 64 MiB allocations.
func (s *authServer) withHashSem(fn func()) {
	s.hashSem <- struct{}{}
	defer func() { <-s.hashSem }()
	fn()
}

// ── client IP + rate limiting ─────────────────────────────────────────────────

// clientIP extracts a best-effort client IP for rate-limiting. We trust the
// socket peer (RemoteAddr) only — X-Forwarded-For is NOT honoured because this
// service is meant to face a trusted LAN directly; honouring a spoofable header
// would let a client mint unlimited buckets.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// rateLimiter is a simple per-key (per-IP) token bucket. allow() decrements a
// bucket, refilling lazily by elapsed time. In-memory + process-local — adequate
// for a single small host; not a distributed limiter.
type rateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	burst    int
	refill   time.Duration
	lastTrim time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(burst int, refill time.Duration) *rateLimiter {
	return &rateLimiter{
		buckets:  make(map[string]*bucket),
		burst:    burst,
		refill:   refill,
		lastTrim: time.Now(),
	}
}

// allow reports whether the key has a token to spend, consuming one if so.
func (rl *rateLimiter) allow(key string) bool {
	now := time.Now()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.trimLocked(now)

	b, ok := rl.buckets[key]
	if !ok {
		b = &bucket{tokens: float64(rl.burst), last: now}
		rl.buckets[key] = b
	}

	// Lazy refill: add tokens for elapsed time, capped at burst.
	elapsed := now.Sub(b.last)
	b.tokens += elapsed.Seconds() / rl.refill.Seconds()
	if b.tokens > float64(rl.burst) {
		b.tokens = float64(rl.burst)
	}
	b.last = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// trimLocked drops idle buckets so the map cannot grow unbounded under churning
// source IPs. Caller MUST hold rl.mu. Two-pass: collect dead keys, then delete.
func (rl *rateLimiter) trimLocked(now time.Time) {
	if now.Sub(rl.lastTrim) < 5*time.Minute {
		return
	}
	rl.lastTrim = now
	idle := now.Add(-10 * time.Minute)
	dead := make([]string, 0)
	for key, b := range rl.buckets {
		if b.last.Before(idle) {
			dead = append(dead, key)
		}
	}
	for _, key := range dead {
		delete(rl.buckets, key)
	}
}

// ── CSRF (cookie + hidden field, constant-time compared) ───────────────────────

// csrfToken returns the token from the request's CSRF cookie, minting + setting a
// fresh one if absent. The same value is embedded as a hidden form field; on POST
// the field must constant-time-equal the cookie (double-submit pattern).
func csrfToken(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(csrfCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	raw := make([]byte, csrfTokenLen)
	if _, err := rand.Read(raw); err != nil {
		// Extremely unlikely; an empty token simply fails the next POST check.
		return ""
	}
	tok := base64.RawURLEncoding.EncodeToString(raw)
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		// Secure intentionally omitted — see the cleartext caveat at the top.
	})
	return tok
}

// checkCSRF constant-time-compares the posted form token against the cookie.
func checkCSRF(r *http.Request) bool {
	c, err := r.Cookie(csrfCookieName)
	if err != nil || c.Value == "" {
		return false
	}
	field := r.PostFormValue("csrf")
	if field == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(field)) == 1
}

// ── admin gate (signed short-lived cookie) ────────────────────────────────────

// adminGate issues + validates the admin-unlock cookie. The cookie value is
// `<expiryUnix>.<hmac>` where hmac = HMAC-SHA256(key, expiryUnix). The signing
// key is random per process, so cookies do not survive a restart (operators
// simply re-unlock) and cannot be forged without the in-memory key.
type adminGate struct {
	key []byte
}

func newAdminGate() *adminGate {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		// A nil key makes every validate() fail closed — acceptable.
		return &adminGate{}
	}
	return &adminGate{key: key}
}

func (g *adminGate) issue(now time.Time) string {
	if len(g.key) == 0 {
		return ""
	}
	exp := now.Add(adminCookieTTL).Unix()
	msg := strconv.FormatInt(exp, 10)
	mac := hmac.New(sha256.New, g.key)
	mac.Write([]byte(msg))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return msg + "." + sig
}

// valid reports whether the cookie value is a well-formed, unexpired, correctly
// signed admin token. Constant-time HMAC compare; never leaks which check failed.
func (g *adminGate) valid(value string, now time.Time) bool {
	if len(g.key) == 0 || value == "" {
		return false
	}
	dot := strings.LastIndexByte(value, '.')
	if dot <= 0 || dot == len(value)-1 {
		return false
	}
	msg, sig := value[:dot], value[dot+1:]

	mac := hmac.New(sha256.New, g.key)
	mac.Write([]byte(msg))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		return false
	}

	exp, err := strconv.ParseInt(msg, 10, 64)
	if err != nil {
		return false
	}
	return now.Unix() < exp
}

// adminUnlocked reports whether the request carries a valid admin cookie.
func (s *authServer) adminUnlocked(r *http.Request) bool {
	c, err := r.Cookie(adminCookieName)
	if err != nil {
		return false
	}
	return s.adminAuth.valid(c.Value, time.Now())
}

// ── templates (server-rendered html/template; auto-escaping) ───────────────────

// cleartextNote is shown on every web page so users know the channel is plain
// HTTP — passwords cross the LAN unencrypted.
const cleartextNote = `Served over plain HTTP — passwords travel in cleartext. Use only on a trusted network.`

const pageStyle = `<style>
body{font-family:system-ui,sans-serif;max-width:640px;margin:3rem auto;padding:0 1rem;color:#222}
h1{font-size:1.4rem}
form{margin:1rem 0;padding:1rem;border:1px solid #ccc;border-radius:8px}
label{display:block;margin:.5rem 0 .15rem}
input[type=text],input[type=password]{width:100%;padding:.45rem;box-sizing:border-box}
button{margin-top:.8rem;padding:.5rem 1rem;cursor:pointer}
.warn{background:#fff4e5;border:1px solid #e0a96d;padding:.6rem .8rem;border-radius:6px;font-size:.85rem;color:#7a4d00}
.err{background:#fdecea;border:1px solid #d9534f;padding:.6rem .8rem;border-radius:6px;color:#a12622}
.ok{background:#e8f5e9;border:1px solid #4caf50;padding:.6rem .8rem;border-radius:6px;color:#1b5e20}
table{border-collapse:collapse;width:100%;margin:1rem 0}
th,td{border:1px solid #ddd;padding:.4rem .5rem;text-align:left;font-size:.9rem}
fieldset{border:1px solid #ccc;border-radius:8px;margin:1rem 0}
small{color:#666}
</style>`

var (
	loginTmpl       = template.Must(template.New("login").Parse(loginHTML))
	loginDoneTmpl   = template.Must(template.New("loginDone").Parse(loginDoneHTML))
	loginBadTmpl    = template.Must(template.New("loginBad").Parse(loginBadHTML))
	adminUnlockTmpl = template.Must(template.New("adminUnlock").Parse(adminUnlockHTML))
	adminTmpl       = template.Must(template.New("admin").Parse(adminHTML))
)

const loginHTML = `<!doctype html><html><head><meta charset="utf-8"><title>Sign in — ArcLore</title>` + pageStyle + `</head><body>
<h1>Sign in to ArcLore</h1>
<div class="warn">{{.Cleartext}}</div>
{{if .Err}}<div class="err">{{.Err}}</div>{{end}}
<form method="POST" action="/login?session={{.Session}}">
  <input type="hidden" name="session" value="{{.Session}}">
  <input type="hidden" name="csrf" value="{{.CSRF}}">
  <label for="u">Username</label>
  <input type="text" id="u" name="username" autocomplete="username" autofocus>
  <label for="p">Password</label>
  <input type="password" id="p" name="password" autocomplete="current-password">
  <button type="submit">Sign in</button>
</form>
</body></html>`

const loginDoneHTML = `<!doctype html><html><head><meta charset="utf-8"><title>Signed in — ArcLore</title>` + pageStyle + `</head><body>
<h1>Signed in</h1>
<div class="ok">Signed in as <strong>{{.User}}</strong>. Return to your editor — you can close this tab.</div>
</body></html>`

const loginBadHTML = `<!doctype html><html><head><meta charset="utf-8"><title>Login link — ArcLore</title>` + pageStyle + `</head><body>
<h1>Login link invalid</h1>
<div class="err">This login link is invalid or has expired. Start the login again from your editor or the CLI.</div>
</body></html>`

const adminUnlockHTML = `<!doctype html><html><head><meta charset="utf-8"><title>Admin — ArcLore</title>` + pageStyle + `</head><body>
<h1>ArcLore admin</h1>
<div class="warn">{{.Cleartext}}</div>
{{if .Err}}<div class="err">{{.Err}}</div>{{end}}
<form method="POST" action="/admin/unlock">
  <input type="hidden" name="csrf" value="{{.CSRF}}">
  <label for="s">Admin secret</label>
  <input type="password" id="s" name="secret" autocomplete="off" autofocus>
  <button type="submit">Unlock</button>
</form>
</body></html>`

const adminHTML = `<!doctype html><html><head><meta charset="utf-8"><title>Admin — ArcLore</title>` + pageStyle + `</head><body>
<h1>ArcLore user admin</h1>
<div class="warn">{{.Cleartext}}</div>
{{if .Err}}<div class="err">{{.Err}}</div>{{end}}
{{if .OK}}<div class="ok">{{.OK}}</div>{{end}}

<h2>Users</h2>
<table>
  <tr><th>Username</th><th>Display name</th><th>Created</th><th>Updated</th></tr>
  {{range .Users}}<tr><td>{{.Username}}</td><td>{{.DisplayName}}</td><td>{{.CreatedStr}}</td><td>{{.UpdatedStr}}</td></tr>{{else}}<tr><td colspan="4"><small>No users yet.</small></td></tr>{{end}}
</table>

<fieldset><legend>Create user</legend>
<form method="POST" action="/admin/users">
  <input type="hidden" name="csrf" value="{{.CSRF}}">
  <label>Username</label><input type="text" name="username">
  <label>Display name (optional)</label><input type="text" name="display_name">
  <label>Password</label><input type="password" name="password" autocomplete="new-password">
  <button type="submit">Create</button>
</form></fieldset>

<fieldset><legend>Set password</legend>
<form method="POST" action="/admin/users/setpw">
  <input type="hidden" name="csrf" value="{{.CSRF}}">
  <label>Username</label><input type="text" name="username">
  <label>New password</label><input type="password" name="password" autocomplete="new-password">
  <button type="submit">Set password</button>
</form></fieldset>

<fieldset><legend>Delete user</legend>
<form method="POST" action="/admin/users/delete">
  <input type="hidden" name="csrf" value="{{.CSRF}}">
  <label>Username</label><input type="text" name="username">
  <button type="submit">Delete</button>
</form></fieldset>
</body></html>`

// adminUserRow is a List() user with formatted timestamps for the table.
type adminUserRow struct {
	Username    string
	DisplayName string
	CreatedStr  string
	UpdatedStr  string
}

func toAdminRows(users []User) []adminUserRow {
	rows := make([]adminUserRow, 0, len(users))
	for _, u := range users {
		rows = append(rows, adminUserRow{
			Username:    u.Username,
			DisplayName: u.DisplayName,
			CreatedStr:  unixToStr(u.Created),
			UpdatedStr:  unixToStr(u.Updated),
		})
	}
	return rows
}

func unixToStr(sec int64) string {
	if sec == 0 {
		return ""
	}
	return time.Unix(sec, 0).UTC().Format("2006-01-02 15:04 UTC")
}

// ── /login ─────────────────────────────────────────────────────────────────

// handleLogin serves the interactive-login page (GET) and completes the session
// (POST). The browser carries ONLY the session code — never client_state.
func (s *authServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleLoginGet(w, r)
	case http.MethodPost:
		s.handleLoginPost(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *authServer) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimSpace(r.URL.Query().Get("session"))
	// Validate: must exist, be pending, unexpired. Neutral page otherwise — do
	// not leak whether the code was unknown vs expired vs already used.
	sess, ok := s.sessions.Get(code)
	if !ok || sess.status != sessionPending {
		renderLoginBad(w)
		return
	}

	csrf := csrfToken(w, r)
	renderHTML(w, http.StatusOK, loginTmpl, map[string]any{
		"Cleartext": cleartextNote,
		"Session":   code,
		"CSRF":      csrf,
		"Err":       "",
	})
}

func (s *authServer) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	if !s.loginRL.allow(clientIP(r)) {
		http.Error(w, "too many requests — slow down", http.StatusTooManyRequests)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	code := strings.TrimSpace(r.PostFormValue("session"))
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")

	// Re-validate the session up front (pending + unexpired). If the link is
	// dead, show the neutral invalid page rather than a credential error.
	sess, ok := s.sessions.Get(code)
	if !ok || sess.status != sessionPending {
		renderLoginBad(w)
		return
	}

	// CSRF + credential verification: ALWAYS run Verify (constant-time-ish) so a
	// CSRF failure is indistinguishable in timing from a bad password. We collect
	// failure into one generic outcome and never reveal which check failed.
	csrfOK := checkCSRF(r)

	// Read the stored hash with the DB conn released, THEN run the argon2 compare
	// inside the hash semaphore — never derive a hash while holding the single DB
	// conn (the argon2/DB-ordering invariant; see store.go).
	//
	// Timing-oracle fix: when the user is not found (hashErr != nil) we still run
	// argon2 against dummyArgon2Hash so unknown-user and wrong-password paths do
	// the same work. The VerifyPassword result is discarded on the not-found path;
	// credsOK is still gated on hashErr == nil so an unknown user can never authn.
	hash, hashErr := s.users.VerifyHash(username)

	var credsOK bool
	s.withHashSem(func() {
		h := hash
		if hashErr != nil {
			h = dummyArgon2Hash
		}
		ok := VerifyPassword(h, password)
		credsOK = hashErr == nil && ok
	})

	if !csrfOK || !credsOK {
		s.renderLoginError(w, r, code)
		return
	}

	// Mint the token carrying the caller's EFFECTIVE grants directly
	// (grant-driven), not an empty resource set: admin → all repos + urc-*;
	// non-admin → exactly their grants. aud = cfg.Audience (the lore-server
	// domain). Subject + display name both come from the verified username.
	// VerifyHash already proved the row exists, so effectiveResources's ok is
	// true in practice; we still fail closed (500, no urc-*) if it is not.
	norm := normalizeUsername(username)
	// expires_at in MILLISECONDS to match the UserToken/exchange unit.
	token, _, expiresAtMs, err := s.svc.MintFor(norm, norm)
	if err != nil {
		http.Error(w, "internal error minting token", http.StatusInternalServerError)
		return
	}

	if err := s.sessions.Complete(code, norm, token, expiresAtMs); err != nil {
		// The session lapsed between validation and completion (raced eviction or
		// a concurrent complete). Neutral invalid-link page.
		renderLoginBad(w)
		return
	}

	renderHTML(w, http.StatusOK, loginDoneTmpl, map[string]any{
		"User": norm,
	})
}

// renderLoginError re-renders the login form with a generic message. It must
// only be reached for a session that is still valid+pending (otherwise show the
// neutral invalid-link page).
func (s *authServer) renderLoginError(w http.ResponseWriter, r *http.Request, code string) {
	csrf := csrfToken(w, r)
	renderHTML(w, http.StatusUnauthorized, loginTmpl, map[string]any{
		"Cleartext": cleartextNote,
		"Session":   code,
		"CSRF":      csrf,
		"Err":       "Invalid username or password.",
	})
}

func renderLoginBad(w http.ResponseWriter) {
	renderHTML(w, http.StatusOK, loginBadTmpl, map[string]any{})
}

// ── /admin ───────────────────────────────────────────────────────────────────

// adminDisabled writes the fail-closed 503 page when admin_secret is unset. We
// NEVER serve admin open: an empty secret disables the whole surface.
func (s *authServer) adminDisabled(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte(`<!doctype html><meta charset="utf-8">` + pageStyle +
		`<h1>Admin disabled</h1><div class="err">User admin is disabled because <code>admin_secret</code> is not set. Set it in config.toml and restart to enable <code>/admin</code>.</div>`))
}

// requireAdmin gates a handler: serves the 503 page if admin is disabled, the
// unlock form if not yet unlocked. Returns true only when the caller may proceed.
func (s *authServer) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if s.cfg.AdminSecret == "" {
		s.adminDisabled(w)
		return false
	}
	if !s.adminUnlocked(r) {
		s.renderAdminUnlock(w, r, "")
		return false
	}
	return true
}

func (s *authServer) renderAdminUnlock(w http.ResponseWriter, r *http.Request, errMsg string) {
	csrf := csrfToken(w, r)
	status := http.StatusOK
	if errMsg != "" {
		status = http.StatusUnauthorized
	}
	renderHTML(w, status, adminUnlockTmpl, map[string]any{
		"Cleartext": cleartextNote,
		"CSRF":      csrf,
		"Err":       errMsg,
	})
}

// handleAdmin renders the user-management page (GET only; the mutating POSTs live
// at /admin/users*).
func (s *authServer) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	s.renderAdmin(w, r, "", "")
}

func (s *authServer) renderAdmin(w http.ResponseWriter, r *http.Request, okMsg, errMsg string) {
	csrf := csrfToken(w, r)
	users, listErr := s.users.ListUsers()
	if listErr != nil {
		// Surface the read failure in the error banner rather than panicking.
		if errMsg == "" {
			errMsg = "Could not load users: " + listErr.Error()
		}
		users = nil
	}
	status := http.StatusOK
	if errMsg != "" {
		status = http.StatusBadRequest
	}
	renderHTML(w, status, adminTmpl, map[string]any{
		"Cleartext": cleartextNote,
		"CSRF":      csrf,
		"Users":     toAdminRows(users),
		"OK":        okMsg,
		"Err":       errMsg,
	})
}

// handleAdminUnlock processes the admin-secret form (constant-time compare) and,
// on success, sets the short-lived signed admin cookie.
func (s *authServer) handleAdminUnlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.cfg.AdminSecret == "" {
		s.adminDisabled(w)
		return
	}
	if !s.adminRL.allow(clientIP(r)) {
		http.Error(w, "too many requests — slow down", http.StatusTooManyRequests)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !checkCSRF(r) {
		s.renderAdminUnlock(w, r, "Session expired — try again.")
		return
	}

	provided := r.PostFormValue("secret")
	// Dual-mode admin-secret verification:
	//   - $argon2id$… PHC hash → re-derive under the hash semaphore (never derive
	//     a hash unbounded; argon2 is memory-hard and concurrent unlock attempts
	//     would otherwise exhaust memory — the same invariant as the login path).
	//   - plaintext (back-compat) → constant-time compare so existing configs
	//     keep working without a forced upgrade.
	if strings.HasPrefix(s.cfg.AdminSecret, "$argon2id$") {
		var ok bool
		s.withHashSem(func() { ok = VerifyPassword(s.cfg.AdminSecret, provided) })
		if !ok {
			s.renderAdminUnlock(w, r, "Incorrect admin secret.")
			return
		}
	} else if subtle.ConstantTimeCompare([]byte(provided), []byte(s.cfg.AdminSecret)) != 1 {
		s.renderAdminUnlock(w, r, "Incorrect admin secret.")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    s.adminAuth.issue(time.Now()),
		Path:     "/admin",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(adminCookieTTL.Seconds()),
		// Secure intentionally omitted — see cleartext caveat at top.
	})
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// adminMutationGuard wraps the shared preamble for the three mutating POSTs:
// method check, admin gate, rate-limit, form parse, CSRF. Returns ok=false (and
// has already written a response) if the request should not proceed.
func (s *authServer) adminMutationGuard(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	if !s.requireAdmin(w, r) {
		return false
	}
	if !s.adminRL.allow(clientIP(r)) {
		http.Error(w, "too many requests — slow down", http.StatusTooManyRequests)
		return false
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return false
	}
	if !checkCSRF(r) {
		s.renderAdmin(w, r, "", "Session expired — reload /admin and try again.")
		return false
	}
	return true
}

// handleAdminUserCreate handles POST /admin/users (create) → AddUser. The hash
// is computed inside the argon2 semaphore (caller-side), never under the DB conn
// (see the argon2/DB-ordering invariant in store.go). The DB persists
// immediately, so there is no separate Save step.
func (s *authServer) handleAdminUserCreate(w http.ResponseWriter, r *http.Request) {
	if !s.adminMutationGuard(w, r) {
		return
	}
	username := r.PostFormValue("username")
	displayName := r.PostFormValue("display_name")
	password := r.PostFormValue("password")
	if err := validatePassword(strings.TrimSpace(password)); err != nil {
		s.renderAdmin(w, r, "", err.Error())
		return
	}

	var hash string
	var addErr error
	s.withHashSem(func() {
		var hErr error
		hash, hErr = HashPassword(password)
		if hErr != nil {
			addErr = hErr
			return
		}
		// Admin-page creates are non-admin users.
		addErr = s.users.AddUser(username, displayName, hash, false)
	})
	if addErr != nil {
		s.renderAdmin(w, r, "", adminErrMsg("create user", addErr))
		return
	}
	s.renderAdmin(w, r, "Created user "+normalizeUsername(username)+".", "")
}

// handleAdminUserSetPassword handles POST /admin/users/setpw → SetPassword. The
// hash is computed inside the argon2 semaphore (never under the DB conn). The DB
// persists immediately.
func (s *authServer) handleAdminUserSetPassword(w http.ResponseWriter, r *http.Request) {
	if !s.adminMutationGuard(w, r) {
		return
	}
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")
	if err := validatePassword(strings.TrimSpace(password)); err != nil {
		s.renderAdmin(w, r, "", err.Error())
		return
	}

	var hash string
	var setErr error
	s.withHashSem(func() {
		var hErr error
		hash, hErr = HashPassword(password)
		if hErr != nil {
			setErr = hErr
			return
		}
		setErr = s.users.SetPassword(username, hash)
	})
	if setErr != nil {
		s.renderAdmin(w, r, "", adminErrMsg("set password", setErr))
		return
	}
	s.renderAdmin(w, r, "Updated password for "+normalizeUsername(username)+".", "")
}

// handleAdminUserDelete handles POST /admin/users/delete → DeleteUser. No
// password hashing, so it is not semaphore-guarded. The DB persists immediately.
func (s *authServer) handleAdminUserDelete(w http.ResponseWriter, r *http.Request) {
	if !s.adminMutationGuard(w, r) {
		return
	}
	username := r.PostFormValue("username")

	if err := s.users.DeleteUser(username); err != nil {
		s.renderAdmin(w, r, "", adminErrMsg("delete user", err))
		return
	}
	s.renderAdmin(w, r, "Deleted user "+normalizeUsername(username)+".", "")
}

// adminErrMsg maps store errors to admin-facing messages. The admin pages are
// gated by the secret, so showing the specific reason (exists / not found /
// invalid) is fine here — unlike the deliberately-generic /login surface.
func adminErrMsg(action string, err error) string {
	switch {
	case errors.Is(err, ErrUserExists):
		return "Cannot " + action + ": user already exists."
	case errors.Is(err, ErrUserNotFound):
		return "Cannot " + action + ": user not found."
	default:
		return "Cannot " + action + ": " + err.Error()
	}
}

// ── shared render helper ──────────────────────────────────────────────────────

// renderHTML executes tmpl into a buffer first so a template error cannot leave a
// half-written body with a 200 already committed.
func renderHTML(w http.ResponseWriter, status int, tmpl *template.Template, data any) {
	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		http.Error(w, "internal error rendering page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprint(w, buf.String())
}
