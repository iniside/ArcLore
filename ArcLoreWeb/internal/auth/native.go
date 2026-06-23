package auth

import (
	"errors"
	"net/http"

	"github.com/a-h/templ"
	"github.com/alexedwards/scs/v2"

	"arcloreweb/internal/mgmt"
	"arcloreweb/web/templates"
)

// Native implements ArcLoreWeb's native login + first-run setup against
// arc-lore-auth's HTTP /api surface. It replaces the old UCS browser-redirect
// flow for the web UI — the UCS/gRPC flow stays in arc-lore-auth for the UE
// editor/CLI clients, which ArcLoreWeb no longer drives.
//
// On a successful login or setup it stores the identity (user_sub, user_name,
// identity_token, token_expiry, is_admin) in the scs session; identity_token is
// the Bearer forwarded onward to both lore (via the exchange) and the mgmt API.
type Native struct {
	Mgmt     *mgmt.Client
	Sessions *scs.SessionManager
}

// ── login ────────────────────────────────────────────────────────────────────

// LoginForm (GET /auth/login) renders the username/password form. When the
// instance has no users yet it steers to /setup so the first admin is created
// instead. A Status error is treated as "assume has users" (show the form) — a
// down mgmt API must not 500 the login page.
func (n *Native) LoginForm(w http.ResponseWriter, r *http.Request) {
	status, err := n.Mgmt.Status(r.Context())
	if err == nil && !status.HasUsers {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	n.renderPage(w, r, "Sign in — ArcLore", templates.LoginPage("", status.RegistrationOpen))
}

// LoginSubmit (POST /auth/login) authenticates against mgmt.Login and, on
// success, stores the identity in the session, renews the session token, and
// redirects home. A 401 re-renders the form with a generic error; any other
// failure renders a generic "service unavailable" error.
func (n *Native) LoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		n.renderPage(w, r, "Sign in — ArcLore", templates.LoginPage("Invalid form submission.", n.registrationOpen(r)))
		return
	}
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")

	resp, err := n.Mgmt.Login(r.Context(), username, password)
	if err != nil {
		var apiErr *mgmt.APIError
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusUnauthorized {
			n.renderPage(w, r, "Sign in — ArcLore", templates.LoginPage("Invalid username or password.", n.registrationOpen(r)))
			return
		}
		n.renderPage(w, r, "Sign in — ArcLore", templates.LoginPage("Sign-in is unavailable. Try again shortly.", n.registrationOpen(r)))
		return
	}

	if !n.storeIdentity(w, r, resp) {
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ── register (self-service sign-up) ────────────────────────────────────────────

// RegisterForm (GET /auth/register) renders the public sign-up form. It FAILS
// CLOSED: when registration is closed OR the Status call errors it redirects to
// the login page rather than rendering the form. The server endpoint re-checks
// every POST, so this gate is defense-in-depth only.
func (n *Native) RegisterForm(w http.ResponseWriter, r *http.Request) {
	st, err := n.Mgmt.Status(r.Context())
	if err != nil || !st.RegistrationOpen {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	n.renderPage(w, r, "Register — ArcLore", templates.RegisterPage(""))
}

// RegisterSubmit (POST /auth/register) creates a non-admin account via
// mgmt.Register and auto-logs in by storing the returned token. A 403 (closed),
// 409 (duplicate), or 400 (validation) re-renders the form with an inline
// message; any other failure renders a generic error.
func (n *Native) RegisterSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		n.renderPage(w, r, "Register — ArcLore", templates.RegisterPage("Invalid form submission."))
		return
	}
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")

	resp, err := n.Mgmt.Register(r.Context(), username, password)
	if err != nil {
		var apiErr *mgmt.APIError
		if errors.As(err, &apiErr) {
			msg := "Registration failed. Try again shortly."
			switch apiErr.Status {
			case http.StatusForbidden:
				msg = "Registration is closed."
			case http.StatusConflict:
				msg = "That username is already taken."
			case http.StatusBadRequest:
				msg = apiErr.Message
			}
			n.renderPage(w, r, "Register — ArcLore", templates.RegisterPage(msg))
			return
		}
		n.renderPage(w, r, "Register — ArcLore", templates.RegisterPage("Registration is unavailable. Try again shortly."))
		return
	}

	if !n.storeIdentity(w, r, resp) {
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ── account (self-service) ──────────────────────────────────────────────────────

// AccountForm (GET /account) renders the account screen. It runs behind
// RequireAuth, so an Identity is always present in the context.
func (n *Native) AccountForm(w http.ResponseWriter, r *http.Request) {
	n.renderPage(w, r, "Account — ArcLore", templates.AccountPage("", ""))
}

// ChangePassword (POST /account/password) changes the logged-in user's own
// password via mgmt.ChangeMyPassword, forwarding the session's identity token as
// the Bearer (which requireAPIAuth accepts). A 401 (wrong current) or 400
// (validation) re-renders with an inline error; success re-renders with a
// confirmation note.
func (n *Native) ChangePassword(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		n.renderPage(w, r, "Account — ArcLore", templates.AccountPage("Invalid form submission.", ""))
		return
	}
	current := r.PostFormValue("current")
	newPassword := r.PostFormValue("new")

	identity, _ := IdentityFromContext(r.Context())
	if err := n.Mgmt.ChangeMyPassword(r.Context(), identity.Token, current, newPassword); err != nil {
		var apiErr *mgmt.APIError
		if errors.As(err, &apiErr) {
			msg := "Could not change your password. Try again shortly."
			switch apiErr.Status {
			case http.StatusUnauthorized:
				msg = "Your current password is incorrect."
			case http.StatusBadRequest:
				msg = apiErr.Message
			}
			n.renderPage(w, r, "Account — ArcLore", templates.AccountPage(msg, ""))
			return
		}
		n.renderPage(w, r, "Account — ArcLore", templates.AccountPage("Password change is unavailable. Try again shortly.", ""))
		return
	}
	n.renderPage(w, r, "Account — ArcLore", templates.AccountPage("", "Password changed."))
}

// ── setup (first-run) ─────────────────────────────────────────────────────────

// SetupForm (GET /setup) renders the create-first-admin form. When users already
// exist it redirects to /auth/login. A Status error is surfaced as a generic
// error on the setup page rather than a 500.
func (n *Native) SetupForm(w http.ResponseWriter, r *http.Request) {
	status, err := n.Mgmt.Status(r.Context())
	if err != nil {
		n.renderPage(w, r, "Set up ArcLore", templates.SetupPage("Could not reach the auth service. Is it running?"))
		return
	}
	if status.HasUsers {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	n.renderPage(w, r, "Set up ArcLore", templates.SetupPage(""))
}

// SetupSubmit (POST /setup) creates the first admin via mgmt.Setup and auto-logs
// in by storing the returned token. A 409 (setup already ran) redirects to
// login; other failures re-render the setup form with a generic error.
func (n *Native) SetupSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		n.renderPage(w, r, "Set up ArcLore", templates.SetupPage("Invalid form submission."))
		return
	}
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")
	displayName := r.PostFormValue("display_name")

	resp, err := n.Mgmt.Setup(r.Context(), username, password, displayName)
	if err != nil {
		var apiErr *mgmt.APIError
		if errors.As(err, &apiErr) {
			if apiErr.Status == http.StatusConflict {
				http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
				return
			}
			n.renderPage(w, r, "Set up ArcLore", templates.SetupPage(apiErr.Message))
			return
		}
		n.renderPage(w, r, "Set up ArcLore", templates.SetupPage("Could not reach the auth service. Is it running?"))
		return
	}

	if !n.storeIdentity(w, r, resp) {
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ── shared ────────────────────────────────────────────────────────────────────

// Logout (GET /auth/logout) destroys the session and redirects to the login
// page.
func (n *Native) Logout(w http.ResponseWriter, r *http.Request) {
	if err := n.Sessions.Destroy(r.Context()); err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
}

// registrationOpen fetches the current registration state for re-rendering the
// login page's "Create one" link. A Status error is treated as closed (false) —
// a down mgmt API must not break the login page.
func (n *Native) registrationOpen(r *http.Request) bool {
	st, err := n.Mgmt.Status(r.Context())
	if err != nil {
		return false
	}
	return st.RegistrationOpen
}

// storeIdentity renews the session token and writes the identity from an
// AuthResp into the session. Returns false (after writing a 500) when the token
// renewal fails.
func (n *Native) storeIdentity(w http.ResponseWriter, r *http.Request, resp mgmt.AuthResp) bool {
	if err := n.Sessions.RenewToken(r.Context()); err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return false
	}
	n.Sessions.Put(r.Context(), sessionKeyUserSub, resp.UserID)
	n.Sessions.Put(r.Context(), sessionKeyUserName, resp.Name)
	n.Sessions.Put(r.Context(), sessionKeyIdentityToken, resp.Token)
	n.Sessions.Put(r.Context(), sessionKeyTokenExpiry, resp.ExpiresAt)
	n.Sessions.Put(r.Context(), sessionKeyIsAdmin, resp.IsAdmin)
	return true
}

// renderPage wraps a body in the base Layout and writes a 200. When the request
// is an htmx partial swap, only the body fragment is sent (mirrors
// handlers.renderPage — duplicated here to avoid an auth→handlers import).
func (n *Native) renderPage(w http.ResponseWriter, r *http.Request, title string, body templ.Component) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Header.Get("HX-Request") == "true" {
		_ = body.Render(r.Context(), w)
		return
	}
	// Empty username + section → no logout affordance and no active pill on the
	// login/setup pages (they render through this same Layout).
	_ = templates.Layout(title, body, "", false, "").Render(r.Context(), w)
}
