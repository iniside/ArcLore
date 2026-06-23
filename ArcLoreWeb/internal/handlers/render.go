package handlers

import (
	"net/http"
	"strings"

	"github.com/a-h/templ"

	"arcloreweb/internal/auth"
	"arcloreweb/internal/render"
	"arcloreweb/web/templates"
)

// renderPage wraps a body component in the base Layout and writes it with a 200.
// isAdmin is read from the request context (Identity) and forwarded to Layout so
// the admin nav links appear only for admin sessions.
func renderPage(w http.ResponseWriter, r *http.Request, title string, body templ.Component) {
	renderPageStatus(w, r, http.StatusOK, title, body)
}

// renderPageStatus wraps a body component in the base Layout and writes it with
// the given status code (e.g. 404 for NotFound).
//
// When the request carries an "HX-Request: true" header (an htmx partial
// navigation swap), only the body component is rendered — the full Layout
// shell (nav, <head>, etc.) is omitted so htmx can splice just the
// #main-content region without re-initialising the whole page. Every nav link
// in layout.templ carries hx-target="#main-content" + hx-push-url="true" so
// the browser URL stays in sync. Plain href fallback works for no-JS clients.
func renderPageStatus(w http.ResponseWriter, r *http.Request, statusCode int, title string, body templ.Component) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)

	if r.Header.Get("HX-Request") == "true" {
		// Partial swap: send only the body fragment.
		if err := body.Render(r.Context(), w); err != nil {
			return
		}
		return
	}

	identity, _ := auth.IdentityFromContext(r.Context())
	// The appbar highlights Home / Explore / Admin from the request path.
	section := "home"
	switch {
	case strings.HasPrefix(r.URL.Path, "/admin"):
		section = "admin"
	case strings.HasPrefix(r.URL.Path, "/explore"):
		section = "explore"
	}
	page := templates.Layout(title, body, identity.Sub, identity.IsAdmin, section)
	if err := page.Render(r.Context(), w); err != nil {
		// Headers are already committed; nothing useful to surface to the client.
		return
	}
}

// ServeChromaCSS serves the shared chroma class-mode stylesheet (style "github")
// used by markdown code fences and the Step 5 file view. Wire it at
// /static/chroma.css before the static embed catch-all.
func (h *Handler) ServeChromaCSS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	if err := render.GenerateCSS(w); err != nil {
		http.Error(w, "failed to generate stylesheet", http.StatusInternalServerError)
	}
}
