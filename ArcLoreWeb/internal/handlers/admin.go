package handlers

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"

	"github.com/alexedwards/scs/v2"
	"github.com/go-chi/chi/v5"

	modelv1 "arcloreweb/gen/lore/model/v1"
	"arcloreweb/internal/auth"
	"arcloreweb/internal/lore"
	"arcloreweb/internal/mgmt"
	"arcloreweb/web/templates"
)

// AdminHandler handles the /admin/* management screens. All routes require
// RequireAuth + RequireAdmin middleware (mounted in main.go). The Bearer token
// forwarded to the mgmt API is the logged-in admin's identity token, read via
// identityToken(r) from the request context.
type AdminHandler struct {
	Mgmt     *mgmt.Client
	Lore     LoreClient
	Sessions *scs.SessionManager
}

// NewAdmin constructs an AdminHandler.
func NewAdmin(mgmtClient *mgmt.Client, loreClient LoreClient, sessions *scs.SessionManager) *AdminHandler {
	return &AdminHandler{Mgmt: mgmtClient, Lore: loreClient, Sessions: sessions}
}

// adminToken returns the logged-in admin's Bearer token from the request
// context (set by RequireAuth via IdentityFromContext). Empty under the
// dev/auth-disabled path, but admin routes are only reachable when auth is
// enabled, so that case cannot occur in practice.
func adminToken(r *http.Request) string {
	identity, ok := auth.IdentityFromContext(r.Context())
	if !ok {
		return ""
	}
	return identity.Token
}

// ── Users ────────────────────────────────────────────────────────────────────

// AdminUsers handles GET /admin/users — lists all users and renders the user
// management table with a create-user form. An optional ?err= query param
// surfaces a message from a prior redirect (PRG pattern).
func (h *AdminHandler) AdminUsers(w http.ResponseWriter, r *http.Request) {
	errMsg := r.URL.Query().Get("err")
	token := adminToken(r)

	users, err := h.Mgmt.ListUsers(r.Context(), token)
	if err != nil {
		http.Error(w, "admin: list users: "+err.Error(), http.StatusBadGateway)
		return
	}

	views := make([]templates.AdminUserView, 0, len(users))
	for _, u := range users {
		views = append(views, templates.AdminUserView{
			Username:    u.Username,
			DisplayName: u.DisplayName,
			IsAdmin:     u.IsAdmin,
			Created:     u.Created,
		})
	}

	// Best-effort: a Status failure leaves the toggle showing CLOSED rather than
	// failing the whole page; the POST handler is the real gate.
	st, _ := h.Mgmt.Status(r.Context())

	renderPage(w, r, "Users — ArcLore Admin", templates.AdminUsersPage(views, errMsg, st.RegistrationOpen))
}

// AdminSetRegistration handles POST /admin/registration — opens or closes public
// registration via the mgmt API then redirects back to GET /admin/users (PRG).
// On failure the message surfaces via ?err=.
func (h *AdminHandler) AdminSetRegistration(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/users?err=bad+form", http.StatusSeeOther)
		return
	}
	open := r.FormValue("open") == "1"

	if err := h.Mgmt.SetRegistration(r.Context(), adminToken(r), open); err != nil {
		http.Redirect(w, r, "/admin/users?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// AdminCreateUser handles POST /admin/users — creates a new user then redirects
// back to GET /admin/users (PRG). A 409 from the mgmt API (duplicate username)
// surfaces via ?err=.
func (h *AdminHandler) AdminCreateUser(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/users?err=bad+form", http.StatusSeeOther)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	displayName := r.FormValue("display_name")
	isAdmin := r.FormValue("is_admin") == "1"

	token := adminToken(r)
	_, err := h.Mgmt.CreateUser(r.Context(), token, username, password, displayName, isAdmin)
	if err != nil {
		apiErr := &mgmt.APIError{}
		if errors.As(err, &apiErr) {
			http.Redirect(w, r, "/admin/users?err="+url.QueryEscape(http.StatusText(apiErr.Status)+": "+apiErr.Message), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/admin/users?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// AdminDeleteUser handles POST /admin/users/{username}/delete — removes a user
// then redirects back to GET /admin/users. A 409 (last admin) surfaces via ?err=.
func (h *AdminHandler) AdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	token := adminToken(r)

	err := h.Mgmt.DeleteUser(r.Context(), token, username)
	if err != nil {
		apiErr := &mgmt.APIError{}
		if errors.As(err, &apiErr) {
			http.Redirect(w, r, "/admin/users?err="+url.QueryEscape(apiErr.Message), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/admin/users?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// AdminSetPassword handles POST /admin/users/{username}/password — updates a
// user's password then redirects back to GET /admin/users.
func (h *AdminHandler) AdminSetPassword(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/users?err=bad+form", http.StatusSeeOther)
		return
	}
	password := r.FormValue("password")
	token := adminToken(r)

	if err := h.Mgmt.SetPassword(r.Context(), token, username, password); err != nil {
		http.Redirect(w, r, "/admin/users?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// AdminSetAdmin handles POST /admin/users/{username}/admin — promotes or demotes
// a user's admin flag then redirects back to GET /admin/users. A 409 (last admin
// demotion) surfaces via ?err=.
func (h *AdminHandler) AdminSetAdmin(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/users?err=bad+form", http.StatusSeeOther)
		return
	}
	isAdmin := r.FormValue("is_admin") == "1"
	token := adminToken(r)

	err := h.Mgmt.SetAdmin(r.Context(), token, username, isAdmin)
	if err != nil {
		apiErr := &mgmt.APIError{}
		if errors.As(err, &apiErr) {
			http.Redirect(w, r, "/admin/users?err="+url.QueryEscape(apiErr.Message), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/admin/users?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// ── Repos ────────────────────────────────────────────────────────────────────

// AdminRepos handles GET /admin/repos — lists repositories via lore
// ListRepositories (the same call Home uses, now correct post-Phase-1 registry).
// An optional ?err= query param surfaces a message from a prior redirect.
func (h *AdminHandler) AdminRepos(w http.ResponseWriter, r *http.Request) {
	errMsg := r.URL.Query().Get("err")

	ctx, aerr := h.baseCtx(r)
	if aerr != nil {
		renderPageStatus(w, r, http.StatusForbidden, "Not authorized — ArcLore",
			templates.Forbidden("repositories", forbiddenDetail(aerr)))
		return
	}

	repos, err := h.Lore.ListRepositories(ctx)
	if err != nil {
		http.Error(w, "admin: list repos: "+err.Error(), http.StatusBadGateway)
		return
	}

	views := make([]templates.AdminRepoView, 0, len(repos))
	for _, repo := range repos {
		views = append(views, adminRepoView(repo))
	}

	renderPage(w, r, "Repos — ArcLore Admin", templates.AdminReposPage(views, errMsg))
}

// adminRepoView maps a lore Repository proto into the admin display model.
func adminRepoView(repo *modelv1.Repository) templates.AdminRepoView {
	return templates.AdminRepoView{
		// 32 lowercase-hex — exactly the value `lore clone .../<name>` resolves to
		// and what `lore repository create --id <ID>` needs to attach a folder.
		ID:                hex.EncodeToString(repo.GetId()),
		Name:              repo.GetName(),
		Description:       repo.GetDescription(),
		DefaultBranchName: repo.GetDefaultBranchName(),
		Creator:           repo.GetCreator(),
	}
}

// AdminCreateRepo handles POST /admin/repos — creates a repository via the lore
// RepositoryService (which in turn registers the resource + grants the creator
// owner via our RebacApi.CreateResource), then redirects back to GET /admin/repos
// (PRG). On error it re-renders the list page with the mapped message via ?err=.
//
// The lore call carries the admin's wildcard ("urc-*") authz token as Bearer —
// lore-server's RepositoryService authn accepts it AND forwards it to our
// RebacApi.CreateResource, which verifies it (sub = admin) and grants the admin
// the owner permission. The creator is stamped explicitly from the admin's sub
// so creator/lock attribution shows the real owner.
func (h *AdminHandler) AdminCreateRepo(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/repos?err=bad+form", http.StatusSeeOther)
		return
	}
	name := r.FormValue("name")
	description := r.FormValue("description")

	identity, _ := auth.IdentityFromContext(r.Context())

	// Exchange the admin's identity token for the wildcard authz Bearer that
	// lore-server's RepositoryService authn accepts and forwards to RebacApi.
	token, err := h.Lore.ResourceAuthzToken(r.Context(), identityToken(r), lore.WildcardResource)
	if err != nil {
		http.Redirect(w, r, "/admin/repos?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	_, err = h.Lore.RepositoryCreate(r.Context(), token, lore.RepositoryCreateInput{
		Name:        name,
		Description: description,
		Creator:     identity.Sub,
	})
	if err != nil {
		http.Redirect(w, r, "/admin/repos?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/repos", http.StatusSeeOther)
}

// AdminDeleteRepo handles POST /admin/repos/{id}/delete — deletes a repository
// via lore RepositoryService then redirects back to GET /admin/repos (PRG).
// NOT_FOUND (already deleted) is treated as success — idempotent UX.
func (h *AdminHandler) AdminDeleteRepo(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	repoID, err := lore.ParseID(id)
	if err != nil {
		http.Redirect(w, r, "/admin/repos?err="+url.QueryEscape("bad repository id"), http.StatusSeeOther)
		return
	}
	token, err := h.Lore.ResourceAuthzToken(r.Context(), identityToken(r), lore.WildcardResource)
	if err != nil {
		http.Redirect(w, r, "/admin/repos?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	if err := h.Lore.RepositoryDelete(r.Context(), token, repoID); err != nil && !errors.Is(err, lore.ErrRepoNotFound) {
		http.Redirect(w, r, "/admin/repos?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	// NOT_FOUND (already deleted) is treated as success — idempotent UX.
	http.Redirect(w, r, "/admin/repos", http.StatusSeeOther)
}

// AdminImportRepo handles POST /admin/repos/import — registers an EXISTING
// repository (one that lives on lore-server but has no resource row here, e.g.
// created before this control plane) as a resource via the mgmt API, granting
// the calling admin owner. After this the repo appears in the list (its name is
// fetched server-side from lore-server). PRG back to /admin/repos.
func (h *AdminHandler) AdminImportRepo(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/repos?err=bad+form", http.StatusSeeOther)
		return
	}
	resourceID := r.FormValue("resource_id")
	name := r.FormValue("name")

	if _, err := h.Mgmt.ImportResource(r.Context(), adminToken(r), resourceID, name); err != nil {
		http.Redirect(w, r, "/admin/repos?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/repos", http.StatusSeeOther)
}

// AdminRemoveResource handles POST /admin/resources/remove — removes a resource
// registration via the mgmt API then redirects back to GET /admin/grants (PRG).
func (h *AdminHandler) AdminRemoveResource(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/grants?err=bad+form", http.StatusSeeOther)
		return
	}
	resourceID := r.FormValue("resource_id")
	if err := h.Mgmt.RemoveResource(r.Context(), adminToken(r), resourceID); err != nil {
		http.Redirect(w, r, "/admin/grants?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/grants", http.StatusSeeOther)
}

// ── Grants ───────────────────────────────────────────────────────────────────

// AdminGrants handles GET /admin/grants — lists all registered resources via
// the mgmt API and, when ?user= is present, overlays that user's grants on each
// resource row. An optional ?err= query param surfaces error messages from PRG
// redirects.
func (h *AdminHandler) AdminGrants(w http.ResponseWriter, r *http.Request) {
	errMsg := r.URL.Query().Get("err")
	selectedUser := r.URL.Query().Get("user")
	token := adminToken(r)

	rawResources, err := h.Mgmt.ListResources(r.Context(), token)
	if err != nil {
		http.Error(w, "admin: list resources: "+err.Error(), http.StatusBadGateway)
		return
	}

	// Best-effort member list for the left pane; a failure here just renders an
	// empty list rather than failing the whole page.
	users, _ := h.Mgmt.ListUsers(r.Context(), token)
	members := make([]templates.AdminGrantsMember, 0, len(users))
	for _, u := range users {
		members = append(members, templates.AdminGrantsMember{
			Username:    u.Username,
			DisplayName: u.DisplayName,
			IsAdmin:     u.IsAdmin,
			Selected:    u.Username == selectedUser,
		})
	}

	// Fetch grants for the selected user so we can annotate each resource row.
	var userGrants map[string][]string
	if selectedUser != "" {
		userGrants, err = h.Mgmt.Grants(r.Context(), token, selectedUser)
		if err != nil {
			// Non-fatal — render without the grant overlay and surface the error.
			errMsg = "grants lookup: " + err.Error()
		}
	}

	views := make([]templates.AdminGrantsResource, 0, len(rawResources))
	for _, res := range rawResources {
		perms := []string(nil)
		if userGrants != nil {
			perms = userGrants[res.ResourceID]
		}
		views = append(views, templates.AdminGrantsResource{
			ResourceID:  res.ResourceID,
			Name:        res.Name,
			Permissions: perms,
		})
	}

	renderPage(w, r, "Grants — ArcLore Admin", templates.AdminGrantsPage(members, views, selectedUser, errMsg))
}

// AdminAddGrant handles POST /admin/grants — adds a grant then redirects back
// to GET /admin/grants (PRG), preserving the user filter if one was sent.
func (h *AdminHandler) AdminAddGrant(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/grants?err=bad+form", http.StatusSeeOther)
		return
	}
	username := r.FormValue("username")
	resourceID := r.FormValue("resource_id")
	permission := r.FormValue("permission")
	token := adminToken(r)

	if err := h.Mgmt.AddGrant(r.Context(), token, username, resourceID, permission); err != nil {
		http.Redirect(w, r, "/admin/grants?user="+url.QueryEscape(username)+"&err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/grants?user="+url.QueryEscape(username), http.StatusSeeOther)
}

// AdminRemoveGrant handles POST /admin/grants/delete — revokes a grant then
// redirects back to GET /admin/grants (PRG), preserving the user filter.
func (h *AdminHandler) AdminRemoveGrant(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/grants?err=bad+form", http.StatusSeeOther)
		return
	}
	username := r.FormValue("username")
	resourceID := r.FormValue("resource_id")
	permission := r.FormValue("permission")
	token := adminToken(r)

	if err := h.Mgmt.RemoveGrant(r.Context(), token, username, resourceID, permission); err != nil {
		http.Redirect(w, r, "/admin/grants?user="+url.QueryEscape(username)+"&err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/grants?user="+url.QueryEscape(username), http.StatusSeeOther)
}

// baseCtx returns a repo-less lore call context for AdminHandler. It mirrors
// Handler.baseCtx: exchanges the wildcard authz token and stamps it onto a
// zero-repo lore context. identityToken(r) is visible because AdminHandler is
// in the same package (handlers).
func (h *AdminHandler) baseCtx(r *http.Request) (context.Context, error) {
	tok, err := h.Lore.ResourceAuthzToken(r.Context(), identityToken(r), lore.WildcardResource)
	if err != nil {
		return nil, err
	}
	return lore.WithLoreCall(r.Context(), tok, [16]byte{}), nil
}
