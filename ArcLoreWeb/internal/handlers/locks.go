package handlers

import (
	"encoding/hex"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	gen "arcloreweb/gen"
	"arcloreweb/internal/lore"
	"arcloreweb/web/templates"
)

// lockedAtRelative formats a lock timestamp as the same coarse human-relative
// string used on the commits page (e.g. "3 hours ago"); a zero/epoch time
// renders empty. Note: AsTime() on a nil *timestamppb.Timestamp returns the
// Unix epoch (not a zero time.Time), so both IsZero and Unix()<=0 are checked.
func lockedAtRelative(t time.Time) string {
	if t.IsZero() || t.Unix() <= 0 {
		return ""
	}
	return relativeTime(uint64(t.Unix()))
}

// Locks handles GET /{owner}/{repo}/locks/branch/{branch}: the read-only list of
// locks held on a branch. Resolution mirrors Commits (repo name → repo-scoped
// ctx → branch name → branchID); the owner url segment is cosmetic and ignored.
func (h *Handler) Locks(w http.ResponseWriter, r *http.Request) {
	repoName := chi.URLParam(r, "repo")
	branchName := chi.URLParam(r, "branch")

	// --- resolve repo ---
	baseCtx, berr := h.baseCtx(r)
	if berr != nil {
		renderPageStatus(w, r, http.StatusForbidden, "Not authorized — ArcLore",
			templates.Forbidden(repoName, forbiddenDetail(berr)))
		return
	}
	repo, err := h.Lore.GetRepositoryByName(baseCtx, repoName)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			renderPageStatus(w, r, http.StatusNotFound, "Not found — ArcLore", templates.NotFound(repoName))
			return
		}
		http.Error(w, "failed to load repository: "+err.Error(), http.StatusBadGateway)
		return
	}
	repoID := toID(repo.GetId())
	ctx, aerr := h.repoCtx(r, repoID)
	if aerr != nil {
		renderPageStatus(w, r, http.StatusForbidden, "Not authorized — ArcLore",
			templates.Forbidden(repoName, forbiddenDetail(aerr)))
		return
	}

	// --- resolve branch ---
	branch, err := h.Lore.GetBranchByName(ctx, branchName)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			renderPageStatus(w, r, http.StatusNotFound, "Branch not found — ArcLore",
				templates.NotFound("branch: "+branchName))
			return
		}
		http.Error(w, "failed to load branch: "+err.Error(), http.StatusBadGateway)
		return
	}
	branchID := toID(branch.GetId())

	locks, err := h.Lore.QueryLocks(ctx, branchID)
	if err != nil {
		http.Error(w, "failed to query locks: "+err.Error(), http.StatusBadGateway)
		return
	}

	rows := make([]templates.LockRowView, 0, len(locks))
	for _, lock := range locks {
		res := lock.GetResource()
		rows = append(rows, templates.LockRowView{
			Path:        res.GetDescription(),
			Owner:       lock.GetOwner(),
			LockedAt:    lockedAtRelative(lock.GetLockedAt().AsTime()),
			Branch:      hex.EncodeToString(res.GetBranch()),
			Hash:        hex.EncodeToString(res.GetHash()),
			Description: res.GetDescription(),
		})
	}

	view := templates.LocksView{
		Owner:      ownerSegment,
		RepoName:   repoName,
		BranchName: branchName,
		Rows:       rows,
	}
	renderPage(w, r, "Locks — "+repoName, templates.LocksPage(view))
}

// ReleaseLock handles POST /{owner}/{repo}/locks/branch/{branch}/release: it
// releases a single lock identified by the row's exact Resource (branch+hash
// hex + description), then redirects (PRG) back to the locks page. Behind
// RequireAuth — lore-server is the release authority; own-lock release must
// work for any authenticated user (NOT admin-only).
//
// Resolution mirrors Locks (repo name → repo-scoped ctx → repoID). All errors
// surface to the user via a ?err= query on the PRG redirect.
func (h *Handler) ReleaseLock(w http.ResponseWriter, r *http.Request) {
	repoName := chi.URLParam(r, "repo")
	branchName := chi.URLParam(r, "branch")
	locksURL := "/" + chi.URLParam(r, "owner") + "/" + repoName + "/locks/branch/" + branchName

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, locksURL+"?err=bad+form", http.StatusSeeOther)
		return
	}

	branchHex := r.FormValue("branch")
	hashHex := r.FormValue("hash")
	description := r.FormValue("description")

	branchBytes, err := hex.DecodeString(branchHex)
	if err != nil {
		http.Redirect(w, r, locksURL+"?err="+url.QueryEscape("invalid lock id"), http.StatusSeeOther)
		return
	}
	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		http.Redirect(w, r, locksURL+"?err="+url.QueryEscape("invalid lock id"), http.StatusSeeOther)
		return
	}

	// Resolve repoID exactly as the Locks page does: repo name → repository id.
	baseCtx, berr := h.baseCtx(r)
	if berr != nil {
		http.Redirect(w, r, locksURL+"?err="+url.QueryEscape(forbiddenDetail(berr)), http.StatusSeeOther)
		return
	}
	repo, err := h.Lore.GetRepositoryByName(baseCtx, repoName)
	if err != nil {
		http.Redirect(w, r, locksURL+"?err="+url.QueryEscape("failed to load repository"), http.StatusSeeOther)
		return
	}
	repoID := toID(repo.GetId())

	// Exchange the caller's identity token for the wildcard authz Bearer that
	// lore-server's LockService authn accepts (same pattern as repo-create).
	token, err := h.Lore.ResourceAuthzToken(r.Context(), identityToken(r), lore.WildcardResource)
	if err != nil {
		http.Redirect(w, r, locksURL+"?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	resource := &gen.Resource{Branch: branchBytes, Hash: hashBytes, Description: description}
	if err := h.Lore.Unlock(r.Context(), token, repoID, []*gen.Resource{resource}); err != nil {
		http.Redirect(w, r, locksURL+"?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, locksURL, http.StatusSeeOther)
}
