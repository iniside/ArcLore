package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"arcloreweb/web/templates"
)

// lockedAtRelative formats a lock timestamp as the same coarse human-relative
// string used on the commits page (e.g. "3 hours ago"); a nil/zero timestamp
// renders empty.
func lockedAtRelative(ts *timestamppb.Timestamp) string {
	if ts == nil {
		return ""
	}
	sec := ts.GetSeconds()
	if sec <= 0 {
		return ""
	}
	return relativeTime(uint64(sec))
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
		path := ""
		if res := lock.GetResource(); res != nil {
			path = res.GetDescription()
		}
		rows = append(rows, templates.LockRowView{
			Path:     path,
			Owner:    lock.GetOwner(),
			LockedAt: lockedAtRelative(lock.GetLockedAt()),
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
