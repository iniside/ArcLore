package handlers

import (
	"net/http"

	modelv1 "arcloreweb/gen/lore/model/v1"
	"arcloreweb/internal/auth"
	"arcloreweb/web/templates"
)

// Home renders the personal dashboard (GET /): user header, a repositories
// sidebar from ListRepositories, and coming-soon placeholders for the
// contribution heatmap and activity feed.
//
// Heatmap and activity feed are deferred: populating them requires a
// lore-server activity RPC that exposes per-revision author and timestamp
// (and ideally a cross-repo activity stream). modelv1.RevisionItem carries
// neither field, and ListRevisions is per-branch only, so there is no
// client-side path to reconstruct this data.
func (h *Handler) Home(w http.ResponseWriter, r *http.Request) {
	ctx, aerr := h.baseCtx(r)
	if aerr != nil {
		renderPageStatus(w, r, http.StatusForbidden, "Not authorized — ArcLore",
			templates.Forbidden("repositories", forbiddenDetail(aerr)))
		return
	}

	repos, err := h.Lore.ListRepositories(ctx)
	if err != nil {
		http.Error(w, "failed to list repositories: "+err.Error(), http.StatusBadGateway)
		return
	}

	sidebar := make([]templates.HomeRepoView, 0, len(repos))
	for _, repo := range repos {
		sidebar = append(sidebar, templates.HomeRepoView{Name: repo.GetName()})
	}

	identity, _ := auth.IdentityFromContext(r.Context())
	view := templates.HomeView{
		Username:  identity.Sub,
		RepoCount: len(repos),
		Repos:     sidebar,
	}
	renderPage(w, r, "ArcLore", templates.HomePage(view))
}

// Explore renders the repository-discovery list (GET /explore): the Forge repo
// list-table over every repository the user can see.
func (h *Handler) Explore(w http.ResponseWriter, r *http.Request) {
	ctx, aerr := h.baseCtx(r)
	if aerr != nil {
		renderPageStatus(w, r, http.StatusForbidden, "Not authorized — ArcLore",
			templates.Forbidden("repositories", forbiddenDetail(aerr)))
		return
	}

	repos, err := h.Lore.ListRepositories(ctx)
	if err != nil {
		http.Error(w, "failed to list repositories: "+err.Error(), http.StatusBadGateway)
		return
	}

	views := make([]templates.RepoListView, 0, len(repos))
	for _, repo := range repos {
		views = append(views, repoListView(repo))
	}
	renderPage(w, r, "Explore — ArcLore", templates.RepoListPage(views))
}

// repoListView maps a lore Repository into the card view model.
func repoListView(repo *modelv1.Repository) templates.RepoListView {
	return templates.RepoListView{
		Name:              repo.GetName(),
		Description:       repo.GetDescription(),
		DefaultBranchName: repo.GetDefaultBranchName(),
		Creator:           repo.GetCreator(),
	}
}
