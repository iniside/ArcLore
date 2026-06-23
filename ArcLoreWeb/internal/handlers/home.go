package handlers

import (
	"net/http"
	"time"

	modelv1 "arcloreweb/gen/lore/model/v1"
	"arcloreweb/internal/auth"
	"arcloreweb/web/templates"
)

// Home renders the personal dashboard (GET /): user header, contribution
// heatmap (real month labels, zero data — there's no per-day source yet), an
// activity-feed empty state, and a repositories sidebar from ListRepositories.
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
		Months:    last12Months(),
		HeatCells: make([]int, 53*7), // empty heatmap (all level 0) until per-day data exists
		HeatTotal: 0,
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

// last12Months returns 12 abbreviated month labels, oldest first.
func last12Months() []string {
	now := time.Now()
	out := make([]string, 0, 12)
	for i := 11; i >= 0; i-- {
		out = append(out, now.AddDate(0, -i, 0).Month().String()[:3])
	}
	return out
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
