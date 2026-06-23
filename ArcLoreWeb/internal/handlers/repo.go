package handlers

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	gen "arcloreweb/gen"
	thin_clientv1 "arcloreweb/gen/lore/thin_client/v1"
	"arcloreweb/internal/lore"
	"arcloreweb/internal/render"
	"arcloreweb/web/templates"
)

// ownerSegment is the cosmetic url owner placeholder. Repo names are globally
// unique in Lore, so the owner segment is ignored on resolution and emitted as
// a constant when building links.
const ownerSegment = "-"

// RepoHome renders the repository home page (GET /{owner}/{repo}): the file
// tree at the default branch tip, a README panel, and a lock overlay. The owner
// url segment is ignored — repo names are globally unique.
func (h *Handler) RepoHome(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "repo")

	baseCtx, berr := h.baseCtx(r)
	if berr != nil {
		renderPageStatus(w, r, http.StatusForbidden, "Not authorized — ArcLore",
			templates.Forbidden(name, forbiddenDetail(berr)))
		return
	}

	repo, err := h.Lore.GetRepositoryByName(baseCtx, name)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			renderPageStatus(w, r, http.StatusNotFound, "Not found — ArcLore", templates.NotFound(name))
			return
		}
		http.Error(w, "failed to load repository: "+err.Error(), http.StatusBadGateway)
		return
	}

	repoID := toID(repo.GetId())
	ctx, aerr := h.repoCtx(r, repoID)
	if aerr != nil {
		renderPageStatus(w, r, http.StatusForbidden, "Not authorized — ArcLore",
			templates.Forbidden(name, forbiddenDetail(aerr)))
		return
	}

	// Resolve the branch to view. Default is the repository's default branch; an
	// optional ?branch= query param overrides it. An unknown branch name (gRPC
	// NotFound) is NOT a 404 here — it's a stray query param, so fall back to the
	// default branch silently. Any other error is a real failure.
	branchID := toID(repo.GetDefaultBranchId())
	currentBranchName := repo.GetDefaultBranchName()
	if sel := r.URL.Query().Get("branch"); sel != "" {
		b, berr := h.Lore.GetBranchByName(ctx, sel)
		switch {
		case berr == nil:
			branchID = toID(b.GetId())
			currentBranchName = b.GetName()
		case status.Code(berr) == codes.NotFound:
			// keep the default branch
		default:
			http.Error(w, "failed to resolve branch: "+berr.Error(), http.StatusBadGateway)
			return
		}
	}

	// Best-effort branch list for the switcher dropdown. A failed list just shows
	// the current branch as the sole option rather than erroring the page.
	branches := h.branchOptions(ctx, repo.GetName(), currentBranchName)

	view := templates.RepoView{
		Owner:             ownerSegment,
		Name:              repo.GetName(),
		Description:       repo.GetDescription(),
		DefaultBranchName: repo.GetDefaultBranchName(),
		CurrentBranch:     currentBranchName,
		Branches:          branches,
		ID:                lore.IDToHex(repoID),
		CloneHost:         h.LoreHost,
	}

	_, nodes, terr := h.Lore.RevisionTree(ctx, branchID, 0, "", 1)
	if terr != nil {
		// A fresh/empty default branch returns either a header-only empty stream
		// (no nodes) or a gRPC NotFound — both render as "empty repository", never
		// a crash. Any other error is a real failure.
		if status.Code(terr) == codes.NotFound {
			view.Empty = true
			renderPage(w, r, view.Name+" — ArcLore", templates.RepoPage(view))
			return
		}
		http.Error(w, "failed to read tree: "+terr.Error(), http.StatusBadGateway)
		return
	}
	if len(nodes) == 0 {
		view.Empty = true
		renderPage(w, r, view.Name+" — ArcLore", templates.RepoPage(view))
		return
	}

	// Lock overlay: description on each lock is the repo-relative file path.
	lockByPath := h.lockOverlay(ctx, branchID)

	view.Rows = buildRows(nodes, lockByPath)
	view.Readme = h.renderReadme(ctx, repoID, nodes)

	renderPage(w, r, view.Name+" — ArcLore", templates.RepoPage(view))
}

// lockOverlay queries the branch locks and keys them by file path
// (resource.description). A failed lock query is non-fatal — the page renders
// without lock badges rather than erroring out.
func (h *Handler) lockOverlay(ctx context.Context, branchID [16]byte) map[string]*gen.Lock {
	locks, err := h.Lore.QueryLocks(ctx, branchID)
	if err != nil {
		log.Printf("repo: QueryLocks: %v", err)
		return nil
	}
	byPath := make(map[string]*gen.Lock, len(locks))
	for _, lock := range locks {
		resource := lock.GetResource()
		if resource == nil {
			continue
		}
		byPath[resource.GetDescription()] = lock
	}
	return byPath
}

// branchOptions builds the branch-switcher dropdown entries. It is best-effort:
// a failed ListBranches yields the current branch as the sole option so the
// switcher still labels correctly rather than erroring the page.
func (h *Handler) branchOptions(ctx context.Context, repoName, currentBranchName string) []templates.BranchOption {
	branches, err := h.Lore.ListBranches(ctx)
	if err != nil {
		log.Printf("repo: ListBranches: %v", err)
	}
	if err != nil || len(branches) == 0 {
		return []templates.BranchOption{{
			Name:   currentBranchName,
			URL:    templ.SafeURL("/-/" + repoName + "?branch=" + url.QueryEscape(currentBranchName)),
			Active: true,
		}}
	}
	options := make([]templates.BranchOption, 0, len(branches))
	for _, b := range branches {
		name := b.GetName()
		options = append(options, templates.BranchOption{
			Name:   name,
			URL:    templ.SafeURL("/-/" + repoName + "?branch=" + url.QueryEscape(name)),
			Active: name == currentBranchName,
		})
	}
	return options
}

// buildRows maps the top-level tree nodes into file-table rows, sorting
// directories before files and applying the lock overlay.
func buildRows(nodes []*thin_clientv1.TreeNode, lockByPath map[string]*gen.Lock) []templates.FileRowView {
	rows := make([]templates.FileRowView, 0, len(nodes))
	for _, node := range nodes {
		path := node.GetPath()
		row := templates.FileRowView{
			Name:  leafName(path),
			Path:  path,
			IsDir: node.GetNodeType() == thin_clientv1.NodeType_DIRECTORY,
		}
		if lock, ok := lockByPath[path]; ok {
			row.Locked = true
			row.LockOwner = lock.GetOwner()
		}
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].IsDir != rows[j].IsDir {
			return rows[i].IsDir // directories first
		}
		return rows[i].Name < rows[j].Name
	})
	return rows
}

// renderReadme fetches and renders a top-level README.md (case-insensitive) as a
// markdown component. Any failure (missing, fetch error, oversized, render
// error) yields a nil component — the readme panel is simply omitted.
func (h *Handler) renderReadme(ctx context.Context, repoID [16]byte, nodes []*thin_clientv1.TreeNode) templ.Component {
	var readmeNode *thin_clientv1.TreeNode
	for _, node := range nodes {
		if node.GetNodeType() != thin_clientv1.NodeType_FILE {
			continue
		}
		if strings.EqualFold(leafName(node.GetPath()), "README.md") {
			readmeNode = node
			break
		}
	}
	if readmeNode == nil {
		return nil
	}

	body, _, size, err := h.Lore.FetchContent(ctx, repoID, readmeNode.GetAddress())
	if err != nil {
		return nil
	}
	defer func() { _ = body.Close() }()

	if size > lore.MaxHighlightBytes {
		return nil
	}

	src, err := io.ReadAll(io.LimitReader(body, lore.MaxHighlightBytes))
	if err != nil {
		return nil
	}
	component, err := render.Markdown(src)
	if err != nil {
		return nil
	}
	return component
}

// leafName returns the final path segment of a repo-relative path.
func leafName(path string) string {
	if idx := strings.LastIndexByte(path, '/'); idx >= 0 {
		return path[idx+1:]
	}
	return path
}

// toID copies proto id bytes into a fixed [16]byte (truncating/zero-padding).
// Lore repository and branch ids are always 16 bytes on the wire.
func toID(b []byte) [16]byte {
	var id [16]byte
	copy(id[:], b)
	return id
}
