package handlers

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	thin_clientv1 "arcloreweb/gen/lore/thin_client/v1"
	"arcloreweb/internal/lore"
	"arcloreweb/internal/render"
	"arcloreweb/web/templates"
)

// Tree handles GET /{owner}/{repo}/src/branch/{branch}/*
//
// Resolution:
//  1. Resolve repo by name → repoID (zeroRepo scope for the repo lookup).
//  2. Resolve branch by name → branchID (repoID scope).
//  3. subPath = chi wildcard ("*"), trimmed of leading "/".
//  4. Call RevisionTree(ctx, branchID, 0, parentDir(subPath), 1) which returns
//     the immediate children of the parent directory.
//     - subPath=="" → listing of the branch root (same as repo home but for an
//     arbitrary branch by name).
//     - subPath!="" → scan returned nodes for an exact path match:
//     * DIRECTORY → re-call RevisionTree(…, subPath, 1) and render dir listing.
//     * FILE      → FetchContent → highlight or download panel.
//     * not found → 404.
func (h *Handler) Tree(w http.ResponseWriter, r *http.Request) {
	owner := chi.URLParam(r, "owner")
	repoName := chi.URLParam(r, "repo")
	branchName := chi.URLParam(r, "branch")
	subPath := strings.TrimPrefix(chi.URLParam(r, "*"), "/")

	// --- Step 1: resolve repo ---
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

	// --- Step 2: resolve branch ---
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

	// --- Step 3: resolve the path ---
	if subPath == "" {
		// Branch root — list the root directory.
		h.renderDirListing(w, r, ctx, repoID, branchID, repoName, branchName, owner, "", nil)
		return
	}

	// Fetch the parent directory's immediate children to find the subPath node.
	parent := parentDir(subPath)
	_, parentNodes, terr := h.Lore.RevisionTree(ctx, branchID, 0, parent, 1)
	if terr != nil {
		if status.Code(terr) == codes.NotFound {
			renderPageStatus(w, r, http.StatusNotFound, "Not found — ArcLore", templates.NotFound(subPath))
			return
		}
		http.Error(w, "failed to read tree: "+terr.Error(), http.StatusBadGateway)
		return
	}

	// Find the node whose path exactly matches subPath.
	var matched *thin_clientv1.TreeNode
	for _, node := range parentNodes {
		if node.GetPath() == subPath {
			matched = node
			break
		}
	}
	if matched == nil {
		renderPageStatus(w, r, http.StatusNotFound, "Not found — ArcLore", templates.NotFound(subPath))
		return
	}

	switch matched.GetNodeType() {
	case thin_clientv1.NodeType_DIRECTORY:
		// Re-list the directory itself.
		_, childNodes, terr2 := h.Lore.RevisionTree(ctx, branchID, 0, subPath, 1)
		if terr2 != nil {
			if status.Code(terr2) == codes.NotFound {
				renderPageStatus(w, r, http.StatusNotFound, "Not found — ArcLore", templates.NotFound(subPath))
				return
			}
			http.Error(w, "failed to read tree: "+terr2.Error(), http.StatusBadGateway)
			return
		}
		h.renderDirListing(w, r, ctx, repoID, branchID, repoName, branchName, owner, subPath, childNodes)

	case thin_clientv1.NodeType_FILE, thin_clientv1.NodeType_LINK:
		h.renderFileView(w, r, ctx, repoID, branchID, repoName, branchName, owner, subPath, matched)

	default:
		renderPageStatus(w, r, http.StatusNotFound, "Not found — ArcLore", templates.NotFound(subPath))
	}
}

// Raw handles GET /{owner}/{repo}/raw/branch/{branch}/*
//
// Resolves the repo and branch, locates the FILE node via the same
// parentDir+match logic as Tree, then streams the blob body straight to the
// ResponseWriter (no buffering, no Layout). Returns 404 for missing paths or
// directories; 502 for server errors.
func (h *Handler) Raw(w http.ResponseWriter, r *http.Request) {
	repoName := chi.URLParam(r, "repo")
	branchName := chi.URLParam(r, "branch")
	subPath := strings.TrimPrefix(chi.URLParam(r, "*"), "/")

	if subPath == "" {
		http.Error(w, "raw endpoint requires a file path", http.StatusBadRequest)
		return
	}

	// Resolve repo.
	baseCtx, berr := h.baseCtx(r)
	if berr != nil {
		http.Error(w, forbiddenDetail(berr), http.StatusForbidden)
		return
	}
	repo, err := h.Lore.GetRepositoryByName(baseCtx, repoName)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "failed to load repository: "+err.Error(), http.StatusBadGateway)
		return
	}
	repoID := toID(repo.GetId())
	ctx, aerr := h.repoCtx(r, repoID)
	if aerr != nil {
		http.Error(w, forbiddenDetail(aerr), http.StatusForbidden)
		return
	}

	// Resolve branch.
	branch, err := h.Lore.GetBranchByName(ctx, branchName)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "failed to load branch: "+err.Error(), http.StatusBadGateway)
		return
	}
	branchID := toID(branch.GetId())

	// Locate the node.
	parent := parentDir(subPath)
	_, parentNodes, terr := h.Lore.RevisionTree(ctx, branchID, 0, parent, 1)
	if terr != nil {
		if status.Code(terr) == codes.NotFound {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "failed to read tree: "+terr.Error(), http.StatusBadGateway)
		return
	}

	var matched *thin_clientv1.TreeNode
	for _, node := range parentNodes {
		if node.GetPath() == subPath {
			matched = node
			break
		}
	}
	if matched == nil || matched.GetNodeType() == thin_clientv1.NodeType_DIRECTORY {
		http.NotFound(w, r)
		return
	}

	// Stream the blob.
	body, contentType, size, ferr := h.Lore.FetchContent(ctx, repoID, matched.GetAddress())
	if ferr != nil {
		http.Error(w, "failed to fetch content: "+ferr.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = body.Close() }()

	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)
	if size >= 0 {
		w.Header().Set("Content-Length", formatInt(size))
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, body)
}

// renderDirListing renders the file-table page for a directory. nodes is the
// slice already returned by RevisionTree for dirPath (nil for the branch root
// when we reuse the first call). The lock overlay is applied per row.
func (h *Handler) renderDirListing(
	w http.ResponseWriter,
	r *http.Request,
	ctx context.Context,
	repoID [16]byte,
	branchID [16]byte,
	repoName, branchName, owner, dirPath string,
	nodes []*thin_clientv1.TreeNode,
) {
	// ctx is the repo-scoped context (authz token + repoID) resolved by the
	// caller via repoCtx; every Lore call below reuses it.

	// If nodes were not pre-fetched (branch root fast path), fetch them now.
	if nodes == nil {
		var terr error
		_, nodes, terr = h.Lore.RevisionTree(
			ctx, branchID, 0, dirPath, 1,
		)
		if terr != nil {
			if status.Code(terr) == codes.NotFound {
				renderPageStatus(w, r, http.StatusNotFound, "Not found — ArcLore", templates.NotFound(dirPath))
				return
			}
			http.Error(w, "failed to read tree: "+terr.Error(), http.StatusBadGateway)
			return
		}
	}

	lockByPath := h.lockOverlay(ctx, branchID)
	rows := buildRows(nodes, lockByPath)

	view := templates.TreeView{
		Owner:      owner,
		RepoName:   repoName,
		BranchName: branchName,
		DirPath:    dirPath,
		Rows:       rows,
	}
	title := repoName
	if dirPath != "" {
		title = leafName(dirPath) + " — " + repoName
	}
	renderPage(w, r, title+" — ArcLore", templates.TreePage(view))
}

// renderFileView fetches, (optionally) highlights, and renders a single file.
func (h *Handler) renderFileView(
	w http.ResponseWriter,
	r *http.Request,
	ctx context.Context,
	repoID [16]byte,
	branchID [16]byte,
	repoName, branchName, owner, filePath string,
	node *thin_clientv1.TreeNode,
) {
	body, _, size, ferr := h.Lore.FetchContent(ctx, repoID, node.GetAddress())
	if ferr != nil {
		http.Error(w, "failed to fetch content: "+ferr.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = body.Close() }()

	filename := leafName(filePath)
	rawURL := "/" + owner + "/" + repoName + "/raw/branch/" + branchName + "/" + filePath

	// Lock overlay: check whether this exact path is locked.
	lockByPath := h.lockOverlay(ctx, branchID)
	locked := false
	lockOwner := ""
	if lock, ok := lockByPath[filePath]; ok {
		locked = true
		lockOwner = lock.GetOwner()
	}

	// If the server reports the blob is large, skip buffering immediately.
	if size > lore.MaxHighlightBytes {
		view := templates.FileView{
			Owner:      owner,
			RepoName:   repoName,
			BranchName: branchName,
			FilePath:   filePath,
			Filename:   filename,
			RawURL:     rawURL,
			Locked:     locked,
			LockOwner:  lockOwner,
			TooLarge:   true,
		}
		renderPage(w, r, filename+" — ArcLore", templates.FilePage(view))
		return
	}

	// Buffer up to MaxHighlightBytes + 1 to detect exact-size vs over-size.
	limited := io.LimitReader(body, lore.MaxHighlightBytes+1)
	src, readErr := io.ReadAll(limited)
	if readErr != nil {
		http.Error(w, "failed to read content: "+readErr.Error(), http.StatusBadGateway)
		return
	}

	// Over-cap or binary (NUL byte in first ~8 KiB) → download panel.
	if int64(len(src)) > lore.MaxHighlightBytes || isBinary(src) {
		view := templates.FileView{
			Owner:      owner,
			RepoName:   repoName,
			BranchName: branchName,
			FilePath:   filePath,
			Filename:   filename,
			RawURL:     rawURL,
			Locked:     locked,
			LockOwner:  lockOwner,
			TooLarge:   true,
		}
		renderPage(w, r, filename+" — ArcLore", templates.FilePage(view))
		return
	}

	lexerName := render.LexerName(filename, src)
	highlighted, herr := render.Highlight(filename, src)
	if herr != nil {
		// Fallback: render as plain text if highlight fails.
		lexerName = "Plain Text"
		highlighted, _ = render.Highlight("", src)
	}

	view := templates.FileView{
		Owner:      owner,
		RepoName:   repoName,
		BranchName: branchName,
		FilePath:   filePath,
		Filename:   filename,
		RawURL:     rawURL,
		Locked:     locked,
		LockOwner:  lockOwner,
		LexerName:  lexerName,
		Body:       highlighted,
	}
	renderPage(w, r, filename+" — ArcLore", templates.FilePage(view))
}

// parentDir returns the parent directory portion of a repo-relative path.
// For a top-level entry (no "/") the parent is "" (branch root).
// For "foo/bar/baz.go" it returns "foo/bar".
func parentDir(path string) string {
	if idx := strings.LastIndexByte(path, '/'); idx >= 0 {
		return path[:idx]
	}
	return ""
}

// isBinary reports whether src looks like binary data by scanning the first
// 8 KiB for a NUL byte.
func isBinary(src []byte) bool {
	probe := src
	if len(probe) > 8192 {
		probe = probe[:8192]
	}
	return bytes.IndexByte(probe, 0) >= 0
}

// formatInt renders an int64 as a decimal string without importing strconv at
// the call sites (this file already imports the necessary packages).
func formatInt(n int64) string {
	if n == 0 {
		return "0"
	}
	// Build the string by successive division.
	buf := [20]byte{}
	pos := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
