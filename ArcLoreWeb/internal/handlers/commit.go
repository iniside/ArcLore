package handlers

import (
	"context"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/aymanbagabas/go-udiff"
	"github.com/bluekeyes/go-gitdiff/gitdiff"
	"github.com/go-chi/chi/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	modelv1 "arcloreweb/gen/lore/model/v1"
	thin_clientv1 "arcloreweb/gen/lore/thin_client/v1"
	"arcloreweb/internal/render"
	"arcloreweb/web/templates"
)

// contentDiffWorkers bounds the concurrent per-file blob-fetch + diff calls
// when building a commit's diff view.
const contentDiffWorkers = 6

// maxInlineDiffFiles caps how many changed files get the full address-recover +
// blob-fetch + unified-diff treatment. Files beyond the cap are still listed in
// the sidebar (as list-only synthetics) but make zero RevisionTree/HTTP calls.
const maxInlineDiffFiles = 200

// MaxDiffBytes is the per-side blob cap when fetching content for a diff. A side
// larger than this is treated like a binary/too-large file: listed, no hunk.
const MaxDiffBytes int64 = 1 << 20 // 1 MiB

// Commit handles GET /{owner}/{repo}/commit/{sig}: the full diff of one commit
// against its first parent (parent_self), rendered per file.
func (h *Handler) Commit(w http.ResponseWriter, r *http.Request) {
	owner := chi.URLParam(r, "owner")
	repoName := chi.URLParam(r, "repo")
	sigHex := chi.URLParam(r, "sig")

	sig, derr := hex.DecodeString(sigHex)
	if derr != nil || len(sig) == 0 {
		http.Error(w, "invalid commit signature", http.StatusBadRequest)
		return
	}

	// --- resolve repo (repoID scopes the RevisionDiff/RevisionTree/blob calls) ---
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

	// --- revision metadata ---
	rev, err := h.Lore.RevisionInfoBySignature(ctx, sig)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			renderPageStatus(w, r, http.StatusNotFound, "Commit not found — ArcLore",
				templates.NotFound("commit: "+sigHex))
			return
		}
		http.Error(w, "failed to load commit: "+err.Error(), http.StatusBadGateway)
		return
	}

	view := buildCommitView(owner, repoName, sigHex, rev)
	// The default branch gives the back-link + sub-header tabs (Commits/Locks) a
	// real branch to point at; the commit page itself carries no branch context.
	view.BranchName = repo.GetDefaultBranchName()

	// --- determine the "from" side: parent_self ---
	parentSig := rev.GetParentSelf().GetSignature()
	view.RootCommit = len(parentSig) == 0

	_, entries, derr2 := h.Lore.RevisionDiff(ctx, parentSig, sig)
	if derr2 != nil {
		// A diff failure is rendered as "no file changes" rather than a hard
		// error so the commit header still shows.
		renderPage(w, r, view.ShortSig+" — ArcLore", templates.CommitPage(view))
		return
	}

	// Flatten the diff entries to file changes here (the entry element type is
	// unexported in the lore package; ranging keeps it unnamed). DIRECTORY
	// changes and conflict entries are skipped — conflicts are not rendered in
	// v1.
	changes := make([]*thin_clientv1.DiffChange, 0, len(entries))
	for _, entry := range entries {
		change := entry.Change
		if change == nil {
			continue
		}
		if change.GetNodeType() == thin_clientv1.NodeType_DIRECTORY {
			continue
		}
		// KEEP entries are unchanged files (both content sides present and
		// identical) — nothing to diff or list.
		if change.GetAction() == thin_clientv1.Action_KEEP {
			continue
		}
		changes = append(changes, change)
	}

	// The full content Address for each side is recovered from the revision
	// trees identified here: toIdent = this revision, fromIdent = parent_self
	// (nil for a root commit, which has no parent tree → all-add).
	toIdent := rev.GetIdentifier()
	fromIdent := rev.GetParentSelf().GetIdentifier()

	files, added, deleted := h.buildCommitDiff(ctx, changes, repoID, toIdent, fromIdent)
	view.FilesChanged = len(files)
	view.Added = added
	view.Deleted = deleted
	view.Files = buildCommitFiles(files)
	if len(files) > 0 {
		view.Diff = render.Diff(files)
	}

	renderPage(w, r, view.ShortSig+" — ArcLore", templates.CommitPage(view))
}

// commitDiffResult is one file's resolved diff (or a binary/synthetic stand-in).
type commitDiffResult struct {
	index   int
	files   []*gitdiff.File
	added   uint64
	deleted uint64
}

// buildCommitDiff resolves each changed file's unified diff (bounded
// concurrency): it recovers both content addresses from the revision trees,
// fetches both blobs, and diffs them locally. It returns the flattened, in-order
// file list plus the aggregate add/delete line counts. Binary changes are
// surfaced as a synthetic one-file binary marker. Changes past
// maxInlineDiffFiles are emitted as list-only synthetics with no I/O.
func (h *Handler) buildCommitDiff(
	ctx context.Context,
	changes []*thin_clientv1.DiffChange,
	repoID [16]byte,
	toIdent, fromIdent *modelv1.RevisionIdentifier,
) ([]*gitdiff.File, uint64, uint64) {
	results := make([]commitDiffResult, len(changes))
	sem := make(chan struct{}, contentDiffWorkers)
	var wg sync.WaitGroup

	for i, change := range changes {
		// Past the cap: list the file but make no RevisionTree/HTTP calls.
		if i >= maxInlineDiffFiles {
			file := &gitdiff.File{NewName: diffChangePath(change)}
			stampAction(file, change.GetAction())
			results[i] = commitDiffResult{index: i, files: []*gitdiff.File{file}}
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, change *thin_clientv1.DiffChange) {
			defer wg.Done()
			defer func() { <-sem }()
			results[idx] = h.resolveFileDiff(ctx, idx, change, repoID, toIdent, fromIdent)
		}(i, change)
	}
	wg.Wait()

	sort.SliceStable(results, func(i, j int) bool { return results[i].index < results[j].index })

	files := make([]*gitdiff.File, 0, len(results))
	var totalAdded, totalDeleted uint64
	for i := range results {
		files = append(files, results[i].files...)
		totalAdded += results[i].added
		totalDeleted += results[i].deleted
	}
	return files, totalAdded, totalDeleted
}

// buildCommitFiles projects the parsed diff files onto the sidebar's
// changed-files list: the display path (NewName, falling back to OldName) plus
// per-file add/delete line counts summed from each text fragment. Binary files
// have no text fragments, so their counts stay zero.
func buildCommitFiles(files []*gitdiff.File) []templates.CommitFileView {
	out := make([]templates.CommitFileView, 0, len(files))
	for _, f := range files {
		if f == nil {
			continue
		}
		path := f.NewName
		if path == "" {
			path = f.OldName
		}
		var adds, dels int64
		if !f.IsBinary {
			for _, frag := range f.TextFragments {
				if frag == nil {
					continue
				}
				adds += frag.LinesAdded
				dels += frag.LinesDeleted
			}
		}
		out = append(out, templates.CommitFileView{Path: path, Adds: adds, Dels: dels})
	}
	return out
}

// stampAction flags a gitdiff.File as a new/deleted file from the change action
// so add/delete styling survives even when both diff labels collapse to the same
// path. KEEP/MOVE/COPY leave both flags false (a content modification).
func stampAction(f *gitdiff.File, action thin_clientv1.Action) {
	f.IsNew = action == thin_clientv1.Action_ADD
	f.IsDelete = action == thin_clientv1.Action_DELETE
}

// resolveFileDiff recovers both content versions' full addresses from the
// revision trees, fetches both blobs (capped), and generates a unified diff
// locally with go-udiff. ADD/DELETE/MOVE, root commits, binary and oversized
// files are each handled; a missing/identical/unparseable diff degrades to a
// list-only synthetic file so the change still shows in the sidebar.
func (h *Handler) resolveFileDiff(
	ctx context.Context,
	index int,
	change *thin_clientv1.DiffChange,
	repoID [16]byte,
	toIdent, fromIdent *modelv1.RevisionIdentifier,
) commitDiffResult {
	result := commitDiffResult{index: index}
	action := change.GetAction()

	path := change.GetPath()
	fromPath := change.GetPathFrom()
	if fromPath == "" {
		fromPath = path
	}

	// synthetic emits a single list-only file (no hunk) carrying the display
	// path and the add/delete styling, then returns the result.
	synthetic := func() commitDiffResult {
		file := &gitdiff.File{NewName: diffChangePath(change)}
		stampAction(file, action)
		result.files = []*gitdiff.File{file}
		return result
	}

	// --- recover the "to" (new) content address from this revision's tree ---
	var toAddr *modelv1.Address
	if len(change.GetContentTo()) > 0 && toIdent != nil {
		toAddr = h.recoverAddress(ctx, toIdent, path)
	}

	// --- recover the "from" (old) content address from the parent tree ---
	var fromAddr *modelv1.Address
	if len(change.GetContentFrom()) > 0 && fromIdent != nil {
		fromAddr = h.recoverAddress(ctx, fromIdent, fromPath)
	}

	// --- fetch both sides (capped); a missing side stays empty ---
	toBytes, toTrunc, _ := h.Lore.FetchContentBytes(ctx, repoID, toAddr, MaxDiffBytes)
	fromBytes, fromTrunc, _ := h.Lore.FetchContentBytes(ctx, repoID, fromAddr, MaxDiffBytes)

	// --- binary: surface a binary marker, no hunk ---
	if (toAddr != nil && isBinary(toBytes)) || (fromAddr != nil && isBinary(fromBytes)) {
		file := &gitdiff.File{NewName: path, IsBinary: true}
		stampAction(file, action)
		result.files = []*gitdiff.File{file}
		return result
	}

	// --- too large: a side exceeded the cap → list-only, no hunk ---
	if toTrunc || fromTrunc {
		return synthetic()
	}

	// go-gitdiff rejects empty file labels; both sides share the change path so
	// the same-label collapse is recovered by the IsNew/IsDelete stamp below.
	label := path
	if label == "" {
		label = fromPath
	}
	unified := udiff.Unified(label, label, string(fromBytes), string(toBytes))
	if unified == "" {
		// Identical content (e.g. a pure rename) — list only, no hunk.
		return synthetic()
	}

	files, perr := render.ParseUnifiedDiff(unified)
	if perr != nil || len(files) == 0 {
		return synthetic()
	}
	for _, f := range files {
		if f.NewName == "" && f.OldName == "" {
			f.NewName = path
		}
		stampAction(f, action)
		for _, frag := range f.TextFragments {
			if frag == nil {
				continue
			}
			result.added += uint64(frag.LinesAdded)
			result.deleted += uint64(frag.LinesDeleted)
		}
	}
	result.files = files
	return result
}

// recoverAddress recovers a file's full content Address (32-byte hash +
// 16-byte context) from a revision tree, mirroring the single-file lookup in
// tree.go: list the parent directory (pathPrefix MUST be a directory — passing
// the file path itself is rejected by the server) and match the child node by
// exact path. A tree error (e.g. NotFound) or a missing child yields nil so the
// file still lists; both-nil collapses to a list-only synthetic upstream.
func (h *Handler) recoverAddress(
	ctx context.Context,
	ident *modelv1.RevisionIdentifier,
	filePath string,
) *modelv1.Address {
	_, nodes, terr := h.Lore.RevisionTree(ctx, toID(ident.GetBranchId()), ident.GetNumber(), parentDir(filePath), 1)
	if terr != nil {
		return nil
	}
	for _, node := range nodes {
		if node.GetPath() == filePath && node.GetNodeType() == thin_clientv1.NodeType_FILE {
			return node.GetAddress()
		}
	}
	return nil
}

// diffChangePath returns the most informative path for a change.
func diffChangePath(change *thin_clientv1.DiffChange) string {
	if p := change.GetPath(); p != "" {
		return p
	}
	return change.GetPathFrom()
}

// buildCommitView assembles the proto-free commit header view from a Revision.
func buildCommitView(owner, repoName, sigHex string, rev *thin_clientv1.Revision) templates.CommitView {
	subject, body := splitMessage(rev.GetCommitMessage())
	view := templates.CommitView{
		Owner:    owner,
		RepoName: repoName,
		ShortSig: shortSig(sigHex),
		HexSig:   sigHex,
		Subject:  subject,
		Body:     body,
		Author:   rev.GetCreatedBy(),
		Date:     unixDate(rev.GetTimestamp()),
	}
	if committer := rev.GetCommittedBy(); committer != "" && committer != view.Author {
		view.Committer = committer
	}

	parentSelf := rev.GetParentSelf().GetSignature()
	if len(parentSelf) != 0 {
		ph := hex.EncodeToString(parentSelf)
		view.Parents = append(view.Parents, templates.CommitParentView{
			ShortSig: shortSig(ph),
			URL:      commitURL(owner, repoName, ph),
		})
	}
	parentOther := rev.GetParentOther().GetSignature()
	if len(parentOther) != 0 {
		ph := hex.EncodeToString(parentOther)
		view.Parents = append(view.Parents, templates.CommitParentView{
			ShortSig: shortSig(ph),
			URL:      commitURL(owner, repoName, ph),
		})
	}
	return view
}

// splitMessage splits a commit message into its subject (first line) and body
// (the remainder, leading blank lines trimmed).
func splitMessage(msg string) (subject, body string) {
	first, rest, found := strings.Cut(msg, "\n")
	if first == "" {
		first = "(no message)"
	}
	if !found {
		return first, ""
	}
	return first, strings.TrimLeft(rest, "\n")
}
