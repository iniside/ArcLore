package handlers

import (
	"context"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	modelv1 "arcloreweb/gen/lore/model/v1"
	"arcloreweb/web/templates"
)

// maxCommitRows is the hard ceiling on how many history rows are enriched and
// rendered per page. RevisionList page size is server-controlled, so this caps
// the bounded N+1 RevisionInfo fan-out regardless of how many items the server
// returns.
const maxCommitRows = 50

// enrichWorkers bounds the concurrent RevisionInfo calls during enrichment.
const enrichWorkers = 6

// Commits handles GET /{owner}/{repo}/commits/branch/{branch}: paged commit
// history for a branch, newest→oldest, grouped by date.
func (h *Handler) Commits(w http.ResponseWriter, r *http.Request) {
	owner := chi.URLParam(r, "owner")
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

	// --- cursor from ?cursor=<hex> (empty → nil = branch tip) ---
	var cursor []byte
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		decoded, derr := hex.DecodeString(raw)
		if derr != nil {
			http.Error(w, "invalid cursor", http.StatusBadRequest)
			return
		}
		cursor = decoded
	}

	items, forward, backward, lerr := h.Lore.ListRevisions(ctx, branchID, cursor)
	if lerr != nil {
		if status.Code(lerr) == codes.NotFound {
			renderPage(w, r, repoName+" — ArcLore", templates.CommitListPage(templates.CommitListView{
				Owner: owner, RepoName: repoName, BranchName: branchName, Empty: true,
			}))
			return
		}
		http.Error(w, "failed to list revisions: "+lerr.Error(), http.StatusBadGateway)
		return
	}

	// Dedup by signature (the anchor may appear mid-page with items on both
	// sides), preserving the newest→oldest order the server returned, then cap
	// to the render ceiling.
	deduped := dedupBySignature(items)
	if len(deduped) > maxCommitRows {
		deduped = deduped[:maxCommitRows]
	}

	rows := h.enrichRevisions(ctx, owner, repoName, deduped)

	view := templates.CommitListView{
		Owner:      owner,
		RepoName:   repoName,
		BranchName: branchName,
		Groups:     groupByDate(rows),
		Empty:      len(rows) == 0,
	}
	// Newer = backward cursor; Older = forward cursor (history is newest→oldest,
	// the forward cursor walks toward older commits).
	if len(backward) != 0 {
		view.PrevURL = commitsURL(owner, repoName, branchName, backward)
	}
	if len(forward) != 0 {
		view.NextURL = commitsURL(owner, repoName, branchName, forward)
	}

	renderPage(w, r, repoName+" — Commits — ArcLore", templates.CommitListPage(view))
}

// dedupBySignature removes duplicate revision items by signature, keeping the
// first occurrence so the returned newest→oldest order is preserved.
func dedupBySignature(items []*modelv1.RevisionItem) []*modelv1.RevisionItem {
	seen := make(map[string]struct{}, len(items))
	out := make([]*modelv1.RevisionItem, 0, len(items))
	for _, item := range items {
		key := string(item.GetSignature())
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

// enrichRevisions performs the bounded N+1 RevisionInfo enrichment: each lean
// RevisionItem is resolved to its message/author/timestamp via a small bounded
// worker pool (no unbounded goroutine fan-out). Input order is preserved in the
// output. Items whose RevisionInfo fails are rendered with placeholder metadata
// rather than dropped.
func (h *Handler) enrichRevisions(
	ctx context.Context,
	owner, repoName string,
	items []*modelv1.RevisionItem,
) []templates.CommitRowView {
	rows := make([]templates.CommitRowView, len(items))
	sem := make(chan struct{}, enrichWorkers)
	var wg sync.WaitGroup

	for i, item := range items {
		sig := item.GetSignature()
		hexSig := hex.EncodeToString(sig)
		row := templates.CommitRowView{
			ShortSig: shortSig(hexSig),
			HexSig:   hexSig,
			URL:      commitURL(owner, repoName, hexSig),
			Subject:  "(no message)",
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, sig []byte, base templates.CommitRowView) {
			defer wg.Done()
			defer func() { <-sem }()

			rev, err := h.Lore.RevisionInfoBySignature(ctx, sig)
			if err == nil && rev != nil {
				base.Subject = firstLine(rev.GetCommitMessage())
				base.Author = rev.GetCreatedBy()
				base.RelTime = relativeTime(rev.GetTimestamp())
				base.Date = unixDate(rev.GetTimestamp())
			}
			rows[idx] = base
		}(i, sig, row)
	}

	wg.Wait()
	return rows
}

// groupByDate groups already-ordered commit rows into date sections, preserving
// row order within and across groups.
func groupByDate(rows []templates.CommitRowView) []templates.CommitDateGroup {
	groups := make([]templates.CommitDateGroup, 0)
	for _, row := range rows {
		date := row.Date
		if date == "" {
			date = "unknown date"
		}
		if n := len(groups); n > 0 && groups[n-1].Date == date {
			groups[n-1].Rows = append(groups[n-1].Rows, row)
			continue
		}
		groups = append(groups, templates.CommitDateGroup{Date: date, Rows: []templates.CommitRowView{row}})
	}
	return groups
}

// commitsURL builds a commit-history page link carrying a hex cursor.
func commitsURL(owner, repoName, branchName string, cursor []byte) string {
	return "/" + owner + "/" + repoName + "/commits/branch/" + branchName +
		"?cursor=" + hex.EncodeToString(cursor)
}

// commitURL builds a single-commit link from a hex signature.
func commitURL(owner, repoName, hexSig string) string {
	return "/" + owner + "/" + repoName + "/commit/" + hexSig
}

// shortSig returns the first 12 hex characters of a hex signature.
func shortSig(hexSig string) string {
	if len(hexSig) <= 12 {
		return hexSig
	}
	return hexSig[:12]
}

// firstLine returns the first line of a (possibly multi-line) commit message.
func firstLine(msg string) string {
	for i := 0; i < len(msg); i++ {
		if msg[i] == '\n' {
			line := msg[:i]
			if line == "" {
				return "(no message)"
			}
			return line
		}
	}
	if msg == "" {
		return "(no message)"
	}
	return msg
}

// unixDate renders a Lore timestamp (milliseconds since the Unix epoch — see
// lore-revision util::time::timestamp_millis) as a YYYY-MM-DD calendar date used
// for grouping and absolute display.
func unixDate(ts uint64) string {
	if ts == 0 {
		return ""
	}
	return time.UnixMilli(int64(ts)).UTC().Format("2006-01-02")
}

// relativeTime renders a Lore timestamp (milliseconds since the Unix epoch) as a
// coarse human-relative string.
func relativeTime(ts uint64) string {
	if ts == 0 {
		return ""
	}
	d := time.Since(time.UnixMilli(int64(ts)))
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return pluralAgo(int(d/time.Minute), "minute")
	case d < 24*time.Hour:
		return pluralAgo(int(d/time.Hour), "hour")
	case d < 30*24*time.Hour:
		return pluralAgo(int(d/(24*time.Hour)), "day")
	case d < 365*24*time.Hour:
		return pluralAgo(int(d/(30*24*time.Hour)), "month")
	default:
		return pluralAgo(int(d/(365*24*time.Hour)), "year")
	}
}

// pluralAgo formats "N unit(s) ago".
func pluralAgo(n int, unit string) string {
	if n <= 0 {
		n = 1
	}
	plural := ""
	if n != 1 {
		plural = "s"
	}
	return itoa(n) + " " + unit + plural + " ago"
}

// itoa renders a non-negative int as decimal.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}
