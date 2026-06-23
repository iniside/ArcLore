package handlers

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/alexedwards/scs/v2"
	"github.com/go-chi/chi/v5"

	gen "arcloreweb/gen"
	modelv1 "arcloreweb/gen/lore/model/v1"
	thin_clientv1 "arcloreweb/gen/lore/thin_client/v1"
	"arcloreweb/internal/auth"
	"arcloreweb/internal/lore"
)

// ─── fake LoreClient ─────────────────────────────────────────────────────────

// fakeLore implements LoreClient. Each method is backed by a corresponding
// function field so tests can inject per-call behaviour without subclassing.
// All fields default to nil; a nil field makes the method return zero values.
type fakeLore struct {
	grpcHostFn              func() string
	resourceAuthzTokenFn    func(ctx context.Context, identityToken string, resource string) (string, error)
	listRepositoriesFn      func(ctx context.Context) ([]*modelv1.Repository, error)
	getRepositoryByNameFn   func(ctx context.Context, name string) (*modelv1.Repository, error)
	getBranchByNameFn       func(ctx context.Context, name string) (*modelv1.Branch, error)
	listBranchesFn          func(ctx context.Context) ([]*modelv1.Branch, error)
	listRevisionsFn         func(ctx context.Context, branchID [16]byte, cursor []byte) ([]*modelv1.RevisionItem, []byte, []byte, error)
	revisionInfoBySignatureFn func(ctx context.Context, signature []byte) (*thin_clientv1.Revision, error)
	revisionTreeFn          func(ctx context.Context, branchID [16]byte, number uint64, pathPrefix string, maxDepth uint32) (*thin_clientv1.RevisionTreeHeader, []*thin_clientv1.TreeNode, error)
	revisionDiffFn          func(ctx context.Context, signatureFrom, signatureTo []byte) (*thin_clientv1.RevisionDiffHeader, []lore.RevisionDiffEntry, error)
	queryLocksFn            func(ctx context.Context, branchID [16]byte) ([]*gen.Lock, error)
	fetchContentFn          func(ctx context.Context, repoID [16]byte, addr *modelv1.Address) (io.ReadCloser, string, int64, error)
	fetchContentBytesFn     func(ctx context.Context, repoID [16]byte, addr *modelv1.Address, cap int64) ([]byte, bool, error)
	repositoryCreateFn      func(ctx context.Context, token string, in lore.RepositoryCreateInput) ([16]byte, error)
	repositoryDeleteFn      func(ctx context.Context, token string, repoID [16]byte) error
	unlockFn                func(ctx context.Context, token string, repoID [16]byte, resources []*gen.Resource) error
}

func (f *fakeLore) GRPCHost() string {
	if f.grpcHostFn != nil {
		return f.grpcHostFn()
	}
	return "fake:50051"
}

func (f *fakeLore) ResourceAuthzToken(ctx context.Context, identityToken string, resource string) (string, error) {
	if f.resourceAuthzTokenFn != nil {
		return f.resourceAuthzTokenFn(ctx, identityToken, resource)
	}
	return "", nil
}

func (f *fakeLore) ListRepositories(ctx context.Context) ([]*modelv1.Repository, error) {
	if f.listRepositoriesFn != nil {
		return f.listRepositoriesFn(ctx)
	}
	return nil, nil
}

func (f *fakeLore) GetRepositoryByName(ctx context.Context, name string) (*modelv1.Repository, error) {
	if f.getRepositoryByNameFn != nil {
		return f.getRepositoryByNameFn(ctx, name)
	}
	return nil, nil
}

func (f *fakeLore) GetBranchByName(ctx context.Context, name string) (*modelv1.Branch, error) {
	if f.getBranchByNameFn != nil {
		return f.getBranchByNameFn(ctx, name)
	}
	return nil, nil
}

func (f *fakeLore) ListBranches(ctx context.Context) ([]*modelv1.Branch, error) {
	if f.listBranchesFn != nil {
		return f.listBranchesFn(ctx)
	}
	return nil, nil
}

func (f *fakeLore) ListRevisions(ctx context.Context, branchID [16]byte, cursor []byte) ([]*modelv1.RevisionItem, []byte, []byte, error) {
	if f.listRevisionsFn != nil {
		return f.listRevisionsFn(ctx, branchID, cursor)
	}
	return nil, nil, nil, nil
}

func (f *fakeLore) RevisionInfoBySignature(ctx context.Context, signature []byte) (*thin_clientv1.Revision, error) {
	if f.revisionInfoBySignatureFn != nil {
		return f.revisionInfoBySignatureFn(ctx, signature)
	}
	return nil, nil
}

func (f *fakeLore) RevisionTree(ctx context.Context, branchID [16]byte, number uint64, pathPrefix string, maxDepth uint32) (*thin_clientv1.RevisionTreeHeader, []*thin_clientv1.TreeNode, error) {
	if f.revisionTreeFn != nil {
		return f.revisionTreeFn(ctx, branchID, number, pathPrefix, maxDepth)
	}
	return nil, nil, nil
}

func (f *fakeLore) RevisionDiff(ctx context.Context, signatureFrom, signatureTo []byte) (*thin_clientv1.RevisionDiffHeader, []lore.RevisionDiffEntry, error) {
	if f.revisionDiffFn != nil {
		return f.revisionDiffFn(ctx, signatureFrom, signatureTo)
	}
	return nil, nil, nil
}

func (f *fakeLore) QueryLocks(ctx context.Context, branchID [16]byte) ([]*gen.Lock, error) {
	if f.queryLocksFn != nil {
		return f.queryLocksFn(ctx, branchID)
	}
	return nil, nil
}

func (f *fakeLore) FetchContent(ctx context.Context, repoID [16]byte, addr *modelv1.Address) (io.ReadCloser, string, int64, error) {
	if f.fetchContentFn != nil {
		return f.fetchContentFn(ctx, repoID, addr)
	}
	return io.NopCloser(strings.NewReader("")), "text/plain", 0, nil
}

func (f *fakeLore) FetchContentBytes(ctx context.Context, repoID [16]byte, addr *modelv1.Address, cap int64) ([]byte, bool, error) {
	if f.fetchContentBytesFn != nil {
		return f.fetchContentBytesFn(ctx, repoID, addr, cap)
	}
	return nil, false, nil
}

func (f *fakeLore) RepositoryCreate(ctx context.Context, token string, in lore.RepositoryCreateInput) ([16]byte, error) {
	if f.repositoryCreateFn != nil {
		return f.repositoryCreateFn(ctx, token, in)
	}
	return [16]byte{}, nil
}

func (f *fakeLore) RepositoryDelete(ctx context.Context, token string, repoID [16]byte) error {
	if f.repositoryDeleteFn != nil {
		return f.repositoryDeleteFn(ctx, token, repoID)
	}
	return nil
}

func (f *fakeLore) Unlock(ctx context.Context, token string, repoID [16]byte, resources []*gen.Resource) error {
	if f.unlockFn != nil {
		return f.unlockFn(ctx, token, repoID, resources)
	}
	return nil
}

// ─── test helpers ────────────────────────────────────────────────────────────

// newTestHandler builds a *Handler backed by the supplied fake and a real
// in-memory session manager.
func newTestHandler(t *testing.T, fl *fakeLore) (*Handler, *scs.SessionManager) {
	t.Helper()
	sessions := auth.NewSessionManager(false, "")
	h := New(fl, sessions)
	return h, sessions
}

// newRequest builds an httptest.Request with:
//   - the given identity injected into the context via auth.ContextWithIdentity,
//   - a chi route context seeded with the supplied URL params.
//
// params is a flat list of key, value pairs; e.g. "owner", "o", "repo", "r".
func newRequest(t *testing.T, method, target string, body io.Reader, identity auth.Identity, params ...string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, target, body)
	ctx := auth.ContextWithIdentity(r.Context(), identity)

	rctx := chi.NewRouteContext()
	for i := 0; i+1 < len(params); i += 2 {
		rctx.URLParams.Add(params[i], params[i+1])
	}
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	return r.WithContext(ctx)
}

// defaultIdentity is a non-empty identity suitable for most tests.
var defaultIdentity = auth.Identity{Sub: "testuser", Token: "id-token"}

// fakeRepoID is the 16-byte repo id used throughout tests.
var fakeRepoID = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

// fakeRepo returns a minimal *modelv1.Repository with the given name, using
// fakeRepoID as its id and "main" as its default branch.
func fakeRepo(name string) *modelv1.Repository {
	return &modelv1.Repository{
		Id:                fakeRepoID[:],
		Name:              name,
		DefaultBranchId:   fakeRepoID[:],
		DefaultBranchName: "main",
	}
}

// fakeBranch returns a minimal *modelv1.Branch with the given name and id.
func fakeBranch(name string) *modelv1.Branch {
	return &modelv1.Branch{
		Id:   fakeRepoID[:],
		Name: name,
	}
}

// ─── Home ────────────────────────────────────────────────────────────────────

func TestHomeHappyPath(t *testing.T) {
	fl := &fakeLore{
		listRepositoriesFn: func(ctx context.Context) ([]*modelv1.Repository, error) {
			return []*modelv1.Repository{
				fakeRepo("alpha"),
				fakeRepo("beta"),
			}, nil
		},
	}
	h, _ := newTestHandler(t, fl)

	r := newRequest(t, "GET", "/", nil, defaultIdentity)
	w := httptest.NewRecorder()
	h.Home(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Home: want 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "alpha") {
		t.Errorf("Home: body does not contain repo name %q; body snippet: %.200s", "alpha", body)
	}
}

func TestHomeListError(t *testing.T) {
	fl := &fakeLore{
		listRepositoriesFn: func(ctx context.Context) ([]*modelv1.Repository, error) {
			return nil, errors.New("rpc failure")
		},
	}
	h, _ := newTestHandler(t, fl)

	r := newRequest(t, "GET", "/", nil, defaultIdentity)
	w := httptest.NewRecorder()
	h.Home(w, r)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("Home error: want 502, got %d", w.Code)
	}
}

// ─── RepoHome ────────────────────────────────────────────────────────────────

func TestRepoHomeHappyPath(t *testing.T) {
	fl := &fakeLore{
		getRepositoryByNameFn: func(ctx context.Context, name string) (*modelv1.Repository, error) {
			return fakeRepo(name), nil
		},
		listBranchesFn: func(ctx context.Context) ([]*modelv1.Branch, error) {
			return []*modelv1.Branch{fakeBranch("main")}, nil
		},
		revisionTreeFn: func(ctx context.Context, branchID [16]byte, number uint64, pathPrefix string, maxDepth uint32) (*thin_clientv1.RevisionTreeHeader, []*thin_clientv1.TreeNode, error) {
			return nil, []*thin_clientv1.TreeNode{
				{Path: "README.md", NodeType: thin_clientv1.NodeType_FILE},
			}, nil
		},
		queryLocksFn: func(ctx context.Context, branchID [16]byte) ([]*gen.Lock, error) {
			return nil, nil
		},
		fetchContentFn: func(ctx context.Context, repoID [16]byte, addr *modelv1.Address) (io.ReadCloser, string, int64, error) {
			return io.NopCloser(strings.NewReader("# Hello")), "text/markdown", 7, nil
		},
	}
	h, _ := newTestHandler(t, fl)

	r := newRequest(t, "GET", "/-/myrepo", nil, defaultIdentity,
		"owner", "-", "repo", "myrepo")
	w := httptest.NewRecorder()
	h.RepoHome(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("RepoHome: want 200, got %d; body=%.200s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "myrepo") {
		t.Errorf("RepoHome: body does not contain repo name")
	}
}

// ─── Tree ────────────────────────────────────────────────────────────────────

func TestTreeRootHappyPath(t *testing.T) {
	fl := &fakeLore{
		getRepositoryByNameFn: func(ctx context.Context, name string) (*modelv1.Repository, error) {
			return fakeRepo(name), nil
		},
		getBranchByNameFn: func(ctx context.Context, name string) (*modelv1.Branch, error) {
			return fakeBranch(name), nil
		},
		revisionTreeFn: func(ctx context.Context, branchID [16]byte, number uint64, pathPrefix string, maxDepth uint32) (*thin_clientv1.RevisionTreeHeader, []*thin_clientv1.TreeNode, error) {
			return nil, []*thin_clientv1.TreeNode{
				{Path: "src", NodeType: thin_clientv1.NodeType_DIRECTORY},
			}, nil
		},
		queryLocksFn: func(ctx context.Context, branchID [16]byte) ([]*gen.Lock, error) {
			return nil, nil
		},
	}
	h, _ := newTestHandler(t, fl)

	// subPath="" → branch root listing, no "*" param needed.
	r := newRequest(t, "GET", "/-/myrepo/src/branch/main/", nil, defaultIdentity,
		"owner", "-", "repo", "myrepo", "branch", "main", "*", "")
	w := httptest.NewRecorder()
	h.Tree(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Tree root: want 200, got %d; body=%.200s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "src") {
		t.Errorf("Tree root: body does not contain dir name %q", "src")
	}
}

// ─── Commits ─────────────────────────────────────────────────────────────────

func TestCommitsHappyPath(t *testing.T) {
	sig := []byte{0xab, 0xcd, 0xef}
	fl := &fakeLore{
		getRepositoryByNameFn: func(ctx context.Context, name string) (*modelv1.Repository, error) {
			return fakeRepo(name), nil
		},
		getBranchByNameFn: func(ctx context.Context, name string) (*modelv1.Branch, error) {
			return fakeBranch(name), nil
		},
		listRevisionsFn: func(ctx context.Context, branchID [16]byte, cursor []byte) ([]*modelv1.RevisionItem, []byte, []byte, error) {
			return []*modelv1.RevisionItem{
				{Signature: sig},
			}, nil, nil, nil
		},
		revisionInfoBySignatureFn: func(ctx context.Context, signature []byte) (*thin_clientv1.Revision, error) {
			return &thin_clientv1.Revision{
				CommitMessage: "initial commit",
				CreatedBy:     "alice",
				Timestamp:     1_700_000_000_000,
			}, nil
		},
	}
	h, _ := newTestHandler(t, fl)

	r := newRequest(t, "GET", "/-/myrepo/commits/branch/main", nil, defaultIdentity,
		"owner", "-", "repo", "myrepo", "branch", "main")
	w := httptest.NewRecorder()
	h.Commits(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Commits: want 200, got %d; body=%.200s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "initial commit") {
		t.Errorf("Commits: body does not contain commit message")
	}
}

// ─── Commit ──────────────────────────────────────────────────────────────────

func TestCommitHappyPath(t *testing.T) {
	sig := []byte{0x01, 0x02, 0x03, 0x04}
	sigHex := hex.EncodeToString(sig)

	fl := &fakeLore{
		getRepositoryByNameFn: func(ctx context.Context, name string) (*modelv1.Repository, error) {
			return fakeRepo(name), nil
		},
		revisionInfoBySignatureFn: func(ctx context.Context, signature []byte) (*thin_clientv1.Revision, error) {
			return &thin_clientv1.Revision{
				CommitMessage: "feat: add thing",
				CreatedBy:     "bob",
				Timestamp:     1_700_000_000_000,
			}, nil
		},
		revisionDiffFn: func(ctx context.Context, signatureFrom, signatureTo []byte) (*thin_clientv1.RevisionDiffHeader, []lore.RevisionDiffEntry, error) {
			return nil, nil, nil
		},
	}
	h, _ := newTestHandler(t, fl)

	r := newRequest(t, "GET", "/-/myrepo/commit/"+sigHex, nil, defaultIdentity,
		"owner", "-", "repo", "myrepo", "sig", sigHex)
	w := httptest.NewRecorder()
	h.Commit(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Commit: want 200, got %d; body=%.200s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "feat: add thing") {
		t.Errorf("Commit: body does not contain commit message; body=%.300s", w.Body.String())
	}
}

// TestCommitDiffFailureDegrades checks that a RevisionDiff error renders 200
// (commit header shown) rather than a 500.
func TestCommitDiffFailureDegrades(t *testing.T) {
	sig := []byte{0x11, 0x22, 0x33, 0x44}
	sigHex := hex.EncodeToString(sig)

	fl := &fakeLore{
		getRepositoryByNameFn: func(ctx context.Context, name string) (*modelv1.Repository, error) {
			return fakeRepo(name), nil
		},
		revisionInfoBySignatureFn: func(ctx context.Context, signature []byte) (*thin_clientv1.Revision, error) {
			return &thin_clientv1.Revision{
				CommitMessage: "graceful degrade test",
				CreatedBy:     "carol",
			}, nil
		},
		revisionDiffFn: func(ctx context.Context, signatureFrom, signatureTo []byte) (*thin_clientv1.RevisionDiffHeader, []lore.RevisionDiffEntry, error) {
			return nil, nil, errors.New("diff backend unavailable")
		},
	}
	h, _ := newTestHandler(t, fl)

	r := newRequest(t, "GET", "/-/myrepo/commit/"+sigHex, nil, defaultIdentity,
		"owner", "-", "repo", "myrepo", "sig", sigHex)
	w := httptest.NewRecorder()
	h.Commit(w, r)

	// Must not 500; the handler degrades to header-only and returns 200.
	if w.Code != http.StatusOK {
		t.Fatalf("Commit diff-failure: want 200 (graceful degrade), got %d", w.Code)
	}
}

// ─── Locks ───────────────────────────────────────────────────────────────────

func TestLocksHappyPath(t *testing.T) {
	branchBytes := []byte{0xaa, 0xbb}
	hashBytes := []byte{0xcc, 0xdd}

	fl := &fakeLore{
		getRepositoryByNameFn: func(ctx context.Context, name string) (*modelv1.Repository, error) {
			return fakeRepo(name), nil
		},
		getBranchByNameFn: func(ctx context.Context, name string) (*modelv1.Branch, error) {
			return fakeBranch(name), nil
		},
		queryLocksFn: func(ctx context.Context, branchID [16]byte) ([]*gen.Lock, error) {
			return []*gen.Lock{
				{
					Resource: &gen.Resource{
						Branch:      branchBytes,
						Hash:        hashBytes,
						Description: "Assets/Textures/Hero.png",
					},
					Owner: "dave",
				},
			}, nil
		},
	}
	h, _ := newTestHandler(t, fl)

	r := newRequest(t, "GET", "/-/myrepo/locks/branch/main", nil, defaultIdentity,
		"owner", "-", "repo", "myrepo", "branch", "main")
	w := httptest.NewRecorder()
	h.Locks(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Locks: want 200, got %d; body=%.200s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "Assets/Textures/Hero.png") {
		t.Errorf("Locks: body does not contain lock path; body=%.300s", body)
	}
	// The release form must be present (action POST to .../release).
	if !strings.Contains(body, "release") {
		t.Errorf("Locks: body does not contain release form/action")
	}
}

// ─── ReleaseLock ─────────────────────────────────────────────────────────────

func TestReleaseLockCallsUnlock(t *testing.T) {
	branchBytes := []byte{0x01, 0x02, 0x03}
	hashBytes := []byte{0x04, 0x05, 0x06}
	description := "Source/Thing.cpp"

	var capturedResources []*gen.Resource
	fl := &fakeLore{
		getRepositoryByNameFn: func(ctx context.Context, name string) (*modelv1.Repository, error) {
			return fakeRepo(name), nil
		},
		unlockFn: func(ctx context.Context, token string, repoID [16]byte, resources []*gen.Resource) error {
			capturedResources = resources
			return nil
		},
	}
	h, _ := newTestHandler(t, fl)

	form := url.Values{
		"branch":      {hex.EncodeToString(branchBytes)},
		"hash":        {hex.EncodeToString(hashBytes)},
		"description": {description},
	}
	r := newRequest(t, "POST", "/-/myrepo/locks/branch/main/release",
		strings.NewReader(form.Encode()), defaultIdentity,
		"owner", "-", "repo", "myrepo", "branch", "main")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	h.ReleaseLock(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("ReleaseLock: want 303 redirect, got %d", w.Code)
	}
	if capturedResources == nil {
		t.Fatal("ReleaseLock: Unlock was not called")
	}
	res := capturedResources[0]
	if string(res.GetBranch()) != string(branchBytes) {
		t.Errorf("ReleaseLock: Branch mismatch: got %v, want %v", res.GetBranch(), branchBytes)
	}
	if string(res.GetHash()) != string(hashBytes) {
		t.Errorf("ReleaseLock: Hash mismatch: got %v, want %v", res.GetHash(), hashBytes)
	}
	if res.GetDescription() != description {
		t.Errorf("ReleaseLock: Description mismatch: got %q, want %q", res.GetDescription(), description)
	}
	// Redirect must go to the locks page (no ?err=).
	loc := w.Header().Get("Location")
	if strings.Contains(loc, "err=") {
		t.Errorf("ReleaseLock: redirect contains error: %s", loc)
	}
}

// TestReleaseLockBadHexRedirectsWithErr verifies that an invalid hex branch
// value redirects with ?err= and does NOT call Unlock.
func TestReleaseLockBadHexRedirectsWithErr(t *testing.T) {
	unlockCalled := false
	fl := &fakeLore{
		getRepositoryByNameFn: func(ctx context.Context, name string) (*modelv1.Repository, error) {
			return fakeRepo(name), nil
		},
		unlockFn: func(ctx context.Context, token string, repoID [16]byte, resources []*gen.Resource) error {
			unlockCalled = true
			return nil
		},
	}
	h, _ := newTestHandler(t, fl)

	form := url.Values{
		"branch":      {"not-valid-hex!!"},
		"hash":        {"aabbcc"},
		"description": {"foo/bar.cpp"},
	}
	r := newRequest(t, "POST", "/-/myrepo/locks/branch/main/release",
		strings.NewReader(form.Encode()), defaultIdentity,
		"owner", "-", "repo", "myrepo", "branch", "main")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	h.ReleaseLock(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("ReleaseLock bad-hex: want 303, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "err=") {
		t.Errorf("ReleaseLock bad-hex: want ?err= in redirect, got Location=%s", loc)
	}
	if unlockCalled {
		t.Error("ReleaseLock bad-hex: Unlock must not be called on invalid input")
	}
}
