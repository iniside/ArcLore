package lore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	gen "arcloreweb/gen"
	environmentv1 "arcloreweb/gen/lore/environment/v1"
	modelv1 "arcloreweb/gen/lore/model/v1"
	repositoryv1 "arcloreweb/gen/lore/repository/v1"
	revisionv1 "arcloreweb/gen/lore/revision/v1"
	thin_clientv1 "arcloreweb/gen/lore/thin_client/v1"
)

// Client is a typed read-only wrapper over the Lore gRPC services plus the HTTP
// blob endpoint. It is safe for concurrent use. Every read method takes a
// context that already carries the per-call auth (token + repoID) via
// WithLoreCall — the gRPC interceptors and FetchContent read it back out.
type Client struct {
	conn *grpc.ClientConn

	repos        repositoryv1.RepositoryServiceClient
	revisions    revisionv1.RevisionServiceClient
	thin         thin_clientv1.ThinClientServiceClient
	locks        gen.LockServiceClient
	environments environmentv1.EnvironmentServiceClient

	httpClient  *http.Client
	httpBaseURL string
	timeout     time.Duration

	// grpcHost is the bare host:port the gRPC conn dials, with any "scheme://"
	// prefix already stripped by splitScheme. Surfaced via GRPCHost() so the UI
	// can build a clean "lore://host:port/name" without a doubled scheme.
	grpcHost string

	// Auth-service connection (lazily dialed) and the resolved/overridden auth
	// URL. The auth conn is separate from the main conn and carries NO lore
	// -bin interceptors — only the Bearer identity. Guarded by authMu.
	authMu          sync.Mutex
	authConn        *grpc.ClientConn
	authClient      gen.UrcAuthApiClient
	authURL         string // discovered via GetEnvironment, cached
	authURLOverride string // config override (e.g. LORE_AUTH_URL); wins over discovery

	// Per-resource authorization-token cache, keyed by the resource string
	// (e.g. "urc-*" or "urc-"+hex(repoID)). Guarded by authzMu.
	authzMu    sync.Mutex
	authzCache map[string]authzEntry

	// exchangeFn performs the identity→authz exchange for a resource string;
	// defaults to ExchangeResource and is overridable in tests. clock is the
	// injectable clock backing nowMs (nil → time.Now).
	exchangeFn func(ctx context.Context, identityToken string, resource string) (string, int64, error)
	clock      func() time.Time
}

// Dial connects to a Lore server. grpcAddr may carry a scheme:
//
//   - "…s://" (e.g. "grpcs://host:443") → TLS credentials.
//   - any other scheme ("grpc://", "http://", "lore://") or no scheme →
//     plaintext (insecure) credentials.
//
// The scheme is stripped before dialing. httpBaseURL is the base for the HTTP
// blob endpoint (e.g. "http://host:41339"); timeout is the per-call deadline
// applied by every read method.
func Dial(grpcAddr, httpBaseURL string, timeout time.Duration) (*Client, error) {
	target, useTLS := splitScheme(grpcAddr)

	var creds credentials.TransportCredentials
	if useTLS {
		creds = credentials.NewTLS(nil)
	} else {
		creds = insecure.NewCredentials()
	}

	conn, err := grpc.NewClient(
		target,
		grpc.WithTransportCredentials(creds),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    30 * time.Second,
			Timeout: 20 * time.Second,
		}),
		grpc.WithChainUnaryInterceptor(unaryAuthInterceptor),
		grpc.WithChainStreamInterceptor(streamAuthInterceptor),
	)
	if err != nil {
		return nil, fmt.Errorf("lore: dial %q: %w", target, err)
	}

	c := &Client{
		conn:         conn,
		repos:        repositoryv1.NewRepositoryServiceClient(conn),
		revisions:    revisionv1.NewRevisionServiceClient(conn),
		thin:         thin_clientv1.NewThinClientServiceClient(conn),
		locks:        gen.NewLockServiceClient(conn),
		environments: environmentv1.NewEnvironmentServiceClient(conn),
		httpClient:   &http.Client{},
		httpBaseURL:  strings.TrimRight(httpBaseURL, "/"),
		timeout:      timeout,
		grpcHost:     target,
		authzCache:   make(map[string]authzEntry),
	}
	c.exchangeFn = c.ExchangeResource
	return c, nil
}

// GRPCHost returns the bare "host:port" the client dials, with any "scheme://"
// prefix stripped (no trailing slash). Use this to build "lore://host/name"
// URLs in the UI rather than the raw configured address, which may carry a
// scheme that would otherwise double up (e.g. "lore://http://…").
func (c *Client) GRPCHost() string { return c.grpcHost }

// splitScheme strips a "scheme://" prefix from addr and reports whether the
// scheme requested TLS (a trailing 's', e.g. "grpcs"/"https"). A bare host:port
// with no scheme is plaintext.
func splitScheme(addr string) (target string, useTLS bool) {
	idx := strings.Index(addr, "://")
	if idx < 0 {
		return addr, false
	}
	scheme := addr[:idx]
	return addr[idx+len("://"):], strings.HasSuffix(scheme, "s")
}

// Close tears down the underlying gRPC connection plus the auth conn if it was
// lazily dialed. The main-conn error is returned; an auth-conn close error is
// only surfaced when the main conn closed cleanly.
func (c *Client) Close() error {
	mainErr := c.conn.Close()

	c.authMu.Lock()
	authConn := c.authConn
	c.authConn = nil
	c.authClient = nil
	c.authMu.Unlock()

	if authConn != nil {
		if authErr := authConn.Close(); authErr != nil && mainErr == nil {
			return authErr
		}
	}
	return mainErr
}

// ListRepositories drains the RepositoryList server-stream into a slice.
func (c *Client) ListRepositories(ctx context.Context) ([]*modelv1.Repository, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	stream, err := c.repos.RepositoryList(ctx, &repositoryv1.RepositoryListRequest{})
	if err != nil {
		return nil, fmt.Errorf("lore: RepositoryList: %w", err)
	}

	out := make([]*modelv1.Repository, 0)
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, fmt.Errorf("lore: RepositoryList recv: %w", err)
		}
		if msg.Repository != nil {
			out = append(out, msg.Repository)
		}
	}
}

// GetRepositoryByName looks up a single repository by its (globally unique)
// name.
func (c *Client) GetRepositoryByName(ctx context.Context, name string) (*modelv1.Repository, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.repos.RepositoryGet(ctx, &repositoryv1.RepositoryGetRequest{
		Query: &repositoryv1.RepositoryGetRequest_Name{Name: name},
	})
	if err != nil {
		return nil, fmt.Errorf("lore: RepositoryGet(name=%q): %w", name, err)
	}
	return resp.Repository, nil
}

// GetBranchByName looks up a single branch by its name within the repository
// that is already scoped on ctx via WithLoreCall.
func (c *Client) GetBranchByName(ctx context.Context, name string) (*modelv1.Branch, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.revisions.BranchGet(ctx, &revisionv1.BranchGetRequest{
		Query: &revisionv1.BranchGetRequest_Name{Name: name},
	})
	if err != nil {
		return nil, fmt.Errorf("lore: BranchGet(name=%q): %w", name, err)
	}
	return resp.Branch, nil
}

// ListBranches drains the BranchList server-stream into a slice. The repository
// scope comes from the ctx (WithLoreCall); only live branches are returned.
func (c *Client) ListBranches(ctx context.Context) ([]*modelv1.Branch, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	stream, err := c.revisions.BranchList(ctx, &revisionv1.BranchListRequest{})
	if err != nil {
		return nil, fmt.Errorf("lore: BranchList: %w", err)
	}

	out := make([]*modelv1.Branch, 0)
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, fmt.Errorf("lore: BranchList recv: %w", err)
		}
		if msg.Branch != nil {
			out = append(out, msg.Branch)
		}
	}
}

// ListRevisions pages a branch's history (newest→oldest). When cursor is nil
// the page anchors at the branch tip (identifier{branch_id, number:0});
// otherwise cursor is fed back as the signature anchor. It returns the page
// items plus the forward/backward cursors (signature_forward/backward) — feed
// either back as cursor to page.
func (c *Client) ListRevisions(
	ctx context.Context,
	branchID [16]byte,
	cursor []byte,
) (items []*modelv1.RevisionItem, forward, backward []byte, err error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	req := &revisionv1.RevisionListRequest{}
	if cursor == nil {
		req.Start = &revisionv1.RevisionListRequest_Identifier{
			Identifier: &modelv1.RevisionIdentifier{
				BranchId: branchID[:],
				Number:   0,
			},
		}
	} else {
		req.Start = &revisionv1.RevisionListRequest_Signature{Signature: cursor}
	}

	resp, err := c.revisions.RevisionList(ctx, req)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("lore: RevisionList: %w", err)
	}
	return resp.Items, resp.GetSignatureForward(), resp.GetSignatureBackward(), nil
}

// RevisionInfoBySignature returns the full Revision record for a signature.
func (c *Client) RevisionInfoBySignature(ctx context.Context, signature []byte) (*thin_clientv1.Revision, error) {
	return c.revisionInfo(ctx, &thin_clientv1.RevisionInfoRequest{
		Query: &thin_clientv1.RevisionInfoRequest_Signature{Signature: signature},
	})
}

// RevisionInfoByIdentifier returns the full Revision record for a (branch,
// number) identifier; number==0 resolves to the branch tip.
func (c *Client) RevisionInfoByIdentifier(ctx context.Context, branchID [16]byte, number uint64) (*thin_clientv1.Revision, error) {
	return c.revisionInfo(ctx, &thin_clientv1.RevisionInfoRequest{
		Query: &thin_clientv1.RevisionInfoRequest_Identifier{
			Identifier: &modelv1.RevisionIdentifier{BranchId: branchID[:], Number: number},
		},
	})
}

func (c *Client) revisionInfo(ctx context.Context, req *thin_clientv1.RevisionInfoRequest) (*thin_clientv1.Revision, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.thin.RevisionInfo(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("lore: RevisionInfo: %w", err)
	}
	return resp.Revision, nil
}

// RevisionTree walks the file/directory tree at a revision and drains the
// stream into the resolved header plus the tree nodes. pathPrefix limits the
// walk to a subtree (empty = whole tree); maxDepth limits descent (0 =
// unbounded). number==0 in the identifier resolves to the branch tip.
func (c *Client) RevisionTree(
	ctx context.Context,
	branchID [16]byte,
	number uint64,
	pathPrefix string,
	maxDepth uint32,
) (*thin_clientv1.RevisionTreeHeader, []*thin_clientv1.TreeNode, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	req := &thin_clientv1.RevisionTreeRequest{
		Query: &thin_clientv1.RevisionTreeRequest_Identifier{
			Identifier: &modelv1.RevisionIdentifier{BranchId: branchID[:], Number: number},
		},
	}
	if pathPrefix != "" {
		req.PathPrefix = &pathPrefix
	}
	if maxDepth != 0 {
		req.MaxDepth = &maxDepth
	}

	stream, err := c.thin.RevisionTree(ctx, req)
	if err != nil {
		return nil, nil, fmt.Errorf("lore: RevisionTree: %w", err)
	}
	header, nodes, err := drainRevisionTree(stream)
	if err != nil {
		return header, nodes, fmt.Errorf("lore: RevisionTree drain: %w", err)
	}
	return header, nodes, nil
}

// RevisionDiff streams the per-path change list between two revision
// signatures (from→to) and drains it into the header plus the change/conflict
// entries. Each DiffChange carries content_from/content_to addresses used for
// RevisionTree-based address recovery to fetch file content for diffing.
func (c *Client) RevisionDiff(
	ctx context.Context,
	signatureFrom, signatureTo []byte,
) (*thin_clientv1.RevisionDiffHeader, []revisionDiffEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	req := &thin_clientv1.RevisionDiffRequest{
		QueryFrom: &thin_clientv1.RevisionDiffRequest_SignatureFrom{SignatureFrom: signatureFrom},
		QueryTo:   &thin_clientv1.RevisionDiffRequest_SignatureTo{SignatureTo: signatureTo},
	}

	stream, err := c.thin.RevisionDiff(ctx, req)
	if err != nil {
		return nil, nil, fmt.Errorf("lore: RevisionDiff: %w", err)
	}
	header, entries, err := drainRevisionDiff(stream)
	if err != nil {
		return header, entries, fmt.Errorf("lore: RevisionDiff drain: %w", err)
	}
	return header, entries, nil
}

// QueryLocks returns the locks held on a branch. resource.description on each
// returned lock is the repo-relative file path (the tree overlay key).
func (c *Client) QueryLocks(ctx context.Context, branchID [16]byte) ([]*gen.Lock, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.locks.Query(ctx, &gen.QueryRequest{Branch: branchID[:]})
	if err != nil {
		return nil, fmt.Errorf("lore: lock Query: %w", err)
	}
	return resp.Result, nil
}
