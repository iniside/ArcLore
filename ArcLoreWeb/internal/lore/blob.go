package lore

import (
	"context"
	"fmt"
	"io"
	"net/http"

	modelv1 "arcloreweb/gen/lore/model/v1"
)

// MaxHighlightBytes is the size ceiling the handlers consult before buffering a
// blob for syntax highlighting. Lore is a binary-asset VCS, so blobs can be
// multi-GB; above this cap the handler offers a download instead. FetchContent
// itself does NOT buffer — it returns a streaming body.
const MaxHighlightBytes = 1 << 20 // 1 MiB

// FetchContent streams a blob's raw decompressed bytes from the Lore HTTP
// content endpoint:
//
//	GET {httpBaseURL}/v1/repository/{32hex repoID}/content/{97-char address}/
//
// (note the trailing slash). The server reassembles fragments and decompresses,
// so no client-side fragment/decompress logic is needed. The Authorization
// Bearer header is added only when the ctx carries a non-empty token.
//
// The returned io.ReadCloser is the streaming response body — the CALLER must
// close it. contentType and size come from the response Content-Type /
// Content-Length headers (size is -1 when the server omits Content-Length).
func (c *Client) FetchContent(
	ctx context.Context,
	repoID [16]byte,
	addr *modelv1.Address,
) (body io.ReadCloser, contentType string, size int64, err error) {
	addrStr, err := AddressString(addr)
	if err != nil {
		return nil, "", 0, err
	}

	url := fmt.Sprintf("%s/v1/repository/%s/content/%s/", c.httpBaseURL, IDToHex(repoID), addrStr)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", 0, fmt.Errorf("lore: build content request: %w", err)
	}

	if auth, ok := callAuthFromContext(ctx); ok && auth.token != "" {
		req.Header.Set("Authorization", "Bearer "+auth.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", 0, fmt.Errorf("lore: fetch content: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// Drain+close so the connection can be reused, then surface the status.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return nil, "", 0, fmt.Errorf("lore: content endpoint returned %s", resp.Status)
	}

	return resp.Body, resp.Header.Get("Content-Type"), resp.ContentLength, nil
}

// FetchContentBytes fetches a content blob into memory, capped. A nil/empty
// addr (the missing side of an ADD or DELETE) returns (nil, false, nil). The
// returned data is at most cap bytes; truncated is true when the blob exceeded
// cap (in which case data holds the first cap bytes).
//
// The HTTP body from FetchContent is always closed before returning — leaking
// it under a worker pool is a real bug.
func (c *Client) FetchContentBytes(
	ctx context.Context,
	repoID [16]byte,
	addr *modelv1.Address,
	cap int64,
) ([]byte, bool, error) {
	if addr == nil || (len(addr.GetHash()) == 0 && len(addr.GetContext()) == 0) {
		return nil, false, nil
	}

	body, _, _, err := c.FetchContent(ctx, repoID, addr)
	if err != nil {
		return nil, false, err
	}
	defer body.Close()

	read, err := io.ReadAll(io.LimitReader(body, cap+1))
	if err != nil {
		return nil, false, fmt.Errorf("lore: read content bytes: %w", err)
	}

	if int64(len(read)) > cap {
		return read[:cap], true, nil
	}
	return read, false, nil
}
