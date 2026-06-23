package lore

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// jwtSummary decodes (WITHOUT verifying) a JWT's header + payload and returns a
// one-line summary of the fields that matter for diagnosing a server-side
// KeyNotFound / audience / issuer rejection: the signing key id and algorithm
// from the header, and iss/aud/sub/exp plus any resource claims from the
// payload. It never returns the signature and never logs the raw token.
//
// This exists purely for the LORE_AUTH_DEBUG diagnostic path. A malformed token
// yields a best-effort summary rather than an error.
func jwtSummary(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return fmt.Sprintf("<not a JWT: %d segments>", len(parts))
	}

	header := decodeJWTSegment(parts[0])
	payload := decodeJWTSegment(parts[1])

	kid, _ := header["kid"].(string)
	alg, _ := header["alg"].(string)
	iss, _ := payload["iss"].(string)
	sub, _ := payload["sub"].(string)

	aud := jwtAudience(payload["aud"])
	res := jwtResources(payload)

	exp := ""
	if v, ok := payload["exp"].(float64); ok {
		exp = fmt.Sprintf("%d", int64(v))
	}

	redactedSub := sub
	if len(sub) > 8 {
		redactedSub = sub[:8] + "…"
	}

	return fmt.Sprintf("kid=%q alg=%q iss=%q aud=%q sub=%q exp=%s resources=%s",
		kid, alg, iss, aud, redactedSub, exp, res)
}

func decodeJWTSegment(seg string) map[string]any {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		// Some encoders pad; try standard URL encoding too.
		raw, err = base64.URLEncoding.DecodeString(seg)
		if err != nil {
			return map[string]any{}
		}
	}
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}

func jwtAudience(aud any) string {
	switch v := aud.(type) {
	case string:
		return v
	case []any:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ",")
	default:
		return ""
	}
}

// jwtResources renders any resource/permission-style claim the token carries, so
// we can see whether the exchanged token actually gained a "urc-*" grant.
func jwtResources(payload map[string]any) string {
	for _, key := range []string{"resources", "resource", "permissions", "scope"} {
		if v, ok := payload[key]; ok {
			b, err := json.Marshal(v)
			if err == nil {
				return string(b)
			}
		}
	}
	return "<none>"
}
