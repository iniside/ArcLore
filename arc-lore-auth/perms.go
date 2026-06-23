package main

// perms.go — effectiveResources is the SINGLE source of truth for the resource
// grants carried in a minted authz token and for LookupUserPermissions. It is
// FAIL-CLOSED: an unknown subject yields no resources (ok=false), never a
// wildcard. Admins get every registered repo concretely (with the FULL
// permission set) PLUS the urc-* wildcard; non-admins get exactly their granted
// rows and nothing more.
//
// The concrete entries carry the full set — read,write,owner,admin,obliterate,
// migrate — NOT just read,write,owner,admin. lore-server's privileged-op gates
// is_owner_or_admin and can_obliterate resolve via user_permissions, which
// exact-matches a repo id and so SILENTLY IGNORES the urc-* wildcard (it strips
// "urc-" → "*", which parses to a zero id). Anything an admin needs for an
// owner/admin/obliterate op must therefore live on the concrete per-repo entry,
// not the wildcard, or the op is denied even for an admin.

import (
	"errors"
	"sort"
)

// effectiveResources resolves the resource grants for username.
//
// Returns (entries, ok, err):
//   - ok=false, entries=nil: the user does not exist (FAIL CLOSED). Callers
//     must NOT mint a token for an unknown subject.
//   - ok=true: entries is the user's effective grant set (possibly empty for a
//     non-admin with zero grants — an empty, non-nil slice, NOT urc-*).
//
// Admin: one concrete entry per registered resource carrying the full repo
// permission set (read, write, owner, admin, obliterate, migrate), PLUS an
// always-present urc-* wildcard (read, write, migrate, obliterate) — even with
// zero resources. The concrete entry, not the wildcard, is what satisfies
// lore-server's wildcard-blind owner/admin/obliterate gates.
//
// Non-admin: one concrete entry per granted resource_id with its granted
// permissions; NO urc-* wildcard.
//
// Output ordering is deterministic: ListResources is ORDER BY resource_id;
// grant resource_ids are sorted; per-entry permission order comes from the
// grants ORDER BY (resource_id, permission).
func effectiveResources(store StoreInterface, username string) ([]ResourceEntry, bool, error) {
	u, err := store.GetUser(username)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, false, nil
		}
		return nil, false, err
	}

	if u.IsAdmin {
		resources, err := store.ListResources()
		if err != nil {
			return nil, false, err
		}
		entries := make([]ResourceEntry, 0, len(resources)+1)
		for _, r := range resources {
			entries = append(entries, ResourceEntry{
				ResourceID: r.ResourceID,
				Permission: []string{"read", "write", "owner", "admin", "obliterate", "migrate"},
			})
		}
		// Always append the wildcard last so an admin carries basic access to
		// every repo (including ones registered after this token was minted).
		entries = append(entries, ResourceEntry{
			ResourceID: "urc-*",
			Permission: []string{"read", "write", "migrate", "obliterate"},
		})
		return entries, true, nil
	}

	grants, err := store.GrantsFor(username)
	if err != nil {
		return nil, false, err
	}

	ids := make([]string, 0, len(grants))
	for id := range grants {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	entries := make([]ResourceEntry, 0, len(ids))
	for _, id := range ids {
		entries = append(entries, ResourceEntry{
			ResourceID: id,
			Permission: grants[id],
		})
	}
	return entries, true, nil
}
