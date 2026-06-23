package main

// store.go — SQLite-backed identity/registry/grant store (replaces the JSON
// UserStore in users.go). Pure-Go driver (modernc.org/sqlite, driver name
// "sqlite") so the binary cross-compiles with CGO disabled. Schema migrations
// are embedded and applied with goose on Open.
//
// ──────────────────────────────────────────────────────────────────────────────
// ARGON2 / DB-ORDERING SECURITY INVARIANT (MANDATORY):
//
// We NEVER call argon2.IDKey (i.e. HashPassword / VerifyPassword) while holding
// the single SQLite connection. A slow ~64 MiB hash must not block gRPC lookups
// that are queued behind the one DB conn (SetMaxOpenConns(1)).
//
// Enforcement:
//   - Store methods that PERSIST a hash take a PRE-COMPUTED PHC string (`pwHash`)
//     as input. The caller computes HashPassword OUTSIDE any Store call (inside
//     the HTTP layer's argon2 semaphore).
//   - Verification is split: VerifyHash(username) does the DB read and returns
//     the stored PHC string with the conn released; the CALLER then runs
//     VerifyPassword(hash, pw) on its own (inside withHashSem). No Store method
//     ever derives a hash.
// ──────────────────────────────────────────────────────────────────────────────

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var embedMigrations embed.FS

// Store is the SQLite-backed user/resource/grant store. A single *sql.DB with
// SetMaxOpenConns(1) serializes all writers (and readers), which is what makes
// CreateFirstAdmin's count==0 check race-safe.
type Store struct {
	db *sql.DB
}

// StoreInterface is the full public method set of *Store. Dependency holders
// (authServer.users, authGRPCServer.store, rebacGRPCServer.store) and the
// effectiveResources helper depend on this interface rather than the concrete
// *Store, so unit tests can inject a fake store. *Store is still the concrete
// value constructed and passed at wiring time (see OpenStore in main.go) — this
// is a pure-widening seam, not a behavior change.
type StoreInterface interface {
	Close() error
	AddUser(username, displayName, pwHash string, isAdmin bool) error
	ImportLegacyUser(username, displayName, argon2id string, created, updated int64, isAdmin bool) error
	GetUser(username string) (User, error)
	SetPassword(username, pwHash string) error
	DeleteUser(username string) error
	ListUsers() ([]User, error)
	HasUsers() (bool, error)
	VerifyHash(username string) (string, error)
	CreateFirstAdmin(username, displayName, pwHash string) (bool, error)
	UpsertResource(resourceID, name string) (bool, error)
	DeleteResource(resourceID string) error
	AddGrant(username, resourceID, permission string) error
	GrantOwner(username, resourceID string) error
	ListResources() ([]Resource, error)
	GrantsFor(username string) (map[string][]string, error)
	FindByDisplayName(name string) (User, bool, error)
	RemoveGrant(username, resourceID, permission string) error
	SetAdmin(username string, isAdmin bool) error
	RegistrationOpen() (bool, error)
	CountAdmins() (int, error)
	GetConfig(key string) (string, bool, error)
	SetConfig(key, value string) error
	SetRegistrationOpen(open bool) error
}

// Compile-time assertion that *Store satisfies StoreInterface.
var _ StoreInterface = (*Store)(nil)

// OpenStore opens (or creates) the SQLite database at dbPath, applies pragmas,
// caps the pool at one connection, and runs all embedded goose migrations.
func OpenStore(dbPath string) (*Store, error) {
	dsn := "file:" + dbPath +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(ON)" +
		"&_pragma=synchronous(NORMAL)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite db %s: %w", dbPath, err)
	}
	// Single-writer: serializes all access through one connection so the
	// in-tx COUNT==0 first-admin check cannot race a concurrent insert.
	db.SetMaxOpenConns(1)

	goose.SetBaseFS(embedMigrations)
	// "sqlite3" is goose's DDL dialect string; it is correct for the modernc
	// "sqlite" driver (the dialect only governs the emitted migration SQL).
	if err := goose.SetDialect("sqlite3"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("setting goose dialect: %w", err)
	}
	if err := goose.Up(db, "migrations"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("running migrations on %s: %w", dbPath, err)
	}

	return &Store{db: db}, nil
}

// Close releases the underlying database handle.
func (s *Store) Close() error {
	return s.db.Close()
}

// isUniqueViolation reports whether err is a SQLite UNIQUE/PRIMARY-KEY conflict.
// modernc surfaces these as a textual "UNIQUE constraint failed" error.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") ||
		strings.Contains(msg, "PRIMARY KEY constraint failed")
}

// AddUser inserts a new user. `pwHash` is a PRE-COMPUTED argon2id PHC string —
// this method NEVER derives a hash (see the argon2/DB-ordering invariant above).
// On a username conflict it returns ErrUserExists.
func (s *Store) AddUser(username, displayName, pwHash string, isAdmin bool) error {
	norm, err := validateUsername(username)
	if err != nil {
		return err
	}
	if strings.TrimSpace(displayName) == "" {
		displayName = norm
	}
	now := time.Now().Unix()
	admin := 0
	if isAdmin {
		admin = 1
	}

	_, err = s.db.Exec(
		`INSERT INTO users (username, display_name, argon2id, is_admin, created, updated)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		norm, displayName, pwHash, admin, now, now,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: %s", ErrUserExists, norm)
		}
		return fmt.Errorf("inserting user %s: %w", norm, err)
	}
	return nil
}

// ImportLegacyUser inserts a user while preserving the original argon2id hash and
// created/updated timestamps (used for the one-shot users.json import). On a
// username conflict it returns ErrUserExists.
func (s *Store) ImportLegacyUser(username, displayName, argon2id string, created, updated int64, isAdmin bool) error {
	norm, err := validateUsername(username)
	if err != nil {
		return err
	}
	if strings.TrimSpace(displayName) == "" {
		displayName = norm
	}
	admin := 0
	if isAdmin {
		admin = 1
	}

	_, err = s.db.Exec(
		`INSERT INTO users (username, display_name, argon2id, is_admin, created, updated)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		norm, displayName, argon2id, admin, created, updated,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: %s", ErrUserExists, norm)
		}
		return fmt.Errorf("importing user %s: %w", norm, err)
	}
	return nil
}

// GetUser returns the full user row (including Argon2id + IsAdmin) for username.
// Returns ErrUserNotFound if there is no such user.
func (s *Store) GetUser(username string) (User, error) {
	norm := normalizeUsername(username)
	if norm == "" {
		return User{}, ErrUserNotFound
	}

	var u User
	var admin int
	err := s.db.QueryRow(
		`SELECT username, display_name, argon2id, is_admin, token_version, created, updated
		 FROM users WHERE username = ?`,
		norm,
	).Scan(&u.Username, &u.DisplayName, &u.Argon2id, &admin, &u.TokenVersion, &u.Created, &u.Updated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, fmt.Errorf("%w: %s", ErrUserNotFound, norm)
		}
		return User{}, fmt.Errorf("querying user %s: %w", norm, err)
	}
	u.IsAdmin = admin != 0
	return u, nil
}

// SetPassword replaces the stored hash for an existing user. `pwHash` is a
// PRE-COMPUTED argon2id PHC string — this method NEVER derives a hash (see the
// argon2/DB-ordering invariant above). Returns ErrUserNotFound if absent.
func (s *Store) SetPassword(username, pwHash string) error {
	norm, err := validateUsername(username)
	if err != nil {
		return err
	}
	now := time.Now().Unix()

	res, err := s.db.Exec(
		`UPDATE users SET argon2id = ?, updated = ?, token_version = token_version + 1 WHERE username = ?`,
		pwHash, now, norm,
	)
	if err != nil {
		return fmt.Errorf("updating password for %s: %w", norm, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("reading rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("%w: %s", ErrUserNotFound, norm)
	}
	return nil
}

// DeleteUser removes a user (and, via ON DELETE CASCADE, its grants). Returns
// ErrUserNotFound if absent.
func (s *Store) DeleteUser(username string) error {
	norm, err := validateUsername(username)
	if err != nil {
		return err
	}

	res, err := s.db.Exec(`DELETE FROM users WHERE username = ?`, norm)
	if err != nil {
		return fmt.Errorf("deleting user %s: %w", norm, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("reading rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("%w: %s", ErrUserNotFound, norm)
	}
	return nil
}

// ListUsers returns all users ordered by username, with the Argon2id field
// BLANKED (callers outside this package never need the hash).
func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.db.Query(
		`SELECT username, display_name, is_admin, token_version, created, updated
		 FROM users ORDER BY username`,
	)
	if err != nil {
		return nil, fmt.Errorf("listing users: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]User, 0)
	for rows.Next() {
		var u User
		var admin int
		if err := rows.Scan(&u.Username, &u.DisplayName, &admin, &u.TokenVersion, &u.Created, &u.Updated); err != nil {
			return nil, fmt.Errorf("scanning user row: %w", err)
		}
		u.IsAdmin = admin != 0
		u.Argon2id = "" // never surface the hash
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating user rows: %w", err)
	}
	return out, nil
}

// HasUsers reports whether at least one user row exists.
func (s *Store) HasUsers() (bool, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return false, fmt.Errorf("counting users: %w", err)
	}
	return n > 0, nil
}

// VerifyHash returns the stored argon2id PHC string for username so the CALLER
// can compute+compare the hash OUTSIDE any open connection/tx (the argon2/DB
// ordering invariant). Returns ErrUserNotFound (and an empty string) for an
// unknown user.
//
// This method does NOT verify the password — it deliberately hands the hash back
// so VerifyPassword runs in the caller's argon2 semaphore, never under the DB
// conn.
func (s *Store) VerifyHash(username string) (string, error) {
	norm := normalizeUsername(username)
	if norm == "" {
		return "", ErrUserNotFound
	}

	var hash string
	err := s.db.QueryRow(
		`SELECT argon2id FROM users WHERE username = ?`, norm,
	).Scan(&hash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("%w: %s", ErrUserNotFound, norm)
		}
		return "", fmt.Errorf("reading hash for %s: %w", norm, err)
	}
	return hash, nil
}

// CreateFirstAdmin atomically creates the very first user as an admin and closes
// registration, but ONLY if no users exist yet. `pwHash` is a PRE-COMPUTED
// argon2id PHC string (no hashing under the tx).
//
// Returns (true, nil) if this call created the first admin; (false, nil) if a
// user already existed (this call did nothing). The whole thing runs in ONE
// transaction over the single connection, so two concurrent calls serialize and
// exactly one wins the COUNT==0 check.
func (s *Store) CreateFirstAdmin(username, displayName, pwHash string) (bool, error) {
	norm, err := validateUsername(username)
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(displayName) == "" {
		displayName = norm
	}

	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("beginning first-admin tx: %w", err)
	}
	// Rolled back unless we Commit first (post-commit rollback is a no-op).
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return false, fmt.Errorf("counting users in first-admin tx: %w", err)
	}
	if n != 0 {
		// A user already exists — do nothing, leave the existing rows untouched.
		return false, nil
	}

	now := time.Now().Unix()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO users (username, display_name, argon2id, is_admin, created, updated)
		 VALUES (?, ?, ?, 1, ?, ?)`,
		norm, displayName, pwHash, now, now,
	); err != nil {
		return false, fmt.Errorf("inserting first admin %s: %w", norm, err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT OR REPLACE INTO config (key, value) VALUES ('registration_open', 'false')`,
	); err != nil {
		return false, fmt.Errorf("closing registration: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("committing first-admin tx: %w", err)
	}
	committed = true
	return true, nil
}

// ── resources & grants (repo registry) ───────────────────────────────────────

// UpsertResource inserts the resource row for resourceID, or — if it already
// exists — refreshes its name. It returns existed=true when a row was already
// present (the RebacApi.CreateResource handler maps that to lore's
// "ALREADY_EXISTS is success" contract). The created timestamp is only set on
// first insert; a re-upsert leaves it untouched.
func (s *Store) UpsertResource(resourceID, name string) (bool, error) {
	id := strings.TrimSpace(resourceID)
	if id == "" {
		return false, errors.New("resource_id must not be empty")
	}
	now := time.Now().Unix()

	// INSERT … ON CONFLICT updates the name and reports which path ran via the
	// `created` value: on a fresh insert it equals `now`; on conflict it keeps
	// the original (older) created, so created != now ⇒ existed. We read it back
	// rather than rely on RowsAffected (which is 1 for both insert and update).
	var storedCreated int64
	err := s.db.QueryRow(
		`INSERT INTO resources (resource_id, name, created)
		 VALUES (?, ?, ?)
		 ON CONFLICT(resource_id) DO UPDATE SET name = excluded.name
		 RETURNING created`,
		id, name, now,
	).Scan(&storedCreated)
	if err != nil {
		return false, fmt.Errorf("upserting resource %s: %w", id, err)
	}
	return storedCreated != now, nil
}

// DeleteResource removes the resource row for resourceID. ON DELETE CASCADE
// clears its grants. An absent resource is NOT an error — the delete is
// idempotent (lore maps NOT_FOUND→INTERNAL, so the handler must return OK for an
// already-absent resource).
func (s *Store) DeleteResource(resourceID string) error {
	id := strings.TrimSpace(resourceID)
	if id == "" {
		return errors.New("resource_id must not be empty")
	}
	if _, err := s.db.Exec(`DELETE FROM resources WHERE resource_id = ?`, id); err != nil {
		return fmt.Errorf("deleting resource %s: %w", id, err)
	}
	return nil
}

// AddGrant grants `permission` to `username` on `resourceID`. It is idempotent
// (INSERT OR IGNORE on the composite PK). foreign_keys are ON, so both the user
// and the resource row must already exist (grant AFTER UpsertResource).
func (s *Store) AddGrant(username, resourceID, permission string) error {
	norm := normalizeUsername(username)
	if norm == "" {
		return ErrUserNotFound
	}
	id := strings.TrimSpace(resourceID)
	if id == "" {
		return errors.New("resource_id must not be empty")
	}
	perm := strings.TrimSpace(permission)
	if perm == "" {
		return errors.New("permission must not be empty")
	}
	if _, err := s.db.Exec(
		`INSERT OR IGNORE INTO grants (username, resource_id, permission)
		 VALUES (?, ?, ?)`,
		norm, id, perm,
	); err != nil {
		return fmt.Errorf("granting %s on %s to %s: %w", perm, id, norm, err)
	}
	return nil
}

// GrantOwner grants the creator-default permission set (owner, read, write) to
// `username` on `resourceID` — three idempotent rows. The resource row must
// already exist (foreign_keys ON), so call this AFTER UpsertResource.
func (s *Store) GrantOwner(username, resourceID string) error {
	for _, perm := range []string{"owner", "read", "write"} {
		if err := s.AddGrant(username, resourceID, perm); err != nil {
			return err
		}
	}
	return nil
}

// Resource is a registered repository row (resource_id + display name + created).
type Resource struct {
	ResourceID string
	Name       string
	Created    int64
}

// ListResources returns every registered resource ordered by resource_id. The
// returned slice is non-nil (possibly empty). effectiveResources uses the
// ORDER BY to keep an admin's per-repo entries deterministic.
func (s *Store) ListResources() ([]Resource, error) {
	rows, err := s.db.Query(`SELECT resource_id, name, created FROM resources ORDER BY resource_id`)
	if err != nil {
		return nil, fmt.Errorf("listing resources: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]Resource, 0)
	for rows.Next() {
		var r Resource
		if err := rows.Scan(&r.ResourceID, &r.Name, &r.Created); err != nil {
			return nil, fmt.Errorf("scanning resource row: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating resource rows: %w", err)
	}
	return out, nil
}

// GrantsFor returns all grants for username as resource_id -> permissions. The
// ORDER BY (resource_id, permission) makes the per-resource permission slices
// deterministic; the returned map is non-nil (empty for a user with no grants).
// An unknown user is NOT an error — it yields an empty map.
func (s *Store) GrantsFor(username string) (map[string][]string, error) {
	norm := normalizeUsername(username)
	out := make(map[string][]string)
	if norm == "" {
		return out, nil
	}

	rows, err := s.db.Query(
		`SELECT resource_id, permission FROM grants
		 WHERE username = ? ORDER BY resource_id, permission`,
		norm,
	)
	if err != nil {
		return nil, fmt.Errorf("listing grants for %s: %w", norm, err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var resourceID, permission string
		if err := rows.Scan(&resourceID, &permission); err != nil {
			return nil, fmt.Errorf("scanning grant row: %w", err)
		}
		out[resourceID] = append(out[resourceID], permission)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating grant rows: %w", err)
	}
	return out, nil
}

// FindByDisplayName scans all users for one whose DisplayName OR Username matches
// name (case-insensitive). Returns (user, true, nil) on a match; (zero, false,
// nil) when no user matches; (zero, false, non-nil) on a DB error.
// Performs a full-table scan (small N; no index needed here).
func (s *Store) FindByDisplayName(name string) (User, bool, error) {
	needle := strings.ToLower(strings.TrimSpace(name))
	if needle == "" {
		return User{}, false, nil
	}

	users, err := s.ListUsers()
	if err != nil {
		return User{}, false, err
	}
	for _, u := range users {
		if strings.ToLower(u.DisplayName) == needle || strings.ToLower(u.Username) == needle {
			return u, true, nil
		}
	}
	return User{}, false, nil
}

// RemoveGrant revokes `permission` from `username` on `resourceID`. It is
// idempotent: an absent grant row is NOT an error (mirrors DeleteResource's
// tolerance — no RowsAffected check).
func (s *Store) RemoveGrant(username, resourceID, permission string) error {
	norm := normalizeUsername(username)
	id := strings.TrimSpace(resourceID)
	perm := strings.TrimSpace(permission)
	if _, err := s.db.Exec(
		`DELETE FROM grants WHERE username = ? AND resource_id = ? AND permission = ?`,
		norm, id, perm,
	); err != nil {
		return fmt.Errorf("revoking %s on %s from %s: %w", perm, id, norm, err)
	}
	return nil
}

// SetAdmin flips the is_admin flag for an existing user. Returns ErrUserNotFound
// if no row matches.
func (s *Store) SetAdmin(username string, isAdmin bool) error {
	norm, err := validateUsername(username)
	if err != nil {
		return err
	}
	admin := 0
	if isAdmin {
		admin = 1
	}
	now := time.Now().Unix()

	res, err := s.db.Exec(
		`UPDATE users SET is_admin = ?, updated = ?, token_version = token_version + 1 WHERE username = ?`,
		admin, now, norm,
	)
	if err != nil {
		return fmt.Errorf("updating admin flag for %s: %w", norm, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("reading rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("%w: %s", ErrUserNotFound, norm)
	}
	return nil
}

// RegistrationOpen reports whether self-registration is open. The migration does
// NOT seed the `registration_open` config key, so an ABSENT key DEFAULTS TO FALSE
// (closed); this closes the self-registration window before the first admin is
// created. CreateFirstAdmin explicitly writes "false" once the first admin exists.
// Only the exact value "true" reads as open; anything else is closed.
func (s *Store) RegistrationOpen() (bool, error) {
	value, present, err := s.GetConfig("registration_open")
	if err != nil {
		return false, err
	}
	if !present {
		return false, nil
	}
	return value == "true", nil
}

// CountAdmins returns the number of users with the is_admin flag set.
func (s *Store) CountAdmins() (int, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE is_admin = 1`).Scan(&n); err != nil {
		return 0, fmt.Errorf("counting admins: %w", err)
	}
	return n, nil
}

// GetConfig returns the config value for key, and whether it was present.
func (s *Store) GetConfig(key string) (string, bool, error) {
	var value string
	err := s.db.QueryRow(`SELECT value FROM config WHERE key = ?`, key).Scan(&value)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("reading config %s: %w", key, err)
	}
	return value, true, nil
}

// SetConfig writes (inserts or replaces) the config value for key. Mirrors the
// inline INSERT OR REPLACE that CreateFirstAdmin uses for registration_open.
func (s *Store) SetConfig(key, value string) error {
	if _, err := s.db.Exec(
		`INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)`,
		key, value,
	); err != nil {
		return fmt.Errorf("writing config %s: %w", key, err)
	}
	return nil
}

// SetRegistrationOpen toggles self-registration by writing the registration_open
// config key ("true" / "false"). Only the exact value "true" reads as open (see
// RegistrationOpen).
func (s *Store) SetRegistrationOpen(open bool) error {
	value := "false"
	if open {
		value = "true"
	}
	return s.SetConfig("registration_open", value)
}
