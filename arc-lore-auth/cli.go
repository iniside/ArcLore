package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

// ── subcommand: mint ──────────────────────────────────────────────────────────

func runMintCmd(configPath, audienceOverride string, args []string) {
	fs := flag.NewFlagSet("mint", flag.ExitOnError)
	user := fs.String("user", "", "username to embed in the token (required)")
	out := fs.String("out", "", "write token to this file instead of stdout")
	aud := fs.String("audience", "", "override audience (lore-server host domain)")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "mint: %v\n", err)
		os.Exit(1)
	}

	if *user == "" {
		fmt.Fprintln(os.Stderr, "mint: --user is required")
		os.Exit(1)
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mint: config: %v\n", err)
		os.Exit(1)
	}
	// sub-flag overrides global flag overrides config
	if *aud != "" {
		audienceOverride = *aud
	}
	if audienceOverride != "" {
		cfg.Audience = audienceOverride
	}
	if cfg.Audience == "" {
		fmt.Fprintln(os.Stderr, "mint: audience is required (set in config.toml or via -audience flag)")
		os.Exit(1)
	}

	priv, err := loadOrGenerateKey(cfg.KeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mint: key: %v\n", err)
		os.Exit(1)
	}

	kid, err := keyID(&priv.PublicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mint: kid: %v\n", err)
		os.Exit(1)
	}

	token, err := mintToken(cfg, priv, kid, *user)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mint: %v\n", err)
		os.Exit(1)
	}

	if *out != "" {
		if err := os.WriteFile(*out, []byte(token), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "mint: writing output file: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "token written to %s\n", *out)
		return
	}

	fmt.Println(token)
}

// ── subcommand: print-jwks ────────────────────────────────────────────────────

func runPrintJWKSCmd(configPath, audienceOverride string) {
	cfg, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "print-jwks: config: %v\n", err)
		os.Exit(1)
	}
	if audienceOverride != "" {
		cfg.Audience = audienceOverride
	}

	priv, err := loadOrGenerateKey(cfg.KeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "print-jwks: key: %v\n", err)
		os.Exit(1)
	}

	kid, err := keyID(&priv.PublicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "print-jwks: kid: %v\n", err)
		os.Exit(1)
	}

	set, err := buildJWKSet(priv, kid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "print-jwks: %v\n", err)
		os.Exit(1)
	}

	jwksJSON, err := marshalJWKSet(set)
	if err != nil {
		fmt.Fprintf(os.Stderr, "print-jwks: marshal: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(jwksJSON))
}

// ── subcommand: useradd ───────────────────────────────────────────────────────

func runUserAddCmd(configPath string, args []string) {
	fs := flag.NewFlagSet("useradd", flag.ExitOnError)
	displayName := fs.String("display-name", "", "optional display name (defaults to the username)")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "useradd: %v\n", err)
		os.Exit(1)
	}

	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "useradd: usage: arc-lore-auth useradd [--display-name <name>] <username>")
		os.Exit(1)
	}
	username := rest[0]

	cfg, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "useradd: config: %v\n", err)
		os.Exit(1)
	}

	pw, err := promptPasswordTwice()
	if err != nil {
		fmt.Fprintf(os.Stderr, "useradd: %v\n", err)
		os.Exit(1)
	}

	store, err := OpenStore(cfg.DBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "useradd: opening db: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = store.Close() }()

	hash, err := HashPassword(pw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "useradd: hashing password: %v\n", err)
		os.Exit(1)
	}
	if err := store.AddUser(username, *displayName, hash, false); err != nil {
		fmt.Fprintf(os.Stderr, "useradd: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stdout, "created user %q in %s\n", normalizeUsername(username), cfg.DBPath)
}

// ── subcommand: userlist ──────────────────────────────────────────────────────

func runUserListCmd(configPath string) {
	cfg, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "userlist: config: %v\n", err)
		os.Exit(1)
	}

	store, err := OpenStore(cfg.DBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "userlist: opening db: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = store.Close() }()

	users, err := store.ListUsers()
	if err != nil {
		fmt.Fprintf(os.Stderr, "userlist: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stdout, "%-24s %-24s %-6s %s\n", "USERNAME", "DISPLAY", "ADMIN", "CREATED")
	for _, u := range users {
		admin := "no"
		if u.IsAdmin {
			admin = "yes"
		}
		created := ""
		if u.Created != 0 {
			created = time.Unix(u.Created, 0).UTC().Format("2006-01-02 15:04 UTC")
		}
		fmt.Fprintf(os.Stdout, "%-24s %-24s %-6s %s\n", u.Username, u.DisplayName, admin, created)
	}
}

// ── subcommand: userdel ───────────────────────────────────────────────────────

func runUserDelCmd(configPath string, args []string) {
	fs := flag.NewFlagSet("userdel", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "userdel: %v\n", err)
		os.Exit(1)
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "userdel: usage: arc-lore-auth userdel <username>")
		os.Exit(1)
	}
	username := rest[0]

	cfg, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "userdel: config: %v\n", err)
		os.Exit(1)
	}

	store, err := OpenStore(cfg.DBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "userdel: opening db: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = store.Close() }()

	if err := store.DeleteUser(username); err != nil {
		fmt.Fprintf(os.Stderr, "userdel: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, "deleted user %q from %s\n", normalizeUsername(username), cfg.DBPath)
}

// ── subcommand: setpw ─────────────────────────────────────────────────────────

func runSetPwCmd(configPath string, args []string) {
	fs := flag.NewFlagSet("setpw", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "setpw: %v\n", err)
		os.Exit(1)
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "setpw: usage: arc-lore-auth setpw <username>")
		os.Exit(1)
	}
	username := rest[0]

	cfg, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "setpw: config: %v\n", err)
		os.Exit(1)
	}

	pw, err := promptPasswordTwice()
	if err != nil {
		fmt.Fprintf(os.Stderr, "setpw: %v\n", err)
		os.Exit(1)
	}

	store, err := OpenStore(cfg.DBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "setpw: opening db: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = store.Close() }()

	hash, err := HashPassword(pw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "setpw: hashing password: %v\n", err)
		os.Exit(1)
	}
	if err := store.SetPassword(username, hash); err != nil {
		fmt.Fprintf(os.Stderr, "setpw: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, "updated password for %q in %s\n", normalizeUsername(username), cfg.DBPath)
}
