package config

import (
	"testing"
)

// TestValidate checks the cross-field invariants enforced by Validate.
func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "auth enabled with mgmt addr — ok",
			cfg: Config{
				AuthDisabled: false,
				MgmtAPIAddr:  "http://authhost:8080",
			},
			wantErr: false,
		},
		{
			name: "auth disabled with empty mgmt addr — ok",
			cfg: Config{
				AuthDisabled: true,
				MgmtAPIAddr:  "",
			},
			wantErr: false,
		},
		{
			name: "auth disabled with mgmt addr — ok",
			cfg: Config{
				AuthDisabled: true,
				MgmtAPIAddr:  "http://authhost:8080",
			},
			wantErr: false,
		},
		{
			name: "auth enabled with empty mgmt addr — error",
			cfg: Config{
				AuthDisabled: false,
				MgmtAPIAddr:  "",
			},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("Validate: expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Validate: unexpected error: %v", err)
			}
		})
	}
}

// TestLoad checks that Load parses required env vars and populates fields.
// Do NOT use t.Parallel() here — t.Setenv modifies the process environment.
func TestLoad(t *testing.T) {
	t.Run("missing required fields yields error", func(t *testing.T) {
		// Clear the two required vars in case they are set in the environment.
		t.Setenv("LORE_GRPC_ADDR", "")
		t.Setenv("LORE_HTTP_ADDR", "")
		_, err := Load()
		if err == nil {
			t.Fatal("Load: expected error when required fields are missing, got nil")
		}
	})

	t.Run("required fields present with auth disabled", func(t *testing.T) {
		t.Setenv("LORE_GRPC_ADDR", "localhost:41337")
		t.Setenv("LORE_HTTP_ADDR", "http://localhost:41339")
		t.Setenv("LORE_AUTH_DISABLED", "true")
		// Clear MGMT_API_ADDR so auth-disabled path has no mgmt addr.
		t.Setenv("MGMT_API_ADDR", "")

		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: unexpected error: %v", err)
		}
		if cfg.LoreGRPCAddr != "localhost:41337" {
			t.Errorf("LoreGRPCAddr = %q, want %q", cfg.LoreGRPCAddr, "localhost:41337")
		}
		if cfg.LoreHTTPAddr != "http://localhost:41339" {
			t.Errorf("LoreHTTPAddr = %q, want %q", cfg.LoreHTTPAddr, "http://localhost:41339")
		}
		if !cfg.AuthDisabled {
			t.Error("AuthDisabled should be true")
		}
	})

	t.Run("required fields present with auth enabled and mgmt addr", func(t *testing.T) {
		t.Setenv("LORE_GRPC_ADDR", "localhost:41337")
		t.Setenv("LORE_HTTP_ADDR", "http://localhost:41339")
		t.Setenv("LORE_AUTH_DISABLED", "false")
		t.Setenv("MGMT_API_ADDR", "http://authhost:8080")

		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: unexpected error: %v", err)
		}
		if cfg.MgmtAPIAddr != "http://authhost:8080" {
			t.Errorf("MgmtAPIAddr = %q, want %q", cfg.MgmtAPIAddr, "http://authhost:8080")
		}
		if cfg.AuthDisabled {
			t.Error("AuthDisabled should be false")
		}
	})
}
