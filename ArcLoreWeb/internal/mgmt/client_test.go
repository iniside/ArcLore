package mgmt

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestStatusHappyPath verifies that Status sends GET /api/status and decodes
// the JSON response into StatusResp correctly.
func TestStatusHappyPath(t *testing.T) {
	wantResp := StatusResp{HasUsers: true, RegistrationOpen: false}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("Status: want GET, got %s", r.Method)
		}
		if r.URL.Path != "/api/status" {
			t.Errorf("Status: want path /api/status, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(wantResp); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	defer srv.Close()

	client := New(srv.URL, 5*time.Second)
	got, err := client.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: unexpected error: %v", err)
	}
	if got.HasUsers != wantResp.HasUsers {
		t.Errorf("HasUsers = %v, want %v", got.HasUsers, wantResp.HasUsers)
	}
	if got.RegistrationOpen != wantResp.RegistrationOpen {
		t.Errorf("RegistrationOpen = %v, want %v", got.RegistrationOpen, wantResp.RegistrationOpen)
	}
}

// TestStatusErrorPath verifies that a 4xx response from the server causes
// Status to return an *APIError carrying the status code.
func TestStatusErrorPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		if _, err := w.Write([]byte(`{"error":"not authorized"}`)); err != nil {
			t.Errorf("write error body: %v", err)
		}
	}))
	defer srv.Close()

	client := New(srv.URL, 5*time.Second)
	_, err := client.Status(context.Background())
	if err == nil {
		t.Fatal("Status: expected error on 401, got nil")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("Status: want *APIError, got %T: %v", err, err)
	}
	if apiErr.Status != http.StatusUnauthorized {
		t.Errorf("APIError.Status = %d, want %d", apiErr.Status, http.StatusUnauthorized)
	}
	if !strings.Contains(apiErr.Message, "not authorized") {
		t.Errorf("APIError.Message = %q, want it to contain %q", apiErr.Message, "not authorized")
	}
}

// TestLoginSendsCredentials verifies that Login POSTs to /api/login with the
// username and password in the JSON body, and decodes a successful AuthResp.
func TestLoginSendsCredentials(t *testing.T) {
	const wantUser = "alice"
	const wantPass = "s3cr3t"
	wantResp := AuthResp{Token: "tok-abc", UserID: "alice", IsAdmin: true, ExpiresAt: 9999}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Login: want POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/login" {
			t.Errorf("Login: want path /api/login, got %s", r.URL.Path)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("Login: decode body: %v", err)
		}
		if body["username"] != wantUser {
			t.Errorf("Login: username = %q, want %q", body["username"], wantUser)
		}
		if body["password"] != wantPass {
			t.Errorf("Login: password = %q, want %q", body["password"], wantPass)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(wantResp); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	defer srv.Close()

	client := New(srv.URL, 5*time.Second)
	got, err := client.Login(context.Background(), wantUser, wantPass)
	if err != nil {
		t.Fatalf("Login: unexpected error: %v", err)
	}
	if got.Token != wantResp.Token {
		t.Errorf("Token = %q, want %q", got.Token, wantResp.Token)
	}
	if got.IsAdmin != wantResp.IsAdmin {
		t.Errorf("IsAdmin = %v, want %v", got.IsAdmin, wantResp.IsAdmin)
	}
}

// TestLoginError401 verifies that Login returns an *APIError with Status 401
// when the server returns Unauthorized.
func TestLoginError401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		if _, err := w.Write([]byte(`{"error":"wrong password"}`)); err != nil {
			t.Errorf("write error body: %v", err)
		}
	}))
	defer srv.Close()

	client := New(srv.URL, 5*time.Second)
	_, err := client.Login(context.Background(), "alice", "wrongpass")
	if err == nil {
		t.Fatal("Login: expected error on 401, got nil")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("Login: want *APIError, got %T: %v", err, err)
	}
	if apiErr.Status != http.StatusUnauthorized {
		t.Errorf("APIError.Status = %d, want 401", apiErr.Status)
	}
}

// TestNewTrimsTrailingSlash verifies that New strips the trailing slash from
// base so paths join without a double-slash.
func TestNewTrimsTrailingSlash(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(StatusResp{}); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	defer srv.Close()

	client := New(srv.URL+"/", 5*time.Second)
	if _, err := client.Status(context.Background()); err != nil {
		t.Fatalf("Status: %v", err)
	}
	if gotPath != "/api/status" {
		t.Errorf("path = %q, want /api/status (trailing slash on base should not produce double-slash)", gotPath)
	}
}
