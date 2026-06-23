package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

// loadOrGenerateKey loads an RSA-2048 private key from keyPath.
// If the file does not exist it generates a new key and writes it.
func loadOrGenerateKey(keyPath string) (*rsa.PrivateKey, error) {
	if _, err := os.Stat(keyPath); errors.Is(err, os.ErrNotExist) {
		return generateAndSaveKey(keyPath)
	}
	return loadKey(keyPath)
}

func generateAndSaveKey(keyPath string) (*rsa.PrivateKey, error) {
	fmt.Fprintf(os.Stderr, "[arc-lore-auth] generating new RSA-2048 key → %s\n", keyPath)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating RSA key: %w", err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshaling PKCS8: %w", err)
	}

	block := &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}

	dir := filepath.Dir(keyPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("creating key dir %s: %w", dir, err)
	}

	f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, fmt.Errorf("creating key file %s: %w", keyPath, err)
	}
	defer f.Close()

	if err := pem.Encode(f, block); err != nil {
		return nil, fmt.Errorf("writing PEM key: %w", err)
	}

	return priv, nil
}

func loadKey(keyPath string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading key file %s: %w", keyPath, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("key file %s contains no PEM block", keyPath)
	}

	raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing PKCS8 key: %w", err)
	}

	priv, ok := raw.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key file %s does not contain an RSA private key", keyPath)
	}

	return priv, nil
}

// keyID returns a stable kid = lowercase hex of SHA-256 over the DER-encoded
// SubjectPublicKeyInfo (PKIX) of the public key.
func keyID(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshaling public key to DER: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// buildJWKSet builds a jwk.Set containing the RSA public key with the correct
// kid, alg=RS256, use=sig. Uses lestrrat-go/jwx/v2/jwk — never hand-rolls n/e.
func buildJWKSet(priv *rsa.PrivateKey, kid string) (jwk.Set, error) {
	key, err := jwk.FromRaw(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("jwk.FromRaw: %w", err)
	}

	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, fmt.Errorf("setting kid: %w", err)
	}
	if err := key.Set(jwk.AlgorithmKey, "RS256"); err != nil {
		return nil, fmt.Errorf("setting alg: %w", err)
	}
	if err := key.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return nil, fmt.Errorf("setting use: %w", err)
	}

	set := jwk.NewSet()
	if err := set.AddKey(key); err != nil {
		return nil, fmt.Errorf("adding key to set: %w", err)
	}

	return set, nil
}

// marshalJWKSet serialises a jwk.Set to JSON.
// The JSON shape is: {"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"...","n":"...","e":"..."}]}
func marshalJWKSet(set jwk.Set) ([]byte, error) {
	data, err := json.Marshal(set)
	if err != nil {
		return nil, fmt.Errorf("json.Marshal JWKS: %w", err)
	}
	return data, nil
}

// ── TLS cert for the gRPC listener ─────────────────────────────────────────────
//
// This keypair is DISTINCT from the RSA JWT signing key (loadOrGenerateKey):
//   - the JWT signing key signs/verifies tokens (served via JWKS);
//   - this TLS keypair only secures the gRPC transport (h2 over TLS).
// Two separate keys by design — never reuse one for the other.

const tlsCertValidity = 825 * 24 * time.Hour // ~825 days; the CA/Browser-Forum max for leaf certs.

// loadOrGenerateTLSCert returns a tls.Certificate for the gRPC listener.
//
// If both certPath and keyPath exist, they are loaded verbatim. Otherwise a
// self-signed cert is generated for `san` (an IP literal → IPAddresses, else a
// DNS name → DNSNames), persisted to the configured paths, and a trust-install
// hint is printed. The cert is its own issuer (self-signed) so it can be
// installed directly into a Trusted Root store.
//
// Returns the parsed certificate, whether a new cert was generated, and the
// path the cert PEM lives at (for the install hint).
func loadOrGenerateTLSCert(certPath, keyPath, san string) (tls.Certificate, bool, string, error) {
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	certExists := certErr == nil
	keyExists := keyErr == nil

	if certExists && keyExists {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return tls.Certificate{}, false, certPath, fmt.Errorf("loading TLS keypair (%s / %s): %w", certPath, keyPath, err)
		}
		return cert, false, certPath, nil
	}
	if certExists != keyExists {
		return tls.Certificate{}, false, certPath, fmt.Errorf(
			"TLS cert/key are half-present (cert=%t key=%t): supply BOTH %s and %s, or neither (to auto-generate)",
			certExists, keyExists, certPath, keyPath)
	}

	cert, err := generateAndSaveTLSCert(certPath, keyPath, san)
	if err != nil {
		return tls.Certificate{}, false, certPath, err
	}
	return cert, true, certPath, nil
}

func generateAndSaveTLSCert(certPath, keyPath, san string) (tls.Certificate, error) {
	if san == "" {
		return tls.Certificate{}, errors.New("tls_san is required to generate a self-signed cert (must equal the auth_url host)")
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generating TLS key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generating serial number: %w", err)
	}

	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: san},
		NotBefore:    now.Add(-1 * time.Hour), // small backdate for clock skew
		NotAfter:     now.Add(tlsCertValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// Self-signed end-entity cert: IsCA=false so rustls/webpki accepts it as a
		// leaf (CA:TRUE triggers CaUsedAsEndEntity in webpki). BasicConstraintsValid=true
		// ensures the Basic Constraints extension is present with CA=false — an explicit
		// non-CA assertion. Still self-signed so it can be installed as a trust anchor.
		IsCA:                  false,
		BasicConstraintsValid: true,
	}

	// (S3) SAN type must match the host kind: native-roots verification rejects
	// a DNS-typed SAN when the client connects to an IP literal, and vice versa.
	if ip := net.ParseIP(san); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{san}
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("creating self-signed certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshaling TLS PKCS8 key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})

	if err := writeFileWithDir(certPath, certPEM, 0644); err != nil {
		return tls.Certificate{}, fmt.Errorf("writing TLS cert %s: %w", certPath, err)
	}
	if err := writeFileWithDir(keyPath, keyPEM, 0600); err != nil {
		return tls.Certificate{}, fmt.Errorf("writing TLS key %s: %w", keyPath, err)
	}

	fmt.Fprintf(os.Stderr, "[arc-lore-auth] generated self-signed TLS cert for SAN %q → %s (valid until %s)\n",
		san, certPath, tmpl.NotAfter.Format(time.RFC3339))

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parsing generated TLS keypair: %w", err)
	}
	return cert, nil
}

func writeFileWithDir(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating dir %s: %w", dir, err)
	}
	return os.WriteFile(path, data, perm)
}
