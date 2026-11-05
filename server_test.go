package main

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testServer(t *testing.T) *server {
	t.Helper()
	s, err := newServerAt(filepath.Join(t.TempDir(), "totally_not_my_privateKeys.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.store.Close() })
	return s
}
func TestJWKSAndValidJWT(t *testing.T) {
	s := testServer(t)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	var body jwksResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Keys) == 0 {
		t.Fatal("missing public keys")
	}
	for _, j := range body.Keys {
		if j.Kty != "RSA" || j.Alg != "RS256" || j.Use != "sig" {
			t.Fatalf("bad JWK: %+v", j)
		}
	}
	auth := httptest.NewRecorder()
	s.routes().ServeHTTP(auth, httptest.NewRequest(http.MethodPost, "/auth", strings.NewReader(`{"username":"userABC","password":"password123"}`)))
	if auth.Code != 200 {
		t.Fatal(auth.Code, auth.Body.String())
	}
	parts := splitJWT(auth.Body.String())
	if len(parts) != 3 {
		t.Fatal("bad JWT parts")
	}
	var header map[string]string
	if err := decodeSegment(parts[0], &header); err != nil {
		t.Fatal(err)
	}
	var claims jwtClaims
	if err := decodeSegment(parts[1], &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Exp <= time.Now().Unix() {
		t.Fatal("JWT should be valid")
	}
	found := false
	for _, j := range body.Keys {
		if j.Kid == header["kid"] {
			pub, err := rsaPublicKeyFromJWK(j)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyJWT(auth.Body.String(), pub); err != nil {
				t.Fatal(err)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("token kid missing from JWKS")
	}
}
func TestExpiredAuth(t *testing.T) {
	s := testServer(t)
	for _, path := range []string{"/auth?expired", "/auth?expired=true"} {
		rec := httptest.NewRecorder()
		s.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
		if rec.Code != 200 {
			t.Fatal(rec.Code, rec.Body.String())
		}
		var claims jwtClaims
		if err := decodeSegment(splitJWT(rec.Body.String())[1], &claims); err != nil {
			t.Fatal(err)
		}
		if claims.Exp > time.Now().Unix() {
			t.Fatal("expected expired token")
		}
	}
}
func TestDatabasePersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "totally_not_my_privateKeys.db")
	s1, err := newServerAt(path)
	if err != nil {
		t.Fatal(err)
	}
	a, err := s1.store.listValid(time.Now().Unix())
	if err != nil || len(a) == 0 {
		t.Fatal(err)
	}
	originalKid := a[0].Kid
	s1.store.Close()
	s2, err := newServerAt(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.store.Close()
	b, err := s2.store.listValid(time.Now().Unix())
	if err != nil || len(b) == 0 {
		t.Fatal(err)
	}
	if b[0].Kid != originalKid {
		t.Fatal("key not persisted")
	}
}
func TestMethodsAndMalformedInput(t *testing.T) {
	s := testServer(t)
	for _, path := range []string{"/auth", "/.well-known/jwks.json"} {
		method := http.MethodGet
		if path != "/auth" {
			method = http.MethodPost
		}
		rec := httptest.NewRecorder()
		s.routes().ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		if rec.Code != 405 {
			t.Fatalf("expected 405 for %s", path)
		}
	}
	if err := verifyJWT("invalid", &rsa.PublicKey{}); err == nil {
		t.Fatal("invalid token accepted")
	}
	if _, err := rsaPublicKeyFromJWK(jwk{N: "***", E: "AQAB"}); err == nil {
		t.Fatal("bad modulus accepted")
	}
	if _, err := rsaPublicKeyFromJWK(jwk{N: "AQ", E: ""}); err == nil {
		t.Fatal("bad exponent accepted")
	}
}
func TestStoreErrorsAndEmptyResults(t *testing.T) {
	s := testServer(t)
	future := time.Now().Add(100 * 365 * 24 * time.Hour).Unix()
	valid, err := s.store.listValid(future)
	if err != nil || len(valid) != 0 {
		t.Fatal(err, len(valid))
	}
	if _, err := s.store.findKey(future, false); err == nil {
		t.Fatal("expected missing key error")
	}
	expired, err := s.store.findKey(future, true)
	if err != nil || expired.PrivateKey == nil {
		t.Fatal(err)
	}
	if _, err := s.store.decodeRow(1, []byte("bad"), 0); err == nil {
		t.Fatal("expected PEM parsing error")
	}
}
func TestGenerateAndHelpers(t *testing.T) {
	key, err := generateSigningKey(time.Now().Add(time.Hour))
	if err != nil || key.PrivateKey == nil {
		t.Fatal(err)
	}
	token, err := signJWT(key, jwtClaims{Sub: "test", Iat: time.Now().Unix(), Exp: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyJWT(token, &key.PrivateKey.PublicKey); err != nil {
		t.Fatal(err)
	}
}

func TestAdditionalDatabaseErrors(t *testing.T) {
	s := testServer(t)

	invalidPEM := []byte("-----BEGIN RSA PRIVATE KEY-----\nZm9v\n-----END RSA PRIVATE KEY-----")
	if _, err := s.store.decodeRow(1, invalidPEM, 0); err == nil {
		t.Fatal("expected invalid RSA key error")
	}

	if err := s.store.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := s.store.listValid(time.Now().Unix()); err == nil {
		t.Fatal("expected database query error")
	}

	if err := s.store.ensureKeys(time.Now()); err == nil {
		t.Fatal("expected database initialization error")
	}

	if _, err := s.store.findKey(time.Now().Unix(), false); err == nil {
		t.Fatal("expected database lookup error")
	}

	for _, path := range []string{"/auth", "/.well-known/jwks.json"} {
		method := http.MethodGet
		if path == "/auth" {
			method = http.MethodPost
		}
		rec := httptest.NewRecorder()
		s.routes().ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("%s: expected 500, got %d", path, rec.Code)
		}
	}
}
