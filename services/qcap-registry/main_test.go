package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestPublishRequiresBearerTokenWhenConfigured(t *testing.T) {
	dir := t.TempDir()
	reg := &Registry{
		StoreDir:  dir,
		IndexPath: filepath.Join(dir, "index.json"),
		Token:     "secret",
	}

	req := httptest.NewRequest(http.MethodPost, "/artifacts", bytes.NewReader([]byte("qcap")))
	req.Header.Set("X-Qcap-Name", "demo.qcap")
	rec := httptest.NewRecorder()
	reg.publish(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized, got %d", rec.Code)
	}
	if _, err := os.Stat(filepath.Join(dir, "demo.qcap")); !os.IsNotExist(err) {
		t.Fatalf("artifact should not be written without auth")
	}
}

func TestPublishPersistsIndex(t *testing.T) {
	dir := t.TempDir()
	reg := &Registry{
		StoreDir:  dir,
		IndexPath: filepath.Join(dir, "index.json"),
		Token:     "secret",
	}

	req := httptest.NewRequest(http.MethodPost, "/artifacts", bytes.NewReader([]byte("qcap")))
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("X-Qcap-Name", "demo.qcap")
	rec := httptest.NewRecorder()
	reg.publish(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected created, got %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "demo.qcap")); err != nil {
		t.Fatalf("artifact not written: %v", err)
	}

	var persisted []Capsule
	bytes, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		t.Fatalf("index not written: %v", err)
	}
	if err := json.Unmarshal(bytes, &persisted); err != nil {
		t.Fatalf("index invalid JSON: %v", err)
	}
	if len(persisted) != 1 {
		t.Fatalf("expected one capsule, got %d", len(persisted))
	}
	if persisted[0].Name != "demo.qcap" {
		t.Fatalf("unexpected capsule name: %s", persisted[0].Name)
	}
	if persisted[0].Digest == "" || persisted[0].CreatedAt == "" {
		t.Fatalf("expected digest and created_at in persisted index: %+v", persisted[0])
	}
}

func TestPublishRevocationsRequiresBearerTokenWhenConfigured(t *testing.T) {
	dir := t.TempDir()
	reg := &Registry{
		StoreDir:  dir,
		IndexPath: filepath.Join(dir, "index.json"),
		Token:     "secret",
	}

	req := httptest.NewRequest(http.MethodPost, "/revocations/issuer/revocations.json", bytes.NewReader([]byte(`{"revoked":[]}`)))
	rec := httptest.NewRecorder()
	reg.revocations(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized, got %d", rec.Code)
	}
	if _, err := os.Stat(filepath.Join(dir, "revocations", "issuer", "revocations.json")); !os.IsNotExist(err) {
		t.Fatalf("revocations should not be written without auth")
	}
}

func TestPublishAndServeRevocationsByIssuer(t *testing.T) {
	dir := t.TempDir()
	reg := &Registry{
		StoreDir:  dir,
		IndexPath: filepath.Join(dir, "index.json"),
		Token:     "secret",
	}
	body := []byte(`{"schema_version":"0.1.0","revoked":[]}`)

	req := httptest.NewRequest(http.MethodPost, "/revocations/issuer-abc/revocations.json", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	reg.revocations(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected created, got %d: %s", rec.Code, rec.Body.String())
	}

	var doc RevocationDocument
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("response invalid JSON: %v", err)
	}
	if doc.Issuer != "issuer-abc" || doc.Path != "/revocations/issuer-abc/revocations.json" {
		t.Fatalf("unexpected revocation document: %+v", doc)
	}
	if doc.Digest == "" || doc.CreatedAt == "" {
		t.Fatalf("expected digest and created_at in response: %+v", doc)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/revocations/issuer-abc/revocations.json", nil)
	getRec := httptest.NewRecorder()
	reg.revocations(getRec, getReq)

	if getRec.Code != http.StatusOK {
		t.Fatalf("expected ok, got %d: %s", getRec.Code, getRec.Body.String())
	}
	if !bytes.Equal(getRec.Body.Bytes(), body) {
		t.Fatalf("served revocations changed: %s", getRec.Body.String())
	}
	if got := reg.revocationIssuerCount(); got != 1 {
		t.Fatalf("expected one revocation issuer, got %d", got)
	}
}
