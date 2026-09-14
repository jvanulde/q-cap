package main

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestPublishRequiresBearerTokenWhenConfigured(t *testing.T) {
	dir := t.TempDir()
	reg := &Registry{
		StoreDir:  dir,
		IndexPath: filepath.Join(dir, "index.json"),
		Token:     "secret",
	}

	req := httptest.NewRequest(http.MethodPost, "/artifacts", bytes.NewReader(validQcap(t, "first")))
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

	archive := validQcap(t, "first")
	req := httptest.NewRequest(http.MethodPost, "/artifacts", bytes.NewReader(archive))
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
	issuer, body := signedRevocations(t)

	req := httptest.NewRequest(http.MethodPost, "/revocations/"+issuer+"/revocations.json", bytes.NewReader(body))
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
	if doc.Issuer != issuer || doc.Path != "/revocations/"+issuer+"/revocations.json" {
		t.Fatalf("unexpected revocation document: %+v", doc)
	}
	if doc.Digest == "" || doc.CreatedAt == "" {
		t.Fatalf("expected digest and created_at in response: %+v", doc)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/revocations/"+issuer+"/revocations.json", nil)
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

func TestRegistryArtifactRoundTripAndRejectedOverwrite(t *testing.T) {
	dir := t.TempDir()
	reg := &Registry{
		StoreDir:  dir,
		IndexPath: filepath.Join(dir, "index.json"),
		Token:     "secret",
	}
	server := httptest.NewServer(reg.handler())
	defer server.Close()

	original := validQcap(t, "first")
	publishArtifact(t, server.URL, "demo.qcap", original, http.StatusCreated)

	response, err := http.Get(server.URL + "/index.json")
	if err != nil {
		t.Fatalf("get index: %v", err)
	}
	defer response.Body.Close()
	var index []Capsule
	if err := json.NewDecoder(response.Body).Decode(&index); err != nil {
		t.Fatalf("decode index: %v", err)
	}
	if len(index) != 1 || index[0].Name != "demo.qcap" {
		t.Fatalf("unexpected index: %+v", index)
	}

	fetched, err := http.Get(server.URL + "/artifacts/demo.qcap")
	if err != nil {
		t.Fatalf("fetch artifact: %v", err)
	}
	defer fetched.Body.Close()
	fetchedBytes, err := io.ReadAll(fetched.Body)
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	if !bytes.Equal(fetchedBytes, original) {
		t.Fatal("fetched artifact differs from published artifact")
	}

	publishArtifact(t, server.URL, "demo.qcap", []byte("not a zip"), http.StatusBadRequest)
	after, err := os.ReadFile(filepath.Join(dir, "demo.qcap"))
	if err != nil {
		t.Fatalf("read artifact after rejected overwrite: %v", err)
	}
	if !bytes.Equal(after, original) {
		t.Fatal("rejected upload changed the existing artifact")
	}
	assertNoTemporaryFiles(t, dir)
}

func TestPublishRejectsMalformedQcapWithoutPartialFile(t *testing.T) {
	dir := t.TempDir()
	reg := &Registry{StoreDir: dir, IndexPath: filepath.Join(dir, "index.json")}

	req := httptest.NewRequest(http.MethodPost, "/artifacts", strings.NewReader("not a zip"))
	req.Header.Set("X-Qcap-Name", "invalid.qcap")
	rec := httptest.NewRecorder()
	reg.publish(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request, got %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "invalid.qcap")); !os.IsNotExist(err) {
		t.Fatalf("invalid artifact should not exist")
	}
	assertNoTemporaryFiles(t, dir)
}

func TestPublishRejectsQcapWithInvalidManifestSignature(t *testing.T) {
	dir := t.TempDir()
	reg := &Registry{StoreDir: dir, IndexPath: filepath.Join(dir, "index.json")}

	req := httptest.NewRequest(http.MethodPost, "/artifacts", bytes.NewReader(qcapWithSignature(t, "data", false)))
	req.Header.Set("X-Qcap-Name", "invalid-signature.qcap")
	rec := httptest.NewRecorder()
	reg.publish(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request, got %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "invalid-signature.qcap")); !os.IsNotExist(err) {
		t.Fatalf("invalid artifact should not exist")
	}
	assertNoTemporaryFiles(t, dir)
}

func TestValidateQcapRejectsUnsafeArchivePath(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "unsafe.qcap")
	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	entry, err := writer.Create("../outside.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("unsafe")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := validateQcapArchive(archivePath); err == nil || !strings.Contains(err.Error(), "unsafe archive path") {
		t.Fatalf("expected unsafe path rejection, got %v", err)
	}
}

func TestSeedArchivesPassValidation(t *testing.T) {
	archives, err := filepath.Glob("seed/*.qcap")
	if err != nil {
		t.Fatal(err)
	}
	if len(archives) == 0 {
		t.Fatal("expected checked-in seed archives")
	}
	for _, archive := range archives {
		t.Run(filepath.Base(archive), func(t *testing.T) {
			if err := validateQcapArchive(archive); err != nil {
				t.Fatalf("seed archive failed validation: %v", err)
			}
		})
	}
}

func TestStageUploadRejectsOversizeAndRemovesTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	_, _, err := stageUpload(strings.NewReader("12345"), dir, 4)
	if err != errUploadTooLarge {
		t.Fatalf("expected oversize error, got %v", err)
	}
	assertNoTemporaryFiles(t, dir)
}

func TestConcurrentPublishesKeepIndexConsistent(t *testing.T) {
	dir := t.TempDir()
	reg := &Registry{StoreDir: dir, IndexPath: filepath.Join(dir, "index.json")}
	handler := reg.handler()
	archive := validQcap(t, "concurrent")

	const uploads = 12
	statusCodes := make(chan int, uploads)
	var wg sync.WaitGroup
	for i := 0; i < uploads; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/artifacts", bytes.NewReader(archive))
			req.Header.Set("X-Qcap-Name", fmt.Sprintf("artifact-%02d.qcap", i))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			statusCodes <- rec.Code
		}(i)
	}
	wg.Wait()
	close(statusCodes)
	for status := range statusCodes {
		if status != http.StatusCreated {
			t.Fatalf("concurrent publish returned %d", status)
		}
	}

	persistedBytes, err := os.ReadFile(reg.IndexPath)
	if err != nil {
		t.Fatalf("read index: %v", err)
	}
	var persisted []Capsule
	if err := json.Unmarshal(persistedBytes, &persisted); err != nil {
		t.Fatalf("decode index: %v", err)
	}
	if len(persisted) != uploads {
		t.Fatalf("expected %d indexed artifacts, got %d", uploads, len(persisted))
	}
	assertNoTemporaryFiles(t, dir)
}

func TestPublishRevocationsRejectsIssuerMismatchAndBadSignature(t *testing.T) {
	dir := t.TempDir()
	reg := &Registry{StoreDir: dir, IndexPath: filepath.Join(dir, "index.json")}
	issuer, body := signedRevocations(t)

	mismatchReq := httptest.NewRequest(http.MethodPost, "/revocations/not-the-signer/revocations.json", bytes.NewReader(body))
	mismatchRec := httptest.NewRecorder()
	reg.revocations(mismatchRec, mismatchReq)
	if mismatchRec.Code != http.StatusBadRequest {
		t.Fatalf("expected issuer mismatch rejection, got %d: %s", mismatchRec.Code, mismatchRec.Body.String())
	}

	var list RevocationList
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	list.Signature = strings.Repeat("00", ed25519.SignatureSize)
	tampered, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	badSigReq := httptest.NewRequest(http.MethodPost, "/revocations/"+issuer+"/revocations.json", bytes.NewReader(tampered))
	badSigRec := httptest.NewRecorder()
	reg.revocations(badSigRec, badSigReq)
	if badSigRec.Code != http.StatusBadRequest {
		t.Fatalf("expected bad signature rejection, got %d: %s", badSigRec.Code, badSigRec.Body.String())
	}
	if got := reg.revocationIssuerCount(); got != 0 {
		t.Fatalf("rejected revocations should not create issuer storage, got %d", got)
	}
	assertNoTemporaryFiles(t, dir)
}

func validQcap(t *testing.T, marker string) []byte {
	return qcapWithSignature(t, marker, true)
}

func qcapWithSignature(t *testing.T, marker string, validSignature bool) []byte {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	manifestBytes := []byte(`{"schema_version":"0.1.0","merkle_root":"blake3:abc","created_at":"unix-seconds:1","metadata":{}}`)
	signedBytes := manifestBytes
	if !validSignature {
		signedBytes = []byte("different manifest")
	}
	bundle := QcapSignatureBundle{
		MerkleRoot: "blake3:abc",
		Signature:  hex.EncodeToString(ed25519.Sign(privateKey, signedBytes)),
		PublicKey:  hex.EncodeToString(privateKey.Public().(ed25519.PublicKey)),
		Algorithm:  "ed25519:manifest",
	}
	bundleBytes, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	manifest, err := writer.Create("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	_, err = manifest.Write(manifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := writer.Create("signatures/manifest.sig.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signature.Write(bundleBytes); err != nil {
		t.Fatal(err)
	}
	payload, err := writer.Create("payload/data.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := payload.Write([]byte(marker)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func signedRevocations(t *testing.T) (string, []byte) {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	issuer := hex.EncodeToString(privateKey.Public().(ed25519.PublicKey))
	list := RevocationList{
		SchemaVersion: "0.1.0",
		Revoked: []RevocationEntry{{
			CapRoot:             "blake3:abc",
			CapabilitySignature: "signature",
			RevokedAt:           "unix-seconds:1",
			Reason:              "test",
		}},
		PublicKey: issuer,
		Algorithm: "ed25519",
	}
	list.Signature = hex.EncodeToString(ed25519.Sign(privateKey, []byte(list.signingPayload())))
	body, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	return issuer, body
}

func publishArtifact(t *testing.T, baseURL, name string, body []byte, wantStatus int) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, baseURL+"/artifacts", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Content-Type", "application/qcap+zip")
	req.Header.Set("X-Qcap-Name", name)
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("publish artifact: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != wantStatus {
		responseBody, _ := io.ReadAll(response.Body)
		t.Fatalf("expected publish status %d, got %d: %s", wantStatus, response.StatusCode, responseBody)
	}
}

func assertNoTemporaryFiles(t *testing.T, dir string) {
	t.Helper()
	err := filepath.Walk(dir, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(info.Name(), ".qcap-") || strings.Contains(info.Name(), ".qcap-backup-") {
			t.Errorf("temporary file was not removed: %s", filePath)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk temp directory: %v", err)
	}
}
