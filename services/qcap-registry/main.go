package main

import (
	"archive/zip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxArtifactBytes           = int64(512 << 20)
	maxRevocationBytes         = int64(10 << 20)
	maxManifestBytes           = int64(1 << 20)
	maxArchiveEntries          = 10_000
	maxArchiveUncompressedSize = int64(2 << 30)
)

var errUploadTooLarge = fmt.Errorf("upload exceeds size limit")

type Capsule struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Size        int64  `json:"size"`
	ContentType string `json:"content_type"`
	Digest      string `json:"digest"`
	CreatedAt   string `json:"created_at"`
}

type RevocationDocument struct {
	Issuer      string `json:"issuer"`
	Path        string `json:"path"`
	Size        int64  `json:"size"`
	ContentType string `json:"content_type"`
	Digest      string `json:"digest"`
	CreatedAt   string `json:"created_at"`
}

type RevocationList struct {
	SchemaVersion string            `json:"schema_version"`
	Revoked       []RevocationEntry `json:"revoked"`
	Signature     string            `json:"signature"`
	PublicKey     string            `json:"public_key"`
	Algorithm     string            `json:"algorithm"`
}

type RevocationEntry struct {
	CapRoot             string `json:"cap_root"`
	CapabilitySignature string `json:"capability_signature"`
	RevokedAt           string `json:"revoked_at"`
	Reason              string `json:"reason"`
}

type QcapSignatureBundle struct {
	MerkleRoot string `json:"merkle_root"`
	Signature  string `json:"signature"`
	PublicKey  string `json:"public_key"`
	Algorithm  string `json:"algorithm"`
}

type Registry struct {
	StoreDir  string
	IndexPath string
	Token     string

	mu    sync.RWMutex
	Index []Capsule
}

func main() {
	storeDir := firstNonEmpty(os.Getenv("QCAP_REGISTRY_STORE"), os.Getenv("QCAP_REGISTRY_SEED"))
	if storeDir == "" {
		storeDir = "services/qcap-registry/seed"
	}
	indexPath := os.Getenv("QCAP_REGISTRY_INDEX")
	if indexPath == "" {
		indexPath = filepath.Join(storeDir, "index.json")
	}

	reg := &Registry{
		StoreDir:  storeDir,
		IndexPath: indexPath,
		Token:     os.Getenv("QCAP_REGISTRY_TOKEN"),
	}
	if err := os.MkdirAll(storeDir, 0755); err != nil {
		log.Fatalf("could not create registry store: %v", err)
	}
	if err := reg.loadIndex(); err != nil {
		log.Printf("warn: could not load index: %v", err)
	}

	addr := firstNonEmpty(os.Getenv("QCAP_REGISTRY_ADDR"), ":8080")
	log.Printf("registry listening on %s; store dir: %s; index: %s", addr, storeDir, indexPath)
	log.Fatal(http.ListenAndServe(addr, reg.handler()))
}

func (r *Registry) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", r.root)
	mux.HandleFunc("/health", r.health)
	mux.HandleFunc("/health.html", r.healthHTML)
	mux.HandleFunc("/index.json", r.indexJSON)
	mux.HandleFunc("/index", r.indexHTML)
	mux.HandleFunc("/artifacts", r.publish)
	mux.HandleFunc("/artifacts/", r.artifact)
	mux.HandleFunc("/revocations/", r.revocations)
	return mux
}

func (r *Registry) loadIndex() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.loadIndexLocked()
}

func (r *Registry) loadIndexLocked() error {
	var idx []Capsule
	if bytes, err := os.ReadFile(r.IndexPath); err == nil && len(bytes) > 0 {
		if err := json.Unmarshal(bytes, &idx); err != nil {
			return err
		}
	}

	byName := make(map[string]Capsule)
	for _, capsule := range idx {
		byName[capsule.Name] = capsule
	}

	if err := filepath.Walk(r.StoreDir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || filepath.Clean(p) == filepath.Clean(r.IndexPath) {
			return nil
		}
		if filepath.Ext(p) != ".qcap" {
			return nil
		}
		name := filepath.Base(p)
		existing := byName[name]
		digest, err := fileDigest(p)
		if err != nil {
			return err
		}
		createdAt := existing.CreatedAt
		if createdAt == "" {
			createdAt = info.ModTime().UTC().Format(time.RFC3339)
		}
		byName[name] = Capsule{
			Name:        name,
			Path:        "/artifacts/" + name,
			Size:        info.Size(),
			ContentType: "application/qcap+zip",
			Digest:      digest,
			CreatedAt:   createdAt,
		}
		return nil
	}); err != nil {
		return err
	}

	r.Index = r.Index[:0]
	for _, capsule := range byName {
		r.Index = append(r.Index, capsule)
	}
	sort.Slice(r.Index, func(i, j int) bool {
		return r.Index[i].Name < r.Index[j].Name
	})
	return r.saveIndexLocked()
}

func (r *Registry) saveIndexLocked() error {
	if err := os.MkdirAll(filepath.Dir(r.IndexPath), 0755); err != nil {
		return err
	}
	bytes, err := json.MarshalIndent(r.Index, "", "  ")
	if err != nil {
		return err
	}
	bytes = append(bytes, '\n')
	return atomicWriteFile(r.IndexPath, bytes, 0644)
}

func (r *Registry) root(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html><html><head><meta charset="utf-8"><title>QCAP Registry</title></head><body>
		<h1>QCAP Registry (demo)</h1>
		<p>This registry stores .qcap capsules on disk and persists a JSON index.</p>
		<ul>
			<li><a href="/health">/health</a> (JSON status)</li>
			<li><a href="/health.html">/health.html</a> (HTML status)</li>
			<li><a href="/index.json">/index.json</a> (JSON index)</li>
			<li><a href="/index">/index</a> (HTML index)</li>
			<li><a href="/artifacts/">/artifacts/</a> (downloads)</li>
			<li><code>/revocations/&lt;issuer&gt;/revocations.json</code> (signed revocation lists)</li>
		</ul>
	</body></html>`))
}

func (r *Registry) health(w http.ResponseWriter, _ *http.Request) {
	r.mu.RLock()
	artifactCount := len(r.Index)
	r.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":        "ok",
		"auth_required": r.Token != "",
		"artifacts":     artifactCount,
		"revocations":   r.revocationIssuerCount(),
	})
}

func (r *Registry) healthHTML(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html><html><head><meta charset="utf-8"><title>Health</title></head><body>
		<h1>Health</h1>
		<p>The registry is running.</p>
		<p>For machine-readable output, use <a href="/health">/health</a>.</p>
	</body></html>`))
}

func (r *Registry) indexJSON(w http.ResponseWriter, _ *http.Request) {
	_ = r.loadIndex()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(r.indexSnapshot())
}

func (r *Registry) indexHTML(w http.ResponseWriter, _ *http.Request) {
	_ = r.loadIndex()
	index := r.indexSnapshot()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte("<!doctype html><html><head><meta charset=\"utf-8\"><title>Index</title></head><body>"))
	_, _ = w.Write([]byte("<h1>Artifact Index</h1>\n"))
	if len(index) == 0 {
		_, _ = w.Write([]byte("<p><em>No artifacts found.</em></p>"))
	} else {
		_, _ = w.Write([]byte("<ul>"))
		for _, c := range index {
			_, _ = w.Write([]byte("<li>"))
			_, _ = w.Write([]byte(html.EscapeString(c.Name)))
			_, _ = w.Write([]byte(" - <a href=\"" + html.EscapeString(c.Path) + "\">download</a> (" + html.EscapeString(c.ContentType) + ", " + formatSize(c.Size) + ", " + html.EscapeString(c.Digest) + ")"))
			_, _ = w.Write([]byte("</li>"))
		}
		_, _ = w.Write([]byte("</ul>"))
	}
	_, _ = w.Write([]byte("<p>Machine-readable index: <a href=\"/index.json\">/index.json</a></p>"))
	_, _ = w.Write([]byte("</body></html>"))
}

func (r *Registry) publish(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !r.authorized(req) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	name := safeArtifactName(req.Header.Get("X-Qcap-Name"))
	if name == "" {
		name = "artifact.qcap"
	}
	if filepath.Ext(name) != ".qcap" {
		name += ".qcap"
	}
	dest := filepath.Join(r.StoreDir, name)
	tempPath, written, err := stageUpload(req.Body, r.StoreDir, maxArtifactBytes)
	if err != nil {
		writeUploadError(w, err)
		return
	}
	defer os.Remove(tempPath)
	if err := validateQcapArchive(tempPath); err != nil {
		http.Error(w, "invalid qcap archive: "+err.Error(), http.StatusBadRequest)
		return
	}
	digest, err := fileDigest(tempPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	capsule := Capsule{
		Name:        name,
		Path:        "/artifacts/" + name,
		Size:        written,
		ContentType: "application/qcap+zip",
		Digest:      digest,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	if err := r.commitArtifact(tempPath, dest, capsule); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(capsule)
}

func (r *Registry) artifact(w http.ResponseWriter, req *http.Request) {
	name := safeArtifactName(strings.TrimPrefix(req.URL.Path, "/artifacts/"))
	if name == "" || filepath.Ext(name) != ".qcap" {
		http.NotFound(w, req)
		return
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	http.ServeFile(w, req, filepath.Join(r.StoreDir, name))
}

func (r *Registry) revocations(w http.ResponseWriter, req *http.Request) {
	issuer := revocationIssuerFromPath(req.URL.Path)
	if issuer == "" {
		http.NotFound(w, req)
		return
	}

	switch req.Method {
	case http.MethodGet:
		r.serveRevocations(w, req, issuer)
	case http.MethodPost:
		r.publishRevocations(w, req, issuer)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (r *Registry) serveRevocations(w http.ResponseWriter, req *http.Request, issuer string) {
	path := r.revocationPath(issuer)
	w.Header().Set("Content-Type", "application/qcap-revocations+json")
	r.mu.RLock()
	defer r.mu.RUnlock()
	http.ServeFile(w, req, path)
}

func (r *Registry) publishRevocations(w http.ResponseWriter, req *http.Request, issuer string) {
	if !r.authorized(req) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	dest := r.revocationPath(issuer)
	tempPath, written, err := stageUpload(req.Body, r.StoreDir, maxRevocationBytes)
	if err != nil {
		writeUploadError(w, err)
		return
	}
	defer os.Remove(tempPath)
	if err := validateRevocationList(tempPath, issuer); err != nil {
		http.Error(w, "invalid revocation list: "+err.Error(), http.StatusBadRequest)
		return
	}
	digest, err := fileDigest(tempPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	r.mu.Lock()
	err = replaceFile(tempPath, dest)
	r.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	doc := RevocationDocument{
		Issuer:      issuer,
		Path:        "/revocations/" + issuer + "/revocations.json",
		Size:        written,
		ContentType: "application/qcap-revocations+json",
		Digest:      digest,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(doc)
}

func (r *Registry) authorized(req *http.Request) bool {
	if r.Token == "" {
		return true
	}
	return req.Header.Get("Authorization") == "Bearer "+r.Token
}

func (r *Registry) revocationPath(issuer string) string {
	return filepath.Join(r.StoreDir, "revocations", issuer, "revocations.json")
}

func (r *Registry) revocationIssuerCount() int {
	root := filepath.Join(r.StoreDir, "revocations")
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			count++
		}
	}
	return count
}

func revocationIssuerFromPath(path string) string {
	raw := strings.TrimPrefix(path, "/revocations/")
	raw = strings.TrimSuffix(raw, "/revocations.json")
	raw = strings.Trim(raw, "/")
	if raw == "" || strings.Contains(raw, "/") {
		return ""
	}
	return safePathSegment(raw)
}

func safeArtifactName(raw string) string {
	name := filepath.Base(strings.TrimSpace(raw))
	name = strings.ReplaceAll(name, "\\", "_")
	name = strings.ReplaceAll(name, "/", "_")
	if name == "." || name == string(filepath.Separator) {
		return ""
	}
	return name
}

func safePathSegment(raw string) string {
	name := strings.TrimSpace(raw)
	name = strings.ReplaceAll(name, "\\", "_")
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "..", "_")
	if name == "." || name == "" {
		return ""
	}
	return name
}

func fileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func (r *Registry) commitArtifact(tempPath, dest string, capsule Capsule) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i := range r.Index {
		if r.Index[i].Name == capsule.Name {
			if r.Index[i].CreatedAt != "" {
				capsule.CreatedAt = r.Index[i].CreatedAt
			}
			if err := replaceFile(tempPath, dest); err != nil {
				return err
			}
			r.Index[i] = capsule
			return r.saveIndexLocked()
		}
	}
	if err := replaceFile(tempPath, dest); err != nil {
		return err
	}
	r.Index = append(r.Index, capsule)
	sort.Slice(r.Index, func(i, j int) bool {
		return r.Index[i].Name < r.Index[j].Name
	})
	return r.saveIndexLocked()
}

func (r *Registry) indexSnapshot() []Capsule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]Capsule(nil), r.Index...)
}

func stageUpload(body io.Reader, dir string, maxBytes int64) (string, int64, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", 0, err
	}
	temp, err := os.CreateTemp(dir, ".qcap-upload-*")
	if err != nil {
		return "", 0, err
	}
	tempPath := temp.Name()
	keep := false
	defer func() {
		_ = temp.Close()
		if !keep {
			_ = os.Remove(tempPath)
		}
	}()

	written, err := io.Copy(temp, io.LimitReader(body, maxBytes+1))
	if err != nil {
		return "", 0, err
	}
	if written > maxBytes {
		return "", 0, errUploadTooLarge
	}
	if err := temp.Sync(); err != nil {
		return "", 0, err
	}
	if err := temp.Close(); err != nil {
		return "", 0, err
	}
	keep = true
	return tempPath, written, nil
}

func writeUploadError(w http.ResponseWriter, err error) {
	if err == errUploadTooLarge {
		http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
		return
	}
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

func validateQcapArchive(archivePath string) error {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("not a readable ZIP: %w", err)
	}
	defer zr.Close()
	if len(zr.File) == 0 || len(zr.File) > maxArchiveEntries {
		return fmt.Errorf("archive must contain between 1 and %d entries", maxArchiveEntries)
	}

	seen := make(map[string]struct{}, len(zr.File))
	var manifest *zip.File
	var signatureBundle *zip.File
	var totalSize int64
	for _, entry := range zr.File {
		name := entry.Name
		if name == "" || strings.Contains(name, "\\") || strings.Contains(name, ":") || strings.ContainsRune(name, 0) || path.IsAbs(name) {
			return fmt.Errorf("unsafe archive path %q", name)
		}
		cleanName := path.Clean(strings.TrimSuffix(name, "/"))
		if cleanName == "." || cleanName == ".." || strings.HasPrefix(cleanName, "../") || cleanName != strings.TrimSuffix(name, "/") {
			return fmt.Errorf("unsafe archive path %q", name)
		}
		if _, exists := seen[cleanName]; exists {
			return fmt.Errorf("duplicate archive entry %q", name)
		}
		seen[cleanName] = struct{}{}
		if cleanName != "manifest.json" &&
			!strings.HasPrefix(cleanName, "payload/") &&
			!strings.HasPrefix(cleanName, "meta/") &&
			!strings.HasPrefix(cleanName, "signatures/") &&
			cleanName != "payload" && cleanName != "meta" && cleanName != "signatures" {
			return fmt.Errorf("archive entry %q is outside the qcap layout", name)
		}
		if entry.UncompressedSize64 > uint64(maxArchiveUncompressedSize) || totalSize > maxArchiveUncompressedSize-int64(entry.UncompressedSize64) {
			return fmt.Errorf("uncompressed archive exceeds %d bytes", maxArchiveUncompressedSize)
		}
		totalSize += int64(entry.UncompressedSize64)
		if name == "manifest.json" {
			manifest = entry
		}
		if name == "signatures/manifest.sig.json" {
			signatureBundle = entry
		}
	}
	if manifest == nil {
		return fmt.Errorf("manifest.json is required")
	}
	if signatureBundle == nil {
		return fmt.Errorf("signatures/manifest.sig.json is required")
	}
	if manifest.UncompressedSize64 > uint64(maxManifestBytes) {
		return fmt.Errorf("manifest.json exceeds %d bytes", maxManifestBytes)
	}

	r, err := manifest.Open()
	if err != nil {
		return fmt.Errorf("open manifest.json: %w", err)
	}
	defer r.Close()
	manifestBytes, err := io.ReadAll(io.LimitReader(r, maxManifestBytes+1))
	if err != nil {
		return fmt.Errorf("read manifest.json: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(manifestBytes, &fields); err != nil {
		return fmt.Errorf("manifest.json is invalid JSON: %w", err)
	}
	for _, key := range []string{"schema_version", "merkle_root", "created_at", "metadata"} {
		value, ok := fields[key]
		if !ok || len(value) == 0 || string(value) == "null" {
			return fmt.Errorf("manifest.json is missing %s", key)
		}
	}
	stringFields := make(map[string]string)
	for _, key := range []string{"schema_version", "merkle_root", "created_at"} {
		var value string
		if err := json.Unmarshal(fields[key], &value); err != nil || strings.TrimSpace(value) == "" {
			return fmt.Errorf("manifest.json field %s must be a non-empty string", key)
		}
		stringFields[key] = value
	}

	if signatureBundle.UncompressedSize64 > uint64(maxManifestBytes) {
		return fmt.Errorf("manifest signature exceeds %d bytes", maxManifestBytes)
	}
	signatureReader, err := signatureBundle.Open()
	if err != nil {
		return fmt.Errorf("open manifest signature: %w", err)
	}
	defer signatureReader.Close()
	signatureBytes, err := io.ReadAll(io.LimitReader(signatureReader, maxManifestBytes+1))
	if err != nil {
		return fmt.Errorf("read manifest signature: %w", err)
	}
	var bundle QcapSignatureBundle
	if err := json.Unmarshal(signatureBytes, &bundle); err != nil {
		return fmt.Errorf("manifest signature is invalid JSON: %w", err)
	}
	if bundle.MerkleRoot != stringFields["merkle_root"] {
		return fmt.Errorf("manifest and signature Merkle roots do not match")
	}
	publicKey, err := hex.DecodeString(bundle.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("manifest public_key must be a %d-byte hex-encoded Ed25519 key", ed25519.PublicKeySize)
	}
	signature, err := hex.DecodeString(bundle.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("manifest signature must be a %d-byte hex-encoded Ed25519 signature", ed25519.SignatureSize)
	}
	var signedBytes []byte
	switch bundle.Algorithm {
	case "ed25519:manifest":
		signedBytes = manifestBytes
	case "ed25519":
		// Legacy 0.1.0 archives signed the Merkle-root string directly.
		signedBytes = []byte(bundle.MerkleRoot)
	default:
		return fmt.Errorf("unsupported manifest signature algorithm %q", bundle.Algorithm)
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), signedBytes, signature) {
		return fmt.Errorf("manifest signature verification failed")
	}
	return nil
}

func validateRevocationList(filePath, issuer string) error {
	bytes, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	var list RevocationList
	if err := json.Unmarshal(bytes, &list); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if list.SchemaVersion == "" {
		return fmt.Errorf("schema_version is required")
	}
	if list.Algorithm != "ed25519" {
		return fmt.Errorf("unsupported algorithm %q", list.Algorithm)
	}
	if list.PublicKey != issuer {
		return fmt.Errorf("issuer path does not match public_key")
	}
	publicKey, err := hex.DecodeString(list.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("public_key must be a %d-byte hex-encoded Ed25519 key", ed25519.PublicKeySize)
	}
	signature, err := hex.DecodeString(list.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("signature must be a %d-byte hex-encoded Ed25519 signature", ed25519.SignatureSize)
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), []byte(list.signingPayload()), signature) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func (r RevocationList) signingPayload() string {
	lines := []string{"schema_version=" + r.SchemaVersion}
	for _, entry := range r.Revoked {
		lines = append(lines, strings.Join([]string{
			entry.CapRoot,
			entry.CapabilitySignature,
			entry.RevokedAt,
			entry.Reason,
		}, "|"))
	}
	return strings.Join(lines, "\n")
}

func atomicWriteFile(dest string, bytes []byte, mode os.FileMode) error {
	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".qcap-index-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(mode); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(bytes); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return replaceFile(tempPath, dest)
}

func replaceFile(tempPath, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return err
	}
	renameErr := os.Rename(tempPath, dest)
	if renameErr == nil {
		return nil
	}
	if _, err := os.Stat(dest); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("replace %s: %w", filepath.Base(dest), renameErr)
		}
		return fmt.Errorf("inspect replacement target %s: %w", filepath.Base(dest), err)
	}

	backup := fmt.Sprintf("%s.qcap-backup-%d", dest, time.Now().UnixNano())
	if err := os.Rename(dest, backup); err != nil {
		return fmt.Errorf("prepare replacement for %s: %w", filepath.Base(dest), err)
	}
	if err := os.Rename(tempPath, dest); err != nil {
		_ = os.Rename(backup, dest)
		return fmt.Errorf("replace %s: %w", filepath.Base(dest), err)
	}
	if err := os.Remove(backup); err != nil {
		return fmt.Errorf("remove replacement backup for %s: %w", filepath.Base(dest), err)
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func formatSize(n int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case n >= GB:
		return fmt.Sprintf("%.2f GB", float64(n)/float64(GB))
	case n >= MB:
		return fmt.Sprintf("%.2f MB", float64(n)/float64(MB))
	case n >= KB:
		return fmt.Sprintf("%.2f KB", float64(n)/float64(KB))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
