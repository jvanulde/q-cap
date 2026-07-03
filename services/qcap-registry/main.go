package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

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

type Registry struct {
	StoreDir  string
	IndexPath string
	Token     string

	mu    sync.Mutex
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

	mux := http.NewServeMux()
	mux.HandleFunc("/", reg.root)
	mux.HandleFunc("/health", reg.health)
	mux.HandleFunc("/health.html", reg.healthHTML)
	mux.HandleFunc("/index.json", reg.indexJSON)
	mux.HandleFunc("/index", reg.indexHTML)
	mux.HandleFunc("/artifacts", reg.publish)
	mux.HandleFunc("/artifacts/", reg.artifact)
	mux.HandleFunc("/revocations/", reg.revocations)

	addr := ":8080"
	log.Printf("registry listening on %s; store dir: %s; index: %s", addr, storeDir, indexPath)
	log.Fatal(http.ListenAndServe(addr, mux))
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
	return os.WriteFile(r.IndexPath, bytes, 0644)
}

func (r *Registry) upsert(c Capsule) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.Index {
		if r.Index[i].Name == c.Name {
			if r.Index[i].CreatedAt != "" {
				c.CreatedAt = r.Index[i].CreatedAt
			}
			r.Index[i] = c
			return r.saveIndexLocked()
		}
	}
	r.Index = append(r.Index, c)
	sort.Slice(r.Index, func(i, j int) bool {
		return r.Index[i].Name < r.Index[j].Name
	})
	return r.saveIndexLocked()
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
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":        "ok",
		"auth_required": r.Token != "",
		"artifacts":     len(r.Index),
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
	_ = json.NewEncoder(w).Encode(r.Index)
}

func (r *Registry) indexHTML(w http.ResponseWriter, _ *http.Request) {
	_ = r.loadIndex()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte("<!doctype html><html><head><meta charset=\"utf-8\"><title>Index</title></head><body>"))
	_, _ = w.Write([]byte("<h1>Artifact Index</h1>\n"))
	if len(r.Index) == 0 {
		_, _ = w.Write([]byte("<p><em>No artifacts found.</em></p>"))
	} else {
		_, _ = w.Write([]byte("<ul>"))
		for _, c := range r.Index {
			_, _ = w.Write([]byte("<li>"))
			_, _ = w.Write([]byte(c.Name))
			_, _ = w.Write([]byte(" - <a href=\"" + c.Path + "\">download</a> (" + c.ContentType + ", " + formatSize(c.Size) + ", " + c.Digest + ")"))
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
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out, err := os.Create(dest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	written, copyErr := io.Copy(out, http.MaxBytesReader(w, req.Body, 512<<20))
	closeErr := out.Close()
	if copyErr != nil {
		http.Error(w, copyErr.Error(), http.StatusBadRequest)
		return
	}
	if closeErr != nil {
		http.Error(w, closeErr.Error(), http.StatusInternalServerError)
		return
	}
	digest, err := fileDigest(dest)
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
	if err := r.upsert(capsule); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(capsule)
}

func (r *Registry) artifact(w http.ResponseWriter, req *http.Request) {
	name := safeArtifactName(strings.TrimPrefix(req.URL.Path, "/artifacts/"))
	if name == "" {
		http.NotFound(w, req)
		return
	}
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
	http.ServeFile(w, req, path)
}

func (r *Registry) publishRevocations(w http.ResponseWriter, req *http.Request, issuer string) {
	if !r.authorized(req) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	dest := r.revocationPath(issuer)
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out, err := os.Create(dest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	written, copyErr := io.Copy(out, http.MaxBytesReader(w, req.Body, 10<<20))
	closeErr := out.Close()
	if copyErr != nil {
		http.Error(w, copyErr.Error(), http.StatusBadRequest)
		return
	}
	if closeErr != nil {
		http.Error(w, closeErr.Error(), http.StatusInternalServerError)
		return
	}
	digest, err := fileDigest(dest)
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
