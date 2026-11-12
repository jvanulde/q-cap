package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

const (
	scopePublish   = "artifacts:write"
	scopeRevoke    = "revocations:write"
	maxPATLifetime = 90 * 24 * time.Hour
)

// Authentication is opt-in for compatibility with the local demo. When OIDC
// is configured, writes fail closed even if no legacy shared token is set.
type registryAuth struct {
	verifier  *oidc.IDTokenVerifier
	clientID  string
	issuer    string
	admins    map[string]bool
	storePath string
	mu        sync.RWMutex
	tokens    map[string]personalToken
}

type personalToken struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	Audience  string    `json:"audience"`
	Scopes    []string  `json:"scopes"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Digest    string    `json:"digest,omitempty"`
}

type httpsTransport struct{ base http.RoundTripper }

func (t httpsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" || req.URL.User != nil {
		return nil, errors.New("OIDC discovery and keys require HTTPS")
	}
	return t.base.RoundTrip(req)
}

func newRegistryAuth(ctx context.Context, issuer, clientID, subjects, storePath string, client *http.Client) (*registryAuth, error) {
	if issuer == "" || clientID == "" || strings.TrimSpace(subjects) == "" {
		return nil, errors.New("OIDC issuer, client ID, and admin subjects must all be set")
	}
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("OIDC issuer must be an HTTPS URL without credentials, query, or fragment")
	}
	base := http.DefaultTransport
	if client != nil && client.Transport != nil {
		base = client.Transport
	}
	// The same bounded HTTPS-only client is used for discovery and JWKS refresh.
	ctx = oidc.ClientContext(ctx, &http.Client{Timeout: 10 * time.Second, Transport: httpsTransport{base: base}})
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery: %w", err)
	}
	a := &registryAuth{
		verifier:  provider.Verifier(&oidc.Config{ClientID: clientID}),
		clientID:  clientID,
		issuer:    issuer,
		admins:    make(map[string]bool),
		storePath: storePath,
		tokens:    make(map[string]personalToken),
	}
	for _, subject := range strings.Split(subjects, ",") {
		subject = strings.TrimSpace(subject)
		if subject == "" {
			return nil, errors.New("empty OIDC admin subject")
		}
		a.admins[subject] = true
	}
	data, err := os.ReadFile(storePath)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read PAT store: %w", err)
	}
	if err == nil {
		var records []personalToken
		if err := json.Unmarshal(data, &records); err != nil {
			return nil, fmt.Errorf("invalid PAT store: %w", err)
		}
		for _, token := range records {
			digest, decodeErr := hex.DecodeString(token.Digest)
			if decodeErr != nil || len(digest) != sha256.Size || token.ID == "" || token.Subject == "" || token.Issuer == "" || token.Audience == "" || token.ExpiresAt.IsZero() || !validScopes(token.Scopes) {
				return nil, errors.New("invalid PAT record")
			}
			if _, exists := a.tokens[token.ID]; exists {
				return nil, errors.New("duplicate PAT ID")
			}
			a.tokens[token.ID] = token
		}
	}
	return a, nil
}

func bearerToken(req *http.Request) string {
	if len(req.Header.Values("Authorization")) != 1 {
		return ""
	}
	parts := strings.Fields(req.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) > 16384 {
		return ""
	}
	return parts[1]
}

func equalToken(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	x, y := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(x[:], y[:]) == 1
}

func (a *registryAuth) adminSubject(req *http.Request) (string, error) {
	raw := bearerToken(req)
	if raw == "" {
		return "", errors.New("missing bearer token")
	}
	verified, err := a.verifier.Verify(req.Context(), raw)
	if err != nil {
		return "", errors.New("invalid OIDC token")
	}
	var claims struct {
		AuthorizedParty string `json:"azp"`
	}
	if err := verified.Claims(&claims); err != nil {
		return "", errors.New("invalid OIDC claims")
	}
	if (len(verified.Audience) > 1 && claims.AuthorizedParty == "") || (claims.AuthorizedParty != "" && claims.AuthorizedParty != a.clientID) {
		return "", errors.New("invalid OIDC authorized party")
	}
	if !a.admins[verified.Subject] {
		return "", errors.New("subject is not an administrator")
	}
	return verified.Subject, nil
}

func validScopes(scopes []string) bool {
	if len(scopes) == 0 || len(scopes) > 2 {
		return false
	}
	seen := make(map[string]bool)
	for _, scope := range scopes {
		if (scope != scopePublish && scope != scopeRevoke) || seen[scope] {
			return false
		}
		seen[scope] = true
	}
	return true
}

func (a *registryAuth) allows(raw, scope string) bool {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] != "qcap_pat" {
		return false
	}
	digest := sha256.Sum256([]byte(raw))
	a.mu.RLock()
	defer a.mu.RUnlock()
	token, ok := a.tokens[parts[1]]
	if !ok || token.Issuer != a.issuer || token.Audience != a.clientID || !a.admins[token.Subject] || !time.Now().Before(token.ExpiresAt) {
		return false
	}
	expected, err := hex.DecodeString(token.Digest)
	if err != nil || subtle.ConstantTimeCompare(digest[:], expected) != 1 {
		return false
	}
	for _, granted := range token.Scopes {
		if granted == scope {
			return true
		}
	}
	return false
}

func (r *Registry) authorizedScope(req *http.Request, scope string) bool {
	if r.Auth == nil && r.Token == "" {
		return true
	}
	raw := bearerToken(req)
	if equalToken(raw, r.Token) {
		return true
	}
	return r.Auth != nil && r.Auth.allows(raw, scope)
}

// Persist a replacement snapshot before publishing it in memory. Failure never
// grants a newly minted token or acknowledges a revocation that was not stored.
func (a *registryAuth) persistLocked(next map[string]personalToken) error {
	records := make([]personalToken, 0, len(next))
	for _, token := range next {
		records = append(records, token)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.storePath), 0700); err != nil {
		return err
	}
	if err := atomicWriteFile(a.storePath, data, 0600); err != nil {
		return err
	}
	a.tokens = next
	return nil
}

func (a *registryAuth) snapshotLocked() map[string]personalToken {
	next := make(map[string]personalToken, len(a.tokens))
	for id, token := range a.tokens {
		next[id] = token
	}
	return next
}

func (r *Registry) adminTokens(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Auth == nil {
		http.NotFound(w, req)
		return
	}
	subject, err := r.Auth.adminSubject(req)
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	a := r.Auth
	if req.URL.Path != "/admin/tokens" {
		id := strings.TrimPrefix(req.URL.Path, "/admin/tokens/")
		if req.Method != http.MethodDelete || id == "" || strings.Contains(id, "/") {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		if _, exists := a.tokens[id]; !exists {
			http.NotFound(w, req)
			return
		}
		next := a.snapshotLocked()
		delete(next, id)
		if err := a.persistLocked(next); err != nil {
			http.Error(w, "could not persist token revocation", 500)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	switch req.Method {
	case http.MethodGet:
		a.mu.RLock()
		records := make([]personalToken, 0, len(a.tokens))
		for _, token := range a.tokens {
			token.Digest = ""
			records = append(records, token)
		}
		a.mu.RUnlock()
		sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(records)
	case http.MethodPost:
		var input struct {
			Name      string    `json:"name"`
			Scopes    []string  `json:"scopes"`
			ExpiresAt time.Time `json:"expires_at"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, req.Body, 4096))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&input); err != nil {
			http.Error(w, "invalid token request", 400)
			return
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			http.Error(w, "invalid token request", 400)
			return
		}
		now := time.Now().UTC()
		if strings.TrimSpace(input.Name) == "" || len(input.Name) > 128 || !validScopes(input.Scopes) || !input.ExpiresAt.After(now) || input.ExpiresAt.After(now.Add(maxPATLifetime)) {
			http.Error(w, "name, supported scopes, and expiry within 90 days are required", 400)
			return
		}
		var random [48]byte
		if _, err := rand.Read(random[:]); err != nil {
			http.Error(w, "could not generate token", 500)
			return
		}
		id := hex.EncodeToString(random[:16])
		raw := "qcap_pat." + id + "." + hex.EncodeToString(random[16:])
		digest := sha256.Sum256([]byte(raw))
		token := personalToken{ID: id, Name: input.Name, Subject: subject, Issuer: a.issuer, Audience: a.clientID, Scopes: input.Scopes, CreatedAt: now, ExpiresAt: input.ExpiresAt.UTC(), Digest: hex.EncodeToString(digest[:])}
		a.mu.Lock()
		next := a.snapshotLocked()
		next[id] = token
		err := a.persistLocked(next)
		a.mu.Unlock()
		if err != nil {
			http.Error(w, "could not persist token", 500)
			return
		}
		token.Digest = ""
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(struct {
			personalToken
			Token string `json:"token"`
		}{token, raw})
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
