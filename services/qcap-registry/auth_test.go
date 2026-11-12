package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type testIdentityProvider struct {
	server *httptest.Server
	signer jose.Signer
}

func newTestIdentityProvider(t *testing.T) *testIdentityProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key"))
	if err != nil {
		t.Fatal(err)
	}
	p := &testIdentityProvider{signer: signer}
	p.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": p.server.URL, "jwks_uri": p.server.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "test-key", Algorithm: "RS256", Use: "sig"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(p.server.Close)
	return p
}

func (p *testIdentityProvider) token(t *testing.T, changes map[string]any) string {
	t.Helper()
	claims := map[string]any{"iss": p.server.URL, "aud": "qcap-admin", "sub": "admin-one", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
	for k, v := range changes {
		claims[k] = v
	}
	token, err := jwt.Signed(p.signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func authRequest(handler http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	result := httptest.NewRecorder()
	handler.ServeHTTP(result, req)
	return result
}

func newAuthRegistry(t *testing.T, p *testIdentityProvider) *Registry {
	t.Helper()
	store := t.TempDir()
	auth, err := newRegistryAuth(context.Background(), p.server.URL, "qcap-admin", "admin-one", filepath.Join(store, ".auth", "pats.json"), p.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	return &Registry{StoreDir: store, IndexPath: filepath.Join(store, "index.json"), Auth: auth}
}

func tokenBody(scopes []string, expiry time.Time) string {
	data, _ := json.Marshal(map[string]any{"name": "integration", "scopes": scopes, "expires_at": expiry})
	return string(data)
}

func TestOIDCRejectsInvalidIdentity(t *testing.T) {
	p := newTestIdentityProvider(t)
	r := newAuthRegistry(t, p)
	for name, claims := range map[string]map[string]any{
		"issuer":                         {"iss": "https://other.invalid"},
		"audience":                       {"aud": "another-app"},
		"expired":                        {"exp": time.Now().Add(-time.Hour).Unix()},
		"missing expiry":                 {"exp": nil},
		"non-admin":                      {"sub": "other-user"},
		"empty subject":                  {"sub": ""},
		"authorized party":               {"azp": "other-app"},
		"multiple audiences without azp": {"aud": []string{"qcap-admin", "other-app"}},
	} {
		t.Run(name, func(t *testing.T) {
			result := authRequest(r.handler(), "GET", "/admin/tokens", p.token(t, claims), "")
			if result.Code != http.StatusUnauthorized {
				t.Fatalf("status %d: %s", result.Code, result.Body)
			}
		})
	}
	other := newTestIdentityProvider(t)
	for _, token := range []string{"", "not-a-token", other.token(t, map[string]any{"iss": p.server.URL})} {
		if result := authRequest(r.handler(), "GET", "/admin/tokens", token, ""); result.Code != 401 {
			t.Fatalf("invalid signature/token accepted: %d", result.Code)
		}
	}
	if result := authRequest(r.handler(), "GET", "/admin/tokens", p.token(t, nil), ""); result.Code != 200 {
		t.Fatalf("valid admin rejected: %d %s", result.Code, result.Body)
	}
}

func TestPATLifecycleScopesAndPersistence(t *testing.T) {
	p := newTestIdentityProvider(t)
	r := newAuthRegistry(t, p)
	admin := p.token(t, nil)
	handler := r.handler()
	result := authRequest(handler, "POST", "/admin/tokens", admin, tokenBody([]string{scopePublish}, time.Now().Add(time.Hour)))
	if result.Code != 201 {
		t.Fatalf("mint: %d %s", result.Code, result.Body)
	}
	var minted struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(result.Body.Bytes(), &minted); err != nil {
		t.Fatal(err)
	}
	if minted.Token == "" || result.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("missing token/no-store")
	}
	disk, err := os.ReadFile(r.Auth.storePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(disk, []byte(minted.Token)) || bytes.Contains(disk, []byte(strings.Split(minted.Token, ".")[2])) {
		t.Fatal("plaintext token persisted")
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(r.Auth.storePath)
		if info.Mode().Perm() != 0600 {
			t.Fatalf("PAT file mode: %v", info.Mode())
		}
	}
	listed := authRequest(handler, "GET", "/admin/tokens", admin, "")
	if listed.Code != 200 || strings.Contains(listed.Body.String(), "digest") || strings.Contains(listed.Body.String(), minted.Token) {
		t.Fatal("listing leaked token material")
	}
	if authRequest(handler, "GET", "/admin/tokens", minted.Token, "").Code != 401 {
		t.Fatal("PAT gained admin rights")
	}
	if authRequest(handler, "POST", "/artifacts", admin, "").Code != 401 {
		t.Fatal("OIDC token used directly as a PAT")
	}
	if !r.Auth.allows(minted.Token, scopePublish) || r.Auth.allows(minted.Token, scopeRevoke) || r.Auth.allows(minted.Token+"x", scopePublish) {
		t.Fatal("scope/secret validation failed")
	}
	// Exercise the actual write handlers, not only the authorization helper.
	archive, err := os.ReadFile(filepath.Join("seed", "alpha.qcap"))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/artifacts", bytes.NewReader(archive))
	req.Header.Set("Authorization", "Bearer "+minted.Token)
	req.Header.Set("X-Qcap-Name", "pat-test.qcap")
	upload := httptest.NewRecorder()
	handler.ServeHTTP(upload, req)
	if upload.Code != 201 {
		t.Fatalf("publish: %d %s", upload.Code, upload.Body)
	}
	issuer := strings.Repeat("a", 64)
	if authRequest(handler, "POST", "/revocations/"+issuer+"/revocations.json", minted.Token, "{}").Code != 401 {
		t.Fatal("publish scope allowed revocation")
	}
	if authRequest(handler, "POST", "/artifacts", "", "").Code != 401 {
		t.Fatal("OIDC mode allowed anonymous write")
	}
	if authRequest(handler, "GET", "/artifacts/pat-test.qcap", "", "").Code != 200 {
		t.Fatal("public read compatibility lost")
	}
	reloaded, err := newRegistryAuth(context.Background(), p.server.URL, "qcap-admin", "admin-one", r.Auth.storePath, p.server.Client())
	if err != nil || !reloaded.allows(minted.Token, scopePublish) {
		t.Fatalf("restart lost token: %v", err)
	}
	r.Auth = reloaded
	if authRequest(r.handler(), "DELETE", "/admin/tokens/"+minted.ID, admin, "").Code != 204 {
		t.Fatal("revoke failed")
	}
	if r.Auth.allows(minted.Token, scopePublish) {
		t.Fatal("revoked token still works")
	}
	reloaded, err = newRegistryAuth(context.Background(), p.server.URL, "qcap-admin", "admin-one", r.Auth.storePath, p.server.Client())
	if err != nil || reloaded.allows(minted.Token, scopePublish) {
		t.Fatalf("revocation did not survive restart: %v", err)
	}
}

func TestPATExpiryValidationAndPersistenceFailure(t *testing.T) {
	p := newTestIdentityProvider(t)
	r := newAuthRegistry(t, p)
	admin := p.token(t, nil)
	for _, body := range []string{
		tokenBody(nil, time.Now().Add(time.Hour)),
		tokenBody([]string{"admin"}, time.Now().Add(time.Hour)),
		tokenBody([]string{scopePublish, scopePublish}, time.Now().Add(time.Hour)),
		tokenBody([]string{scopePublish}, time.Now().Add(-time.Hour)),
		tokenBody([]string{scopePublish}, time.Now().Add(91*24*time.Hour)),
		`{"name":"x","scopes":["artifacts:write"]}`,
		`{} {}`,
	} {
		if result := authRequest(r.handler(), "POST", "/admin/tokens", admin, body); result.Code != 400 {
			t.Fatalf("invalid request accepted: %d %s", result.Code, result.Body)
		}
	}
	result := authRequest(r.handler(), "POST", "/admin/tokens", admin, tokenBody([]string{scopeRevoke}, time.Now().Add(time.Hour)))
	var minted struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	_ = json.Unmarshal(result.Body.Bytes(), &minted)
	if result.Code != 201 || !r.Auth.allows(minted.Token, scopeRevoke) || r.Auth.allows(minted.Token, scopePublish) {
		t.Fatal("revocation scope failed")
	}
	issuer, revocations := signedRevocations(t)
	if result := authRequest(r.handler(), "POST", "/revocations/"+issuer+"/revocations.json", minted.Token, string(revocations)); result.Code != 201 {
		t.Fatalf("scoped revocation publish: %d %s", result.Code, result.Body)
	}
	r.Auth.clientID = "other-client"
	if r.Auth.allows(minted.Token, scopeRevoke) {
		t.Fatal("PAT survived audience change")
	}
	r.Auth.clientID = "qcap-admin"
	r.Auth.issuer = "https://other-issuer.invalid"
	if r.Auth.allows(minted.Token, scopeRevoke) {
		t.Fatal("PAT survived issuer change")
	}
	r.Auth.issuer = p.server.URL
	stored := r.Auth.tokens[minted.ID]
	stored.ExpiresAt = time.Now().Add(-time.Second)
	r.Auth.tokens[minted.ID] = stored
	if r.Auth.allows(minted.Token, scopeRevoke) {
		t.Fatal("expired token accepted")
	}
	stored.ExpiresAt = time.Now().Add(time.Hour)
	r.Auth.tokens[minted.ID] = stored
	delete(r.Auth.admins, "admin-one")
	if r.Auth.allows(minted.Token, scopeRevoke) {
		t.Fatal("removed administrator's token accepted")
	}
	r.Auth.admins["admin-one"] = true
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("block"), 0600); err != nil {
		t.Fatal(err)
	}
	r.Auth.storePath = filepath.Join(blocker, "pats.json")
	if authRequest(r.handler(), "DELETE", "/admin/tokens/"+minted.ID, admin, "").Code != 500 || !r.Auth.allows(minted.Token, scopeRevoke) {
		t.Fatal("failed revocation changed in-memory state")
	}
	if authRequest(r.handler(), "POST", "/admin/tokens", admin, tokenBody([]string{scopePublish}, time.Now().Add(time.Hour))).Code != 500 || len(r.Auth.tokens) != 1 {
		t.Fatal("failed issuance published token state")
	}
}

func TestPATConcurrentIssuance(t *testing.T) {
	p := newTestIdentityProvider(t)
	r := newAuthRegistry(t, p)
	admin := p.token(t, nil)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if result := authRequest(r.handler(), "POST", "/admin/tokens", admin, tokenBody([]string{scopePublish}, time.Now().Add(time.Hour))); result.Code != 201 {
				t.Errorf("mint: %d", result.Code)
			}
		}()
	}
	wg.Wait()
	reloaded, err := newRegistryAuth(context.Background(), p.server.URL, "qcap-admin", "admin-one", r.Auth.storePath, p.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.tokens) != 8 {
		t.Fatalf("lost tokens: %d", len(reloaded.tokens))
	}
}

func TestAuthConfigurationAndLegacyCompatibility(t *testing.T) {
	p := newTestIdentityProvider(t)
	for _, cfg := range [][3]string{{"", "client", "admin"}, {p.server.URL, "", "admin"}, {p.server.URL, "client", ""}, {"http://issuer.invalid", "client", "admin"}, {p.server.URL, "client", "admin,"}} {
		if _, err := newRegistryAuth(context.Background(), cfg[0], cfg[1], cfg[2], filepath.Join(t.TempDir(), "pats.json"), p.server.Client()); err == nil {
			t.Fatalf("invalid config accepted: %v", cfg)
		}
	}
	path := filepath.Join(t.TempDir(), "pats.json")
	_ = os.WriteFile(path, []byte("invalid json"), 0600)
	if _, err := newRegistryAuth(context.Background(), p.server.URL, "client", "admin", path, p.server.Client()); err == nil {
		t.Fatal("corrupt PAT store accepted")
	}
	r := &Registry{Token: "legacy-test-token"}
	req := httptest.NewRequest("POST", "/artifacts", nil)
	if r.authorizedScope(req, scopePublish) {
		t.Fatal("anonymous write allowed")
	}
	req.Header.Set("Authorization", "Bearer legacy-test-token")
	if !r.authorizedScope(req, scopePublish) || !r.authorizedScope(req, scopeRevoke) {
		t.Fatal("legacy token rejected")
	}
	req.Header.Add("Authorization", "Bearer extra")
	if r.authorizedScope(req, scopePublish) {
		t.Fatal("duplicate auth header accepted")
	}
	if authRequest(r.handler(), "GET", "/admin/tokens", "legacy-test-token", "").Code != 404 {
		t.Fatal("admin endpoint enabled without OIDC")
	}
	r.Token = ""
	if !r.authorizedScope(req, scopePublish) {
		t.Fatal("local demo compatibility lost")
	}
}
