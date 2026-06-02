package mesh

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RealClient implements Client against Headscale's REST API (v0.28.x).
//
// API shape highlights:
//   - Bearer-token auth: `Authorization: Bearer hskey-auth-<prefix>-<secret>`.
//   - All 64-bit IDs (user id, preauth-key id, node id) are emitted by
//     grpc-gateway as JSON strings, not numbers. We keep them as strings
//     end-to-end to avoid signed-int round-trip surprises.
//   - CreatePreAuthKey takes a uint64 user-id, but our Client interface uses
//     a user *name*. The real client resolves name -> id via ListUsers and
//     caches the result.
//   - ListPreAuthKeys has no user filter at the wire level; we filter
//     client-side.
//
// Cross-reference: design/control-plane/mesh.md §3 (intent shape) and §9
// (deferred items).
type RealClient struct {
	baseURL string
	apiKey  string
	hc      *http.Client

	usersMu sync.RWMutex
	users   map[string]string // user name -> user id (uint64 as string)
}

// RealClientConfig is the constructor input for NewRealClient.
type RealClientConfig struct {
	// BaseURL is the Headscale root, e.g. "https://mesh.rasputin.local:8080".
	// Trailing slashes are trimmed.
	BaseURL string
	// APIKey is the value placed in the `Authorization: Bearer ...` header.
	// New v0.28 keys are `hskey-auth-<prefix>-<secret>`; legacy raw secrets
	// also work.
	APIKey string
	// TLSConfig overrides the default TLS config. Use this to trust the
	// Rasputin internal CA root that signed the Headscale leaf cert.
	TLSConfig *tls.Config
	// RequestTimeout caps each HTTP round-trip. Defaults to 30s.
	RequestTimeout time.Duration
}

func NewRealClient(cfg RealClientConfig) (*RealClient, error) {
	if cfg.BaseURL == "" {
		return nil, errors.New("mesh: real client base URL required")
	}
	if cfg.APIKey == "" {
		return nil, errors.New("mesh: real client api key required")
	}
	timeout := cfg.RequestTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.TLSConfig != nil {
		transport.TLSClientConfig = cfg.TLSConfig
	}
	return &RealClient{
		baseURL: strings.TrimRight(cfg.BaseURL, "/"),
		apiKey:  cfg.APIKey,
		hc:      &http.Client{Transport: transport, Timeout: timeout},
		users:   map[string]string{},
	}, nil
}

func (c *RealClient) Backend() string { return "headscale" }

// ----- HTTP plumbing ------------------------------------------------------

// do issues a request, marshals body (if non-nil), and decodes the response
// (if out non-nil). Non-2xx responses become errors carrying the status code
// and (truncated) response body.
func (c *RealClient) do(ctx context.Context, method, path string, body, out any) error {
	var reqBody io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("mesh: marshal %s %s: %w", method, path, err)
		}
		reqBody = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return fmt.Errorf("mesh: build %s %s: %w", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("mesh: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Cap body excerpt; Headscale error responses are small JSON.
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &HTTPError{
			Method: method,
			Path:   path,
			Status: resp.StatusCode,
			Body:   strings.TrimSpace(string(raw)),
		}
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("mesh: decode %s %s: %w", method, path, err)
	}
	return nil
}

// HTTPError carries a non-2xx Headscale response. The Body field is the raw
// (possibly truncated) response payload, useful for log triage.
type HTTPError struct {
	Method string
	Path   string
	Status int
	Body   string
}

func (e *HTTPError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("headscale %s %s: HTTP %d", e.Method, e.Path, e.Status)
	}
	return fmt.Sprintf("headscale %s %s: HTTP %d: %s", e.Method, e.Path, e.Status, e.Body)
}

// IsAlreadyExists is true when Headscale signals the resource already
// exists. grpc-gateway maps AlreadyExists -> HTTP 409. We also tolerate 400s
// whose body mentions "already exists" because older Headscale builds use
// InvalidArgument for the same case.
func IsAlreadyExists(err error) bool {
	var he *HTTPError
	if !errors.As(err, &he) {
		return false
	}
	if he.Status == http.StatusConflict {
		return true
	}
	return he.Status == http.StatusBadRequest && strings.Contains(strings.ToLower(he.Body), "already exists")
}

// ----- Wire types ---------------------------------------------------------
//
// Mirror the grpc-gateway JSON shape (camelCase, uint64 as string).

type hsUser struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	CreatedAt     time.Time `json:"createdAt,omitempty"`
	DisplayName   string    `json:"displayName,omitempty"`
	Email         string    `json:"email,omitempty"`
	Provider      string    `json:"provider,omitempty"`
	ProfilePicURL string    `json:"profilePicUrl,omitempty"`
}

type hsPreAuthKey struct {
	User       hsUser    `json:"user"`
	ID         string    `json:"id"`
	Key        string    `json:"key"`
	Reusable   bool      `json:"reusable"`
	Ephemeral  bool      `json:"ephemeral"`
	Used       bool      `json:"used"`
	Expiration time.Time `json:"expiration"`
	CreatedAt  time.Time `json:"createdAt"`
	ACLTags    []string  `json:"aclTags,omitempty"`
}

type hsNode struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	IPAddresses     []string  `json:"ipAddresses,omitempty"`
	LastSeen        time.Time `json:"lastSeen,omitempty"`
	Online          bool      `json:"online"`
	ApprovedRoutes  []string  `json:"approvedRoutes,omitempty"`
	AvailableRoutes []string  `json:"availableRoutes,omitempty"`
	SubnetRoutes    []string  `json:"subnetRoutes,omitempty"`
	Tags            []string  `json:"tags,omitempty"`
	User            hsUser    `json:"user"`
}

// ----- Users --------------------------------------------------------------

func (c *RealClient) EnsureUser(ctx context.Context, name string) error {
	if name == "" {
		return errors.New("mesh: EnsureUser: empty name")
	}
	if _, ok := c.cachedUserID(name); ok {
		return nil
	}
	// List first — cheaper than a Create on the steady-state path (post-first-boot).
	if id, err := c.findUserIDByName(ctx, name); err != nil {
		return err
	} else if id != "" {
		c.cacheUserID(name, id)
		return nil
	}
	// Not found — create.
	var out struct {
		User hsUser `json:"user"`
	}
	err := c.do(ctx, http.MethodPost, "/api/v1/user", map[string]string{"name": name}, &out)
	if err != nil {
		// Racing creator? Re-list once.
		if IsAlreadyExists(err) {
			id, lerr := c.findUserIDByName(ctx, name)
			if lerr == nil && id != "" {
				c.cacheUserID(name, id)
				return nil
			}
		}
		return fmt.Errorf("ensure user %q: %w", name, err)
	}
	if out.User.ID == "" {
		return fmt.Errorf("ensure user %q: response missing user.id", name)
	}
	c.cacheUserID(name, out.User.ID)
	return nil
}

// resolveUserID returns the Headscale id for a user name, populating the
// cache on miss. Used by every endpoint that takes a uint64 user id.
func (c *RealClient) resolveUserID(ctx context.Context, name string) (string, error) {
	if id, ok := c.cachedUserID(name); ok {
		return id, nil
	}
	id, err := c.findUserIDByName(ctx, name)
	if err != nil {
		return "", err
	}
	if id == "" {
		return "", fmt.Errorf("mesh: user %q not found in Headscale", name)
	}
	c.cacheUserID(name, id)
	return id, nil
}

func (c *RealClient) findUserIDByName(ctx context.Context, name string) (string, error) {
	var out struct {
		Users []hsUser `json:"users"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/user", nil, &out); err != nil {
		return "", fmt.Errorf("list users: %w", err)
	}
	for _, u := range out.Users {
		if u.Name == name {
			return u.ID, nil
		}
	}
	return "", nil
}

func (c *RealClient) cachedUserID(name string) (string, bool) {
	c.usersMu.RLock()
	defer c.usersMu.RUnlock()
	id, ok := c.users[name]
	return id, ok
}

func (c *RealClient) cacheUserID(name, id string) {
	c.usersMu.Lock()
	c.users[name] = id
	c.usersMu.Unlock()
}

// ----- Pre-auth keys ------------------------------------------------------

func (c *RealClient) CreatePreAuthKey(ctx context.Context, in CreatePreAuthKeyInput) (string, string, error) {
	userID, err := c.resolveUserID(ctx, in.User)
	if err != nil {
		return "", "", err
	}
	body := map[string]any{
		"user":      userID,
		"reusable":  in.Reusable,
		"ephemeral": in.Ephemeral,
		"aclTags":   nonNilStrings(in.Tags),
	}
	// Omit zero-time so Headscale applies its server-side default rather
	// than treating "0001-01-01T00:00:00Z" as a past expiration.
	if !in.Expiry.IsZero() {
		body["expiration"] = in.Expiry.UTC().Format(time.RFC3339Nano)
	}
	var out struct {
		PreAuthKey hsPreAuthKey `json:"preAuthKey"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/v1/preauthkey", body, &out); err != nil {
		return "", "", fmt.Errorf("create preauth key: %w", err)
	}
	if out.PreAuthKey.ID == "" || out.PreAuthKey.Key == "" {
		return "", "", errors.New("create preauth key: response missing id or key")
	}
	return out.PreAuthKey.ID, out.PreAuthKey.Key, nil
}

func (c *RealClient) ExpirePreAuthKey(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("mesh: ExpirePreAuthKey: empty id")
	}
	body := map[string]string{"id": id}
	if err := c.do(ctx, http.MethodPost, "/api/v1/preauthkey/expire", body, nil); err != nil {
		return fmt.Errorf("expire preauth key %s: %w", id, err)
	}
	return nil
}

func (c *RealClient) ListPreAuthKeys(ctx context.Context, user string) ([]HSPreAuthKey, error) {
	var out struct {
		PreAuthKeys []hsPreAuthKey `json:"preAuthKeys"`
	}
	// Headscale's ListPreAuthKeys RPC takes no filter parameter — we fetch
	// all and filter client-side.
	if err := c.do(ctx, http.MethodGet, "/api/v1/preauthkey", nil, &out); err != nil {
		return nil, fmt.Errorf("list preauth keys: %w", err)
	}
	keys := make([]HSPreAuthKey, 0, len(out.PreAuthKeys))
	for _, k := range out.PreAuthKeys {
		if user != "" && k.User.Name != user {
			continue
		}
		keys = append(keys, toHSPreAuthKey(k))
	}
	return keys, nil
}

// ----- Nodes --------------------------------------------------------------

func (c *RealClient) ListNodes(ctx context.Context) ([]HSNode, error) {
	var out struct {
		Nodes []hsNode `json:"nodes"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/node", nil, &out); err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	nodes := make([]HSNode, 0, len(out.Nodes))
	for _, n := range out.Nodes {
		nodes = append(nodes, toHSNode(n))
	}
	return nodes, nil
}

func (c *RealClient) SetNodeRoutes(ctx context.Context, nodeID string, cidrs []string) error {
	if nodeID == "" {
		return errors.New("mesh: SetNodeRoutes: empty nodeID")
	}
	path := "/api/v1/node/" + nodeID + "/approve_routes"
	body := map[string]any{"routes": nonNilStrings(cidrs)}
	if err := c.do(ctx, http.MethodPost, path, body, nil); err != nil {
		return fmt.Errorf("approve routes on node %s: %w", nodeID, err)
	}
	return nil
}

// ----- Conversions --------------------------------------------------------

func toHSPreAuthKey(k hsPreAuthKey) HSPreAuthKey {
	return HSPreAuthKey{
		ID:         k.ID,
		User:       k.User.Name,
		Reusable:   k.Reusable,
		Ephemeral:  k.Ephemeral,
		Used:       k.Used,
		Expiration: k.Expiration.UTC(),
		CreatedAt:  k.CreatedAt.UTC(),
		Tags:       append([]string(nil), k.ACLTags...),
		Plaintext:  k.Key, // empty on List per Headscale; only Create returns it
	}
}

func toHSNode(n hsNode) HSNode {
	// Headscale exposes ipv4/ipv6 as a single ipAddresses slice (varies by
	// proto version). The Client surface keeps two separate fields; pick
	// the first plausible v4 and v6 from the address list.
	var ipv4, ipv6 string
	for _, ip := range n.IPAddresses {
		switch {
		case ipv4 == "" && strings.Contains(ip, "."):
			ipv4 = ip
		case ipv6 == "" && strings.Contains(ip, ":"):
			ipv6 = ip
		}
	}
	return HSNode{
		ID:               n.ID,
		User:             n.User.Name,
		Hostname:         n.Name,
		GivenName:        n.Name,
		IPv4:             ipv4,
		IPv6:             ipv6,
		Tags:             append([]string(nil), n.Tags...),
		AdvertisedRoutes: append([]string(nil), n.AvailableRoutes...),
		ApprovedRoutes:   append([]string(nil), n.ApprovedRoutes...),
		LastSeen:         n.LastSeen.UTC(),
	}
}

// nonNilStrings turns a nil slice into an empty slice so JSON encodes [] not
// null. Headscale tolerates null but [] matches its own emit-defaults shape.
func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}
