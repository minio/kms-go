// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"aead.dev/mem"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

// Client is a KES client. Usually, a new client is
// instantiated via the NewClient or NewClientWithConfig
// functions.
//
// In general, a client just requires:
//   - a KES server endpoint
//   - a X.509 certificate for authentication
//
// However, custom transport protocols, timeouts,
// connection pooling, etc. can be specified via
// a custom http.RoundTripper. For example:
//
//	client := &Client{
//	    Endpoints:  []string{"https:127.0.0.1:7373"},
//	    HTTPClient: http.Client{
//	        Transport: &http.Transport{
//	           // specify custom behavior...
//
//	           TLSClientConfig: &tls.Config{
//	               Certificates: []tls.Certificates{clientCert},
//	           },
//	        },
//	    },
//	 }
//
// A custom transport protocol can be used via a
// custom implemention of the http.RoundTripper
// interface.
type Client struct {
	// Endpoints contains one or multiple KES server
	// endpoints. For example: https://127.0.0.1:7373
	//
	// Each endpoint must be a HTTPS endpoint and
	// should point to different KES server replicas
	// with a common configuration.
	//
	// Multiple endpoints should only be specified
	// when multiple KES servers should be used, e.g.
	// for high availability, but no round-robin DNS
	// is used.
	Endpoints []string

	// HTTPClient is the HTTP client.
	//
	// The HTTP client uses its http.RoundTripper
	// to send requests resp. receive responses.
	//
	// It must not be modified concurrently.
	HTTPClient http.Client

	init sync.Once
	lb   *loadBalancer
}

// NewClient returns a new KES client that uses an API key
// for authentication.
func NewClient(endpoint string, key APIKey, options ...CertificateOption) (*Client, error) {
	cert, err := GenerateCertificate(key, options...)
	if err != nil {
		return nil, err
	}
	return NewClientWithConfig(endpoint, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}), nil
}

// NewClientWithConfig returns a new KES client with the
// given KES server endpoint that uses the given TLS config
// for mTLS authentication.
//
// Therefore, the config.Certificates must contain a TLS
// certificate that is valid for client authentication.
//
// NewClientWithConfig uses an http.Transport with reasonable
// defaults.
func NewClientWithConfig(endpoint string, config *tls.Config) *Client {
	return &Client{
		Endpoints: []string{endpoint},
		HTTPClient: http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
					DualStack: true,
				}).DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				TLSClientConfig:       config,
			},
		},
	}
}

// Version tries to fetch the version information from the
// KES server.
func (c *Client) Version(ctx context.Context) (string, error) {
	const (
		APIPath        = "/version"
		Method         = http.MethodGet
		StatusOK       = http.StatusOK
		MaxResponeSize = 1 * mem.KiB
	)
	c.init.Do(c.initLoadBalancer)

	client := retry(c.HTTPClient)
	resp, err := c.lb.Send(ctx, &client, Method, APIPath, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return "", parseErrorResponse(resp)
	}

	type Response struct {
		Version string `json:"version"`
	}
	var response Response
	if err = json.NewDecoder(mem.LimitReader(resp.Body, MaxResponeSize)).Decode(&response); err != nil {
		return "", err
	}
	return response.Version, nil
}

// IsReady reports whether the server is ready to serve requests.
//
// Since the readiness endpoint requires authentication, unless
// disabled at the server, it may fail with ErrNotAllowed even
// though the server might be ready to handle requests.
func (c *Client) IsReady(ctx context.Context) (bool, error) {
	const (
		APIPath  = "/v1/ready"
		Method   = http.MethodGet
		StatusOK = http.StatusOK
	)
	c.init.Do(c.initLoadBalancer)

	client := retry(c.HTTPClient)
	resp, err := c.lb.Send(ctx, &client, Method, APIPath, nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	return resp.StatusCode == StatusOK, parseErrorResponse(resp)
}

// Status returns the current state of the KES server.
func (c *Client) Status(ctx context.Context) (State, error) {
	const (
		APIPath         = "/v1/status"
		Method          = http.MethodGet
		StatusOK        = http.StatusOK
		MaxResponseSize = 1 * mem.MiB
	)
	c.init.Do(c.initLoadBalancer)

	client := retry(c.HTTPClient)
	resp, err := c.lb.Send(ctx, &client, Method, APIPath, nil)
	if err != nil {
		return State{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return State{}, parseErrorResponse(resp)
	}

	var state State
	if err = json.NewDecoder(mem.LimitReader(resp.Body, MaxResponseSize)).Decode(&state); err != nil {
		return State{}, err
	}
	return state, nil
}

// APIs returns a list of all API endpoints supported
// by the KES server.
//
// It returns ErrNotAllowed if the client does not
// have sufficient permissions to fetch the server
// APIs.
func (c *Client) APIs(ctx context.Context) ([]API, error) {
	const (
		APIPath         = "/v1/api"
		Method          = http.MethodGet
		StatusOK        = http.StatusOK
		MaxResponseSize = 1 * mem.MiB
	)
	c.init.Do(c.initLoadBalancer)

	client := retry(c.HTTPClient)
	resp, err := c.lb.Send(ctx, &client, Method, APIPath, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return nil, parseErrorResponse(resp)
	}

	type Response struct {
		Method  string `json:"method"`
		Path    string `json:"path"`
		MaxBody int64  `json:"max_body"`
		Timeout int64  `json:"timeout"` // Timeout in seconds
	}
	var responses []Response
	if err = json.NewDecoder(mem.LimitReader(resp.Body, MaxResponseSize)).Decode(&responses); err != nil {
		return nil, err
	}

	apis := make([]API, 0, len(responses))
	for _, response := range responses {
		apis = append(apis, API{
			Method:  response.Method,
			Path:    response.Path,
			MaxBody: response.MaxBody,
			Timeout: time.Second * time.Duration(response.Timeout),
		})
	}
	return apis, nil
}

// CreateKey creates a new cryptographic key. The key will
// be generated by the KES server.
//
// It returns ErrKeyExists if a key with the same name already
// exists.
func (c *Client) CreateKey(ctx context.Context, name string) error {
	const (
		APIPath  = "/v1/key/create"
		Method   = http.MethodPost
		StatusOK = http.StatusOK
	)
	c.init.Do(c.initLoadBalancer)

	client := retry(c.HTTPClient)
	resp, err := c.lb.Send(ctx, &client, Method, join(APIPath, name), nil)
	if err != nil {
		return err
	}
	if resp.StatusCode != StatusOK {
		return parseErrorResponse(resp)
	}
	return nil
}

// ImportKey imports the given key into a KES server. It
// returns ErrKeyExists if a key with the same key already
// exists.
func (c *Client) ImportKey(ctx context.Context, name string, req *ImportKeyRequest) error {
	const (
		APIPath  = "/v1/key/import"
		Method   = http.MethodPost
		StatusOK = http.StatusOK
	)
	c.init.Do(c.initLoadBalancer)

	type Request struct {
		Key    []byte `json:"key"`
		Cipher string `json:"cipher"`
	}
	body, err := json.Marshal(Request{
		Key:    req.Key,
		Cipher: req.Cipher.String(),
	})
	if err != nil {
		return err
	}

	client := retry(c.HTTPClient)
	resp, err := c.lb.Send(ctx, &client, Method, join(APIPath, name), bytes.NewReader(body), withHeader("Content-Type", "application/json"))
	if err != nil {
		return err
	}
	if resp.StatusCode != StatusOK {
		return parseErrorResponse(resp)
	}
	return nil
}

// DescribeKey returns the KeyInfo for the given key.
// It returns ErrKeyNotFound if no such key exists.
func (c *Client) DescribeKey(ctx context.Context, name string) (*KeyInfo, error) {
	const (
		APIPath         = "/v1/key/describe"
		Method          = http.MethodGet
		StatusOK        = http.StatusOK
		MaxResponseSize = 1 * mem.MiB
	)
	type Response struct {
		Name      string       `json:"name"`
		ID        string       `json:"id"`
		Algorithm KeyAlgorithm `json:"algorithm"`
		CreatedAt time.Time    `json:"created_at"`
		CreatedBy Identity     `json:"created_by"`
	}
	c.init.Do(c.initLoadBalancer)

	client := retry(c.HTTPClient)
	resp, err := c.lb.Send(ctx, &client, Method, join(APIPath, name), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return nil, parseErrorResponse(resp)
	}

	var response Response
	if err := json.NewDecoder(mem.LimitReader(resp.Body, MaxResponseSize)).Decode(&response); err != nil {
		return nil, err
	}
	return &KeyInfo{
		Name:      response.Name,
		Algorithm: response.Algorithm,
		CreatedAt: response.CreatedAt,
		CreatedBy: response.CreatedBy,
	}, nil
}

// DeleteKey deletes the key from a KES server. It returns
// ErrKeyNotFound if no such key exists.
func (c *Client) DeleteKey(ctx context.Context, name string) error {
	const (
		APIPath  = "/v1/key/delete"
		Method   = http.MethodDelete
		StatusOK = http.StatusOK
	)
	c.init.Do(c.initLoadBalancer)

	client := retry(c.HTTPClient)
	resp, err := c.lb.Send(ctx, &client, Method, join(APIPath, name), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return parseErrorResponse(resp)
	}
	return nil
}

// GenerateKey returns a new generated data encryption key (DEK).
// A DEK has a plaintext and ciphertext representation.
//
// The former should be used for cryptographic operations, like
// encrypting some data.
//
// The later is the result of encrypting the plaintext with the named
// key at the KES server. It should be stored at a durable location but
// does not need to stay secret. The ciphertext can only be decrypted
// with the named key at the KES server.
//
// The context is cryptographically bound to the ciphertext and the
// same context value must be provided when decrypting the ciphertext
// via Decrypt. Therefore, an application must either remember the
// context or must be able to re-generate it.
//
// GenerateKey returns ErrKeyNotFound if no key with the given name
// exists.
func (c *Client) GenerateKey(ctx context.Context, name string, context []byte) (DEK, error) {
	const (
		APIPath         = "/v1/key/generate"
		Method          = http.MethodPost
		StatusOK        = http.StatusOK
		MaxResponseSize = 1 * mem.MiB
	)
	c.init.Do(c.initLoadBalancer)

	type Request struct {
		Context []byte `json:"context,omitempty"` // A context is optional
	}
	type Response struct {
		Plaintext  []byte `json:"plaintext"`
		Ciphertext []byte `json:"ciphertext"`
	}

	body, err := json.Marshal(Request{
		Context: context,
	})
	if err != nil {
		return DEK{}, err
	}

	client := retry(c.HTTPClient)
	resp, err := c.lb.Send(ctx, &client, Method, join(APIPath, name), bytes.NewReader(body), withHeader("Content-Type", "application/json"))
	if err != nil {
		return DEK{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return DEK{}, parseErrorResponse(resp)
	}

	var response Response
	if err = json.NewDecoder(mem.LimitReader(resp.Body, MaxResponseSize)).Decode(&response); err != nil {
		return DEK{}, err
	}
	return DEK(response), nil
}

// Encrypt encrypts the given plaintext with the named key at the
// KES server. The optional context is cryptographically bound to
// the returned ciphertext. The exact same context must be provided
// when decrypting the ciphertext again.
//
// Encrypt returns ErrKeyNotFound if no such key exists at the KES
// server.
func (c *Client) Encrypt(ctx context.Context, name string, plaintext, context []byte) ([]byte, error) {
	const (
		APIPath         = "/v1/key/encrypt"
		Method          = http.MethodPost
		StatusOK        = http.StatusOK
		MaxResponseSize = 1 * mem.MiB
	)
	c.init.Do(c.initLoadBalancer)

	type Request struct {
		Plaintext []byte `json:"plaintext"`
		Context   []byte `json:"context,omitempty"` // A context is optional
	}
	type Response struct {
		Ciphertext []byte `json:"ciphertext"`
	}

	body, err := json.Marshal(Request{
		Plaintext: plaintext,
		Context:   context,
	})
	if err != nil {
		return nil, err
	}

	client := retry(c.HTTPClient)
	resp, err := c.lb.Send(ctx, &client, Method, join(APIPath, name), bytes.NewReader(body), withHeader("Content-Type", "application/json"))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return nil, parseErrorResponse(resp)
	}

	var response Response
	if err = json.NewDecoder(mem.LimitReader(resp.Body, MaxResponseSize)).Decode(&response); err != nil {
		return nil, err
	}
	return response.Ciphertext, nil
}

// Decrypt decrypts the ciphertext with the named key at the KES
// server. The exact same context, used during Encrypt, must be
// provided.
//
// Decrypt returns ErrKeyNotFound if no such key exists. It returns
// ErrDecrypt when the ciphertext has been modified or a different
// context value is provided.
func (c *Client) Decrypt(ctx context.Context, name string, ciphertext, context []byte) ([]byte, error) {
	const (
		APIPath         = "/v1/key/decrypt"
		Method          = http.MethodPost
		StatusOK        = http.StatusOK
		MaxResponseSize = 1 * mem.MiB
	)
	c.init.Do(c.initLoadBalancer)

	type Request struct {
		Ciphertext []byte `json:"ciphertext"`
		Context    []byte `json:"context,omitempty"` // A context is optional
	}
	type Response struct {
		Plaintext []byte `json:"plaintext"`
	}
	body, err := json.Marshal(Request{
		Ciphertext: ciphertext,
		Context:    context,
	})
	if err != nil {
		return nil, err
	}

	client := retry(c.HTTPClient)
	resp, err := c.lb.Send(ctx, &client, Method, join(APIPath, name), bytes.NewReader(body), withHeader("Content-Type", "application/json"))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return nil, parseErrorResponse(resp)
	}

	var response Response
	if err = json.NewDecoder(mem.LimitReader(resp.Body, MaxResponseSize)).Decode(&response); err != nil {
		return nil, err
	}
	return response.Plaintext, nil
}

// HMAC returns the HMAC of the given message using the key with the given name.
// It returns ErrKeyNotFound if no such key exists.
func (c *Client) HMAC(ctx context.Context, key string, message []byte) ([]byte, error) {
	const (
		APIPath         = "/v1/key/hmac"
		Method          = http.MethodPut
		StatusOK        = http.StatusOK
		MaxResponseSize = 1 * mem.KB
	)
	c.init.Do(c.initLoadBalancer)

	type Request struct {
		Message []byte `json:"message"`
	}
	type Response struct {
		Sum []byte `json:"hmac"`
	}

	body, err := json.Marshal(Request{
		Message: message,
	})
	if err != nil {
		return nil, err
	}

	client := retry(c.HTTPClient)
	resp, err := c.lb.Send(ctx, &client, Method, join(APIPath, key), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return nil, parseErrorResponse(resp)
	}

	var response Response
	if err = json.NewDecoder(mem.LimitReader(resp.Body, MaxResponseSize)).Decode(&response); err != nil {
		return nil, err
	}
	return response.Sum, nil
}

// ListKeys returns a paginated list of key names from the server,
// starting at the specified prefix. If n > 0, it returns at most n names.
// Otherwise, the server determines the page size.
//
// ListKeys also returns a continuation token for fetching the next batch.
// When the listing reaches the end, the continuation token will be empty.
//
// The ListIter type can be used as a convenient way to iterate over a paginated list.
func (c *Client) ListKeys(ctx context.Context, prefix string, n int) ([]string, string, error) {
	const (
		APIPath         = "/v1/key/list"
		Method          = http.MethodGet
		StatusOK        = http.StatusOK
		MaxResponseSize = 1 * mem.MiB
	)
	type Response struct {
		Names      []string `json:"names"`
		ContinueAt string   `json:"continue_at"`
	}
	c.init.Do(c.initLoadBalancer)

	client := retry(c.HTTPClient)
	resp, err := c.lb.Send(ctx, &client, Method, join(APIPath, prefix), nil)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return nil, "", parseErrorResponse(resp)
	}

	if resp.Header.Get("Content-Type") == "application/x-ndjson" {
		return parseLegacyListing(resp.Body, n)
	}
	var response Response
	if err = json.NewDecoder(mem.LimitReader(resp.Body, MaxResponseSize)).Decode(&response); err != nil {
		return nil, "", err
	}
	return response.Names, response.ContinueAt, nil
}

// DescribePolicy returns the PolicyInfo for the given policy.
// It returns ErrPolicyNotFound if no such policy exists.
func (c *Client) DescribePolicy(ctx context.Context, name string) (*PolicyInfo, error) {
	const (
		APIPath         = "/v1/policy/describe"
		Method          = http.MethodGet
		StatusOK        = http.StatusOK
		MaxResponseSize = 1 * mem.MiB
	)
	c.init.Do(c.initLoadBalancer)

	type Response struct {
		CreatedAt time.Time `json:"created_at"`
		CreatedBy Identity  `json:"created_by"`
	}
	client := retry(c.HTTPClient)
	resp, err := c.lb.Send(ctx, &client, Method, join(APIPath, name), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return nil, parseErrorResponse(resp)
	}

	var response Response
	if err = json.NewDecoder(mem.LimitReader(resp.Body, MaxResponseSize)).Decode(&response); err != nil {
		return nil, err
	}
	return &PolicyInfo{
		Name:      name,
		CreatedAt: response.CreatedAt,
		CreatedBy: response.CreatedBy,
	}, nil
}

// GetPolicy returns the policy with the given name.
// It returns ErrPolicyNotFound if no such policy
// exists.
func (c *Client) GetPolicy(ctx context.Context, name string) (*Policy, error) {
	const (
		APIPath         = "/v1/policy/read"
		Method          = http.MethodGet
		StatusOK        = http.StatusOK
		MaxResponseSize = 1 * mem.MiB
	)
	c.init.Do(c.initLoadBalancer)

	type Response struct {
		Allow     map[string]Rule `json:"allow"`
		Deny      map[string]Rule `json:"deny"`
		CreatedAt time.Time       `json:"created_at"`
		CreatedBy Identity        `json:"created_by"`
	}
	client := retry(c.HTTPClient)
	resp, err := c.lb.Send(ctx, &client, Method, join(APIPath, name), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return nil, parseErrorResponse(resp)
	}

	var response Response
	if err = json.NewDecoder(mem.LimitReader(resp.Body, MaxResponseSize)).Decode(&response); err != nil {
		return nil, err
	}
	return &Policy{
		Allow:     response.Allow,
		Deny:      response.Deny,
		CreatedAt: response.CreatedAt,
		CreatedBy: response.CreatedBy,
	}, nil
}

// ListPolicies returns a paginated list of policy names from the server,
// starting at the specified prefix. If n > 0, it returns at most n names.
// Otherwise, the server determines the page size.
//
// ListPolicies also returns a continuation token for fetching the next batch.
// When the listing reaches the end, the continuation token will be empty.
//
// The ListIter type can be used as a convenient way to iterate over a paginated list.
func (c *Client) ListPolicies(ctx context.Context, prefix string, n int) ([]string, string, error) {
	const (
		APIPath         = "/v1/policy/list"
		Method          = http.MethodGet
		StatusOK        = http.StatusOK
		MaxResponseSize = 1 * mem.MiB
	)
	type Response struct {
		Names      []string `json:"names"`
		ContinueAt string   `json:"continue_at"`
	}
	c.init.Do(c.initLoadBalancer)

	client := retry(c.HTTPClient)
	resp, err := c.lb.Send(ctx, &client, Method, join(APIPath, prefix), nil)
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode != StatusOK {
		return nil, "", parseErrorResponse(resp)
	}

	if resp.Header.Get("Content-Type") == "application/x-ndjson" {
		return parseLegacyListing(resp.Body, n)
	}
	var response Response
	if err = json.NewDecoder(mem.LimitReader(resp.Body, MaxResponseSize)).Decode(&response); err != nil {
		return nil, "", err
	}
	return response.Names, response.ContinueAt, nil
}

// DescribeIdentity returns an IdentityInfo describing the given identity.
func (c *Client) DescribeIdentity(ctx context.Context, identity Identity) (*IdentityInfo, error) {
	const (
		APIPath         = "/v1/identity/describe"
		Method          = http.MethodGet
		StatusOK        = http.StatusOK
		MaxResponseSize = 1 * mem.MiB
	)
	c.init.Do(c.initLoadBalancer)

	type Response struct {
		Policy    string     `json:"policy"`
		IsAdmin   bool       `json:"admin"`
		TTL       string     `json:"ttl"`
		ExpiresAt time.Time  `json:"expires_at"`
		CreatedAt time.Time  `json:"created_at"`
		CreatedBy Identity   `json:"created_by"`
		Children  []Identity `json:"children"`
	}

	client := retry(c.HTTPClient)
	resp, err := c.lb.Send(ctx, &client, Method, join(APIPath, identity.String()), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return nil, parseErrorResponse(resp)
	}
	var response Response
	if err = json.NewDecoder(mem.LimitReader(resp.Body, MaxResponseSize)).Decode(&response); err != nil {
		return nil, err
	}
	var ttl time.Duration
	if response.TTL != "" {
		ttl, err = time.ParseDuration(response.TTL)
		if err != nil {
			return nil, err
		}
	}
	return &IdentityInfo{
		Identity:  identity,
		Policy:    response.Policy,
		IsAdmin:   response.IsAdmin,
		CreatedAt: response.CreatedAt,
		CreatedBy: response.CreatedBy,
		TTL:       ttl,
		ExpiresAt: response.ExpiresAt,
	}, nil
}

// DescribeSelf returns an IdentityInfo describing the identity
// making the API request. It also returns the assigned policy,
// if any.
//
// DescribeSelf allows an application to obtain identity and
// policy information about itself.
func (c *Client) DescribeSelf(ctx context.Context) (*IdentityInfo, *Policy, error) {
	const (
		APIPath         = "/v1/identity/self/describe"
		Method          = http.MethodGet
		StatusOK        = http.StatusOK
		MaxResponseSize = 1 * mem.MiB
	)
	c.init.Do(c.initLoadBalancer)

	type Response struct {
		Identity  Identity   `json:"identity"`
		IsAdmin   bool       `json:"admin"`
		TTL       string     `json:"ttl"`
		ExpiresAt time.Time  `json:"expires_at"`
		CreatedAt time.Time  `json:"created_at"`
		CreatedBy Identity   `json:"created_by"`
		Children  []Identity `json:"children"`

		Policy string          `json:"policy"`
		Allow  map[string]Rule `json:"allow"`
		Deny   map[string]Rule `json:"deny"`
	}

	client := retry(c.HTTPClient)
	resp, err := c.lb.Send(ctx, &client, Method, APIPath, nil)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return nil, nil, parseErrorResponse(resp)
	}
	var response Response
	if err = json.NewDecoder(mem.LimitReader(resp.Body, MaxResponseSize)).Decode(&response); err != nil {
		return nil, nil, err
	}
	var ttl time.Duration
	if response.TTL != "" {
		ttl, err = time.ParseDuration(response.TTL)
		if err != nil {
			return nil, nil, err
		}
	}
	info := &IdentityInfo{
		Identity:  response.Identity,
		Policy:    response.Policy,
		CreatedAt: response.CreatedAt,
		CreatedBy: response.CreatedBy,
		IsAdmin:   response.IsAdmin,
		TTL:       ttl,
		ExpiresAt: response.ExpiresAt,
	}
	policy := &Policy{
		Allow: response.Allow,
		Deny:  response.Deny,
	}
	return info, policy, nil
}

// ListIdentities returns a paginated list of identities from the server,
// starting at the specified prefix. If n > 0, it returns at most n identities.
// Otherwise, the server determines the page size.
//
// ListIdentities also returns a continuation token for fetching the next batch.
// When the listing reaches the end, the continuation token will be empty.
//
// The ListIter type can be used as a convenient way to iterate over a paginated list.
func (c *Client) ListIdentities(ctx context.Context, prefix string, n int) ([]Identity, string, error) {
	const (
		APIPath         = "/v1/identity/list"
		Method          = http.MethodGet
		StatusOK        = http.StatusOK
		MaxResponseSize = 1 * mem.MiB
	)
	type Response struct {
		Names      []Identity `json:"identities"`
		ContinueAt string     `json:"continue_at"`
	}
	c.init.Do(c.initLoadBalancer)

	client := retry(c.HTTPClient)
	resp, err := c.lb.Send(ctx, &client, Method, join(APIPath, prefix), nil)
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode != StatusOK {
		return nil, "", parseErrorResponse(resp)
	}

	if resp.Header.Get("Content-Type") == "application/x-ndjson" {
		return parseLegacyIdentityListing(resp.Body, n)
	}
	var response Response
	if err = json.NewDecoder(mem.LimitReader(resp.Body, MaxResponseSize)).Decode(&response); err != nil {
		return nil, "", err
	}
	return response.Names, response.ContinueAt, nil
}

// AuditLog returns a stream of audit events produced by the
// KES server. The stream does not contain any events that
// happened in the past.
//
// It returns ErrNotAllowed if the client does not
// have sufficient permissions to subscribe to the
// audit log.
func (c *Client) AuditLog(ctx context.Context) (*AuditStream, error) {
	const (
		APIPath  = "/v1/log/audit"
		Method   = http.MethodGet
		StatusOK = http.StatusOK
	)
	c.init.Do(c.initLoadBalancer)

	client := retry(c.HTTPClient)
	resp, err := c.lb.Send(ctx, &client, Method, APIPath, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != StatusOK {
		return nil, parseErrorResponse(resp)
	}
	return NewAuditStream(resp.Body), nil
}

// ErrorLog returns a stream of error events produced by the
// KES server. The stream does not contain any events that
// happened in the past.
//
// It returns ErrNotAllowed if the client does not
// have sufficient permissions to subscribe to the
// error log.
func (c *Client) ErrorLog(ctx context.Context) (*ErrorStream, error) {
	const (
		APIPath  = "/v1/log/error"
		Method   = http.MethodGet
		StatusOK = http.StatusOK
	)
	c.init.Do(c.initLoadBalancer)

	client := retry(c.HTTPClient)
	resp, err := c.lb.Send(ctx, &client, Method, APIPath, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != StatusOK {
		return nil, parseErrorResponse(resp)
	}
	return NewErrorStream(resp.Body), nil
}

// Metrics returns a KES server metric snapshot.
//
// It returns ErrNotAllowed if the client does not
// have sufficient permissions to fetch server metrics.
func (c *Client) Metrics(ctx context.Context) (Metric, error) {
	const (
		APIPath        = "/v1/metrics"
		Method         = http.MethodGet
		StatusOK       = http.StatusOK
		MaxResponeSize = 1 * mem.MiB
	)
	c.init.Do(c.initLoadBalancer)

	client := retry(c.HTTPClient)
	resp, err := c.lb.Send(ctx, &client, Method, APIPath, nil)
	if err != nil {
		return Metric{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return Metric{}, parseErrorResponse(resp)
	}

	const (
		MetricRequestOK         = "kes_http_request_success"
		MetricRequestErr        = "kes_http_request_error"
		MetricRequestFail       = "kes_http_request_failure"
		MetricRequestActive     = "kes_http_request_active"
		MetricAuditEvents       = "kes_log_audit_events"
		MetricErrorEvents       = "kes_log_error_events"
		MetricResponseTime      = "kes_http_response_time"
		MetricSystemUpTme       = "kes_system_up_time"
		MetricSystemCPUs        = "kes_system_num_cpu"
		MetricSystemUsableCPUs  = "kes_system_num_cpu_used"
		MetricSystemThreads     = "kes_system_num_threads"
		MetricSystemHeapUsed    = "kes_system_mem_heap_used"
		MetricSystemHeapObjects = "kes_system_mem_heap_objects"
		MetricSystemStackUsed   = "kes_system_mem_stack_used"
	)

	var (
		metric       Metric
		metricFamily dto.MetricFamily
	)
	decoder := expfmt.NewDecoder(mem.LimitReader(resp.Body, MaxResponeSize), expfmt.ResponseFormat(resp.Header))
	for {
		err := decoder.Decode(&metricFamily)
		if err == io.EOF {
			break
		}
		if err != nil {
			return Metric{}, err
		}

		if len(metricFamily.Metric) == 0 {
			return Metric{}, errors.New("kes: server response contains no metric")
		}
		var (
			name = metricFamily.GetName()
			kind = metricFamily.GetType()
		)
		switch {
		case kind == dto.MetricType_COUNTER && name == MetricRequestOK:
			for _, m := range metricFamily.GetMetric() {
				metric.RequestOK += uint64(m.GetCounter().GetValue())
			}
		case kind == dto.MetricType_COUNTER && name == MetricRequestErr:
			for _, m := range metricFamily.GetMetric() {
				metric.RequestErr += uint64(m.GetCounter().GetValue())
			}
		case kind == dto.MetricType_COUNTER && name == MetricRequestFail:
			for _, m := range metricFamily.GetMetric() {
				metric.RequestFail += uint64(m.GetCounter().GetValue())
			}
		default:
			if len(metricFamily.Metric) != 1 {
				return Metric{}, errors.New("kes: server response contains more than one metric")
			}
			rawMetric := metricFamily.GetMetric()[0] // Safe since we checked length before
			switch {
			case kind == dto.MetricType_GAUGE && name == MetricRequestActive:
				metric.RequestActive = uint64(rawMetric.GetGauge().GetValue())
			case kind == dto.MetricType_COUNTER && name == MetricAuditEvents:
				metric.AuditEvents = uint64(rawMetric.GetCounter().GetValue())
			case kind == dto.MetricType_COUNTER && name == MetricErrorEvents:
				metric.ErrorEvents = uint64(rawMetric.GetCounter().GetValue())
			case kind == dto.MetricType_HISTOGRAM && name == MetricResponseTime:
				metric.LatencyHistogram = map[time.Duration]uint64{}
				for _, bucket := range rawMetric.GetHistogram().GetBucket() {
					if math.IsInf(bucket.GetUpperBound(), 0) { // Ignore the +Inf bucket
						continue
					}

					duration := time.Duration(1000*bucket.GetUpperBound()) * time.Millisecond
					metric.LatencyHistogram[duration] = bucket.GetCumulativeCount()
				}
				delete(metric.LatencyHistogram, 0) // Delete the artificial zero entry
			case kind == dto.MetricType_GAUGE && name == MetricSystemUpTme:
				metric.UpTime = time.Duration(rawMetric.GetGauge().GetValue()) * time.Second
			case kind == dto.MetricType_GAUGE && name == MetricSystemCPUs:
				metric.CPUs = int(rawMetric.GetGauge().GetValue())
			case kind == dto.MetricType_GAUGE && name == MetricSystemUsableCPUs:
				metric.UsableCPUs = int(rawMetric.GetGauge().GetValue())
			case kind == dto.MetricType_GAUGE && name == MetricSystemThreads:
				metric.Threads = int(rawMetric.GetGauge().GetValue())
			case kind == dto.MetricType_GAUGE && name == MetricSystemHeapUsed:
				metric.HeapAlloc = uint64(rawMetric.GetGauge().GetValue())
			case kind == dto.MetricType_GAUGE && name == MetricSystemHeapObjects:
				metric.HeapObjects = uint64(rawMetric.GetGauge().GetValue())
			case kind == dto.MetricType_GAUGE && name == MetricSystemStackUsed:
				metric.StackAlloc = uint64(rawMetric.GetGauge().GetValue())
			}
		}
	}
	return metric, nil
}

func (c *Client) initLoadBalancer() {
	if c.lb == nil {
		c.lb = newLoadBalancer("")
		c.lb.prepareLoadBalancer(c.Endpoints)
	}
}

// Join joins any number of arguments with the API path.
// All arguments are path-escaped before joining.
func join(api string, args ...string) string {
	for _, arg := range args {
		api = path.Join(api, url.PathEscape(arg))
	}
	return api
}

// endpoint returns an endpoint URL starting with the
// given endpoint followed by the path elements.
//
// For example:
//   - endpoint("https://127.0.0.1:7373", "version")                => "https://127.0.0.1:7373/version"
//   - endpoint("https://127.0.0.1:7373/", "/key/create", "my-key") => "https://127.0.0.1:7373/key/create/my-key"
//
// Any leading or trailing whitespaces are removed from
// the endpoint before it is concatenated with the path
// elements.
//
// The path elements will not be URL-escaped.
func endpoint(endpoint string, elems ...string) string {
	endpoint = strings.TrimSpace(endpoint)
	endpoint = strings.TrimSuffix(endpoint, "/")

	if len(elems) > 0 && !strings.HasPrefix(elems[0], "/") {
		endpoint += "/"
	}
	return endpoint + path.Join(elems...)
}
