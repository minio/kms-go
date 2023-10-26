// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"aead.dev/mem"
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

// Enclave returns a new Enclave with the given name.
func (c *Client) Enclave(name string) *Enclave {
	return &Enclave{
		Name:       name,
		Endpoints:  append(make([]string, 0, len(c.Endpoints)), c.Endpoints...),
		HTTPClient: c.HTTPClient,
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

// ExpandCluster expands a KES cluster by adding a new node with
// the given endpoint.
func (c *Client) ExpandCluster(ctx context.Context, endpoint string) error {
	const (
		APIPath  = "/v1/cluster/expand"
		Method   = http.MethodPut
		StatusOK = http.StatusOK
	)
	type Request struct {
		Endpoint string `json:"endpoint"`
	}
	c.init.Do(c.initLoadBalancer)

	body, err := json.Marshal(Request{
		Endpoint: endpoint,
	})
	if err != nil {
		return err
	}

	client := retry(c.HTTPClient)
	resp, err := c.lb.Send(ctx, &client, Method, APIPath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return parseErrorResponse(resp)
	}
	return nil
}

// DescribeCluster returns the KeyCluster for the current cluster.
func (c *Client) DescribeCluster(ctx context.Context) (*ClusterInfo, error) {
	const (
		APIPath         = "/v1/cluster/describe"
		Method          = http.MethodGet
		StatusOK        = http.StatusOK
		MaxResponseSize = 1 * mem.MiB
	)
	type Response struct {
		Nodes  map[uint64]string `json:"nodes"`
		Leader uint64            `json:"leader_id"`
	}
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
	var response Response
	if err := json.NewDecoder(mem.LimitReader(resp.Body, MaxResponseSize)).Decode(&response); err != nil {
		return nil, err
	}
	return &ClusterInfo{
		Nodes:  response.Nodes,
		Leader: response.Leader,
	}, nil
}

// ShrinkCluster shrinks a KES cluster by removingt the new node with
// the given endpoint from the cluster.
func (c *Client) ShrinkCluster(ctx context.Context, endpoint string) error {
	const (
		APIPath  = "/v1/cluster/shrink"
		Method   = http.MethodDelete
		StatusOK = http.StatusOK
	)
	type Request struct {
		Endpoint string `json:"endpoint"`
	}
	c.init.Do(c.initLoadBalancer)

	body, err := json.Marshal(Request{
		Endpoint: endpoint,
	})
	if err != nil {
		return err
	}

	client := retry(c.HTTPClient)
	resp, err := c.lb.Send(ctx, &client, Method, APIPath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return parseErrorResponse(resp)
	}
	return nil
}

// CreateEnclave creates a new enclave with the given
// identity as enclave admin. Only the KES system
// admin can create new enclaves.
//
// It returns ErrEnclaveExists if the enclave already
// exists.
func (c *Client) CreateEnclave(ctx context.Context, name string) error {
	const (
		APIPath  = "/v1/enclave/create"
		Method   = http.MethodPut
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

// DescribeEnclave returns an EnclaveInfo describing the
// specified enclave. Only the KES system admin can create
// fetch enclave descriptions.
//
// It returns ErrEnclaveNotFound if the enclave does not
// exists.
func (c *Client) DescribeEnclave(ctx context.Context, name string) (*EnclaveInfo, error) {
	const (
		APIPath         = "/v1/enclave/describe"
		Method          = http.MethodGet
		StatusOK        = http.StatusOK
		MaxResponseSize = 1 * mem.MiB
	)
	type Response struct {
		Name      string    `json:"name"`
		CreatedAt time.Time `json:"created_at"`
		CreatedBy Identity  `json:"created_by"`
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
	return &EnclaveInfo{
		Name:      response.Name,
		CreatedAt: response.CreatedAt,
		CreatedBy: response.CreatedBy,
	}, nil
}

// ListEnclaves returns a paginated list of enclave names from the server,
// starting at the specified prefix. If n > 0, it returns at most n names.
// Otherwise, the server determines the page size.
//
// ListEnclaves also returns a continuation token for fetching the next batch.
// When the listing reaches the end, the continuation token will be empty.
//
// The ListIter type can be used as a convenient way to iterate over a paginated list.
func (c *Client) ListEnclaves(ctx context.Context, prefix string, n int) ([]string, string, error) {
	const (
		APIPath         = "/v1/enclave/list"
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

	var response Response
	if err := json.NewDecoder(mem.LimitReader(resp.Body, MaxResponseSize)).Decode(&response); err != nil {
		return nil, "", err
	}
	if n > 0 && n < len(response.Names) {
		return response.Names[:n], response.Names[n], nil
	}
	return response.Names, response.ContinueAt, nil
}

// DeleteEnclave delete the specified enclave. Only the
// KES system admin can delete enclaves.
//
// It returns ErrEnclaveNotFound if the enclave does not
// exist.
func (c *Client) DeleteEnclave(ctx context.Context, name string) error {
	const (
		APIPath  = "/v1/enclave/delete"
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

// CreateKey creates a new cryptographic key. The key will
// be generated by the KES server.
//
// It returns ErrKeyExists if a key with the same name already
// exists.
func (c *Client) CreateKey(ctx context.Context, name string) error {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.CreateKey(ctx, name)
}

// ImportKey imports the given key into a KES server. It
// returns ErrKeyExists if a key with the same key already
// exists.
func (c *Client) ImportKey(ctx context.Context, name string, req *ImportKeyRequest) error {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.ImportKey(ctx, name, req)
}

// DescribeKey returns the KeyInfo for the given key.
// It returns ErrKeyNotFound if no such key exists.
func (c *Client) DescribeKey(ctx context.Context, name string) (*KeyInfo, error) {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.DescribeKey(ctx, name)
}

// DeleteKey deletes the key from a KES server. It returns
// ErrKeyNotFound if no such key exists.
func (c *Client) DeleteKey(ctx context.Context, name string) error {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.DeleteKey(ctx, name)
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
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.GenerateKey(ctx, name, context)
}

// Encrypt encrypts the given plaintext with the named key at the
// KES server. The optional context is cryptographically bound to
// the returned ciphertext. The exact same context must be provided
// when decrypting the ciphertext again.
//
// Encrypt returns ErrKeyNotFound if no such key exists at the KES
// server.
func (c *Client) Encrypt(ctx context.Context, name string, plaintext, context []byte) ([]byte, error) {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.Encrypt(ctx, name, plaintext, context)
}

// Decrypt decrypts the ciphertext with the named key at the KES
// server. The exact same context, used during Encrypt, must be
// provided.
//
// Decrypt returns ErrKeyNotFound if no such key exists. It returns
// ErrDecrypt when the ciphertext has been modified or a different
// context value is provided.
func (c *Client) Decrypt(ctx context.Context, name string, ciphertext, context []byte) ([]byte, error) {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.Decrypt(ctx, name, ciphertext, context)
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
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.ListKeys(ctx, prefix, n)
}

// CreateSecret creates a new secret with the given name.
//
// It returns ErrSecretExists if a secret with the same name
// already exists.
func (c *Client) CreateSecret(ctx context.Context, name string, value []byte, options *SecretOptions) error {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.CreateSecret(ctx, name, value, options)
}

// DescribeSecret returns the SecretInfo for the given secret.
//
// It returns ErrSecretNotFound if no such secret exists.
func (c *Client) DescribeSecret(ctx context.Context, name string) (*SecretInfo, error) {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.DescribeSecret(ctx, name)
}

// ReadSecret returns the secret with the given name.
//
// It returns ErrSecretNotFound if no such secret exists.
func (c *Client) ReadSecret(ctx context.Context, name string) ([]byte, *SecretInfo, error) {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.ReadSecret(ctx, name)
}

// DeleteSecret deletes the secret with the given name.
//
// It returns ErrSecretNotFound if no such secret exists.
func (c *Client) DeleteSecret(ctx context.Context, name string) error {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.DeleteSecret(ctx, name)
}

// ListSecrets returns a paginated list of secret names from the server,
// starting at the specified prefix. If n > 0, it returns at most n names.
// Otherwise, the server determines the page size.
//
// ListSecrets also returns a continuation token for fetching the next batch.
// When the listing reaches the end, the continuation token will be empty.
//
// The ListIter type can be used as a convenient way to iterate over a paginated list.
func (c *Client) ListSecrets(ctx context.Context, prefix string, n int) ([]string, string, error) {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.ListSecrets(ctx, prefix, n)
}

// CreatePolicy creates a new policy.
//
// It returns ErrPolicyExists if such a policy already exists.
func (c *Client) CreatePolicy(ctx context.Context, name string, policy *Policy) error {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.CreatePolicy(ctx, name, policy)
}

// DescribePolicy returns the PolicyInfo for the given policy.
// It returns ErrPolicyNotFound if no such policy exists.
func (c *Client) DescribePolicy(ctx context.Context, name string) (*PolicyInfo, error) {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.DescribePolicy(ctx, name)
}

// GetPolicy returns the policy with the given name.
// It returns ErrPolicyNotFound if no such policy
// exists.
func (c *Client) GetPolicy(ctx context.Context, name string) (*Policy, error) {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.GetPolicy(ctx, name)
}

// DeletePolicy deletes the policy with the given name. Any
// assigned identities will be removed as well.
//
// It returns ErrPolicyNotFound if no such policy exists.
func (c *Client) DeletePolicy(ctx context.Context, name string) error {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.DeletePolicy(ctx, name)
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
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.ListPolicies(ctx, prefix, n)
}

// AssignPolicy assigns the policy to the identity.
// The KES admin identity cannot be assigned to any
// policy.
//
// AssignPolicy returns PolicyNotFound if no such policy exists.
func (c *Client) AssignPolicy(ctx context.Context, policy string, identity Identity) error {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.AssignPolicy(ctx, policy, identity)
}

// DescribeIdentity returns an IdentityInfo describing the given identity.
func (c *Client) DescribeIdentity(ctx context.Context, identity Identity) (*IdentityInfo, error) {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.DescribeIdentity(ctx, identity)
}

// DescribeSelf returns an IdentityInfo describing the identity
// making the API request. It also returns the assigned policy,
// if any.
//
// DescribeSelf allows an application to obtain identity and
// policy information about itself.
func (c *Client) DescribeSelf(ctx context.Context) (*IdentityInfo, *Policy, error) {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.DescribeSelf(ctx)
}

// DeleteIdentity removes the identity. Once removed, any
// operation issued by this identity will fail with
// ErrNotAllowed.
//
// The KES admin identity cannot be removed.
func (c *Client) DeleteIdentity(ctx context.Context, identity Identity) error {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.DeleteIdentity(ctx, identity)
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
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.ListIdentities(ctx, prefix, n)
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
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.Metrics(ctx)
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
