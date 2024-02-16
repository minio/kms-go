// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kms

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/minio/kms-go/kms/cmds"
	"github.com/minio/kms-go/kms/internal/api"
	"github.com/minio/kms-go/kms/internal/headers"
	"github.com/minio/kms-go/kms/internal/https"
	pb "github.com/minio/kms-go/kms/protobuf"
)

// Config is a structure containing configuration
// options for KMS clients.
type Config struct {
	// List of KMS cluster node endpoints. The Client
	// tries to distribute requests uniformly across
	// all endpoints.
	Endpoints []string

	// APIKey to authenticate to the KMS cluster.
	//
	// When providing an API key, no TLS.Certificates
	// or TLS.GetClientCertificate must be present.
	APIKey APIKey

	// Optional TLS configuration.
	//
	// If no API key is set, either a TLS.Certificates
	// or TLS.GetClientCertificate must be present.
	TLS *tls.Config
}

// NewClient returns a new Client with the given configuration.
func NewClient(conf *Config) (*Client, error) {
	if conf.APIKey == nil && (conf.TLS == nil || (len(conf.TLS.Certificates) == 0 && conf.TLS.GetClientCertificate == nil)) {
		return nil, errors.New("kms: invalid config: no API key or TLS client certificate provided")
	}
	if conf.APIKey != nil && conf.TLS != nil && len(conf.TLS.Certificates) > 0 {
		return nil, errors.New("kms: invalid config: 'APIKey' and 'TLS.Certificates' are present")
	}
	if conf.APIKey != nil && conf.TLS != nil && conf.TLS.GetClientCertificate != nil {
		return nil, errors.New("kms: invalid config: 'APIKey' and 'TLS.GetClientCertificate' are present")
	}

	tlsConf := conf.TLS.Clone()
	if conf.APIKey != nil {
		cert, err := generateCertificate(conf.APIKey)
		if err != nil {
			return nil, err
		}
		tlsConf.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &cert, nil
		}
	}

	hosts := make([]string, 0, len(conf.Endpoints))
	for _, endpoint := range conf.Endpoints {
		endpoint = strings.TrimSpace(endpoint)
		endpoint = strings.TrimPrefix(endpoint, "http://")
		endpoint = strings.TrimPrefix(endpoint, "https://")
		hosts = append(hosts, endpoint)
	}
	if len(hosts) == 0 {
		hosts = []string{"127.0.0.1:7373"}
	}

	lb := &https.LoadBalancer{
		Hosts: hosts,
		RoundTripper: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConnsPerHost:   50,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       tlsConf,
		},
	}
	return &Client{
		direct: http.Client{Transport: lb.RoundTripper},
		client: http.Client{Transport: lb},
		lb:     lb,
	}, nil
}

// Client is a KMS client. It performs client-side load balancing
// across all its KMS cluster node endpoints.
type Client struct {
	// Direct HTTP client without load balancing.
	// It shares the underlying RoundTripper with
	// the regular client. Should be used when
	// load balancing and retries are not desired.
	// For example, when trying to fetch status
	// information about one particular node.
	direct http.Client

	client http.Client // Client that uses the LB as RoundTripper
	lb     *https.LoadBalancer
}

// Hosts returns a list of KMS servers currently used by client.
func (c *Client) Hosts() []string { return slices.Clone(c.lb.Hosts) }

// Send executes a KMS request, returning a Response for the provided
// Request.
//
// If req.Host is empty, the Client selects the KMS server automatically
// and retries failed requests on other KMS servers, if available.
// When this behavior is not desirable, for example when trying to
// communicate with one particular KMS server, req.Host should be set
// to the server host or host:port.
//
// Send is a low-level API. Most callers should use higher-level
// functionality, like creating a key using CreateKey.
//
// The returned error is of type *HostError.
func (c *Client) Send(ctx context.Context, req *Request) (*http.Response, error) {
	const (
		Method   = http.MethodPost
		Path     = "/v1/kms/"
		StatusOK = http.StatusOK
	)

	var (
		err    error
		reqURL string
		host   = req.Host
	)
	if host == "" {
		reqURL, host, err = c.lb.URL(Path, req.Enclave)
	} else {
		reqURL, err = url.JoinPath(httpsURL(host), Path, req.Enclave)
	}
	if err != nil {
		return nil, hostError(host, err)
	}

	r, err := http.NewRequestWithContext(ctx, Method, reqURL, bytes.NewReader(req.Body))
	if err != nil {
		return nil, hostError(host, err)
	}
	r.ContentLength = int64(len(req.Body))
	r.Header.Add(headers.Accept, headers.ContentTypeAppAny) // accept binary and json
	r.Header.Set(headers.ContentType, headers.ContentTypeBinary)

	var resp *http.Response
	if req.Host == "" {
		resp, err = c.client.Do(r) // Without req.Host, use the client LB.
	} else {
		resp, err = c.direct.Do(r) // With an explicit req.Host, don't use client LB.
	}
	if err != nil {
		return nil, hostError(host, err)
	}
	if resp.StatusCode != StatusOK {
		defer resp.Body.Close()

		return nil, hostError(host, readError(resp))
	}
	return resp, nil
}

// Version returns version information from one or multiple KMS servers.
// If req.Hosts is empty, the Client tries to fetch version information
// from all its hosts.
//
// For a single host, Version returns its version information and a
// HostError wrapping the first error encountered, if any.
//
// For multiple hosts, Version returns a list of version responses. If
// it fails to fetch version information from some hosts, it returns a
// joined error that implements the "Unwrap() []error" interface. Each
// of these errors are of type HostError.
func (c *Client) Version(ctx context.Context, req *VersionRequest) ([]*VersionResponse, error) {
	const (
		Method      = http.MethodGet
		Path        = api.PathVersion
		StatusOK    = http.StatusOK
		ContentType = headers.ContentTypeAppAny // accept JSON or protobuf
	)
	version := func(ctx context.Context, endpoint string) (*VersionResponse, error) {
		url, err := url.JoinPath(httpsURL(endpoint), Path)
		if err != nil {
			return nil, hostError(endpoint, err)
		}
		r, err := http.NewRequestWithContext(ctx, Method, url, nil)
		if err != nil {
			return nil, hostError(endpoint, err)
		}
		r.Header.Set(headers.Accept, ContentType)

		resp, err := c.direct.Do(r)
		if err != nil {
			return nil, hostError(endpoint, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != StatusOK {
			return nil, hostError(endpoint, readError(resp))
		}

		var data VersionResponse
		if err := readResponse(resp, &data); err != nil {
			return nil, hostError(endpoint, err)
		}
		return &data, nil
	}

	endpoints := req.Hosts
	if len(endpoints) == 0 {
		endpoints = c.lb.Hosts
	}
	if len(endpoints) == 1 {
		resp, err := version(ctx, endpoints[0])
		if err != nil {
			return []*VersionResponse{}, err
		}
		return []*VersionResponse{resp}, nil
	}

	resps := make([]*VersionResponse, len(endpoints))
	errs := make([]error, len(endpoints))

	var wg sync.WaitGroup
	for i := range endpoints {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()
			resps[i], errs[i] = version(ctx, endpoints[i])
		}(i)
	}
	wg.Wait()

	// Compact responses by filtering all nil values without alloc.
	responses := resps[:0]
	for _, r := range resps {
		if r != nil {
			responses = append(responses, r)
		}
	}
	return responses[:len(responses):len(responses)], errors.Join(errs...)
}

// Live reports whether one or multiple KMS servers are alive. If
// req.Hosts is empty, the Client checks the liveness of all hosts.
//
// The liveness probe just reports whether the KMS servers are listening
// and responding to requests at all. It does not report whether the
// servers are ready to handle requests. Use the Ready method for checking
// the servers ability to handle read or write requests.
//
// For a single host, Live returns a nil error if the host is alive or
// a HostError wrapping the encountered error.
//
// For multiple hosts, Live only returns a nil error if all hosts are
// alive. If some nodes are not alive, it returns a joined error that
// implements the "Unwrap() []error" interface. Each of these errors
// are of type HostError.
func (c *Client) Live(ctx context.Context, req *LivenessRequest) error {
	const (
		Method      = http.MethodGet
		Path        = api.PathHealthLive
		StatusOK    = http.StatusOK
		ContentType = headers.ContentTypeAppAny // accept JSON or protobuf
	)
	live := func(ctx context.Context, endpoint string) error {
		url, err := url.JoinPath(httpsURL(endpoint), Path)
		if err != nil {
			return hostError(endpoint, err)
		}
		r, err := http.NewRequestWithContext(ctx, Method, url, nil)
		if err != nil {
			return hostError(endpoint, err)
		}
		r.Header.Set(headers.Accept, ContentType)

		resp, err := c.direct.Do(r)
		if err != nil {
			return hostError(endpoint, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != StatusOK {
			return hostError(endpoint, readError(resp))
		}
		return nil
	}

	endpoints := req.Hosts
	if len(endpoints) == 0 {
		endpoints = c.lb.Hosts
	}
	if len(endpoints) == 1 {
		return live(ctx, endpoints[0])
	}

	errs := make([]error, len(endpoints))
	var wg sync.WaitGroup
	for i := range endpoints {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()
			errs[i] = live(ctx, endpoints[i])
		}(i)
	}
	wg.Wait()

	return errors.Join(errs...)
}

// Ready reports whether one or multiple KMS servers are ready to
// serve requests. If req.Hosts is empty, the Client checks the
// readiness of all hosts.
//
// By default, the readiness probe reports whether the servers are
// ready to serve "read" requests. Most KMS API operations, including
// en/decryption, signing or data key generation, are considered read
// requests.
// For checking the readiness for handling write requests, like key
// creation or deletion, set req.Write to true.
//
// For a single host, Ready returns a nil error if the host is ready
// to serve requests or a HostError wrapping the encountered error.
//
// For multiple hosts, Ready only returns a nil error if all hosts are
// ready. If some nodes are not ready, it returns a joined error that
// implements the "Unwrap() []error" interface. Each of these errors
// are of type HostError.
func (c *Client) Ready(ctx context.Context, req *ReadinessRequest) error {
	const (
		Method      = http.MethodGet
		Path        = api.PathHealthReady
		StatusOK    = http.StatusOK
		ContentType = headers.ContentTypeAppAny // accept JSON or protobuf
	)
	ready := func(ctx context.Context, endpoint string) error {
		url, err := url.JoinPath(httpsURL(endpoint), Path)
		if err != nil {
			return hostError(endpoint, err)
		}
		if req.Write {
			url += "?" + api.QueryReadyWrite
		}

		r, err := http.NewRequestWithContext(ctx, Method, url, nil)
		if err != nil {
			return hostError(endpoint, err)
		}
		r.Header.Set(headers.Accept, ContentType)

		resp, err := c.direct.Do(r)
		if err != nil {
			return hostError(endpoint, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != StatusOK {
			return hostError(endpoint, readError(resp))
		}
		return nil
	}

	endpoints := req.Hosts
	if len(endpoints) == 0 {
		endpoints = c.lb.Hosts
	}
	if len(endpoints) == 1 {
		return ready(ctx, endpoints[0])
	}

	errs := make([]error, len(endpoints))
	var wg sync.WaitGroup
	for i := range endpoints {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()
			errs[i] = ready(ctx, endpoints[i])
		}(i)
	}
	wg.Wait()

	return errors.Join(errs...)
}

// ClusterStatus returns status information about the entire KMS cluster.
// The returned ClusterStatusResponse contains status information for all
// nodes within the cluster. It requires SysAdmin privileges.
//
// The returned error is of type *HostError.
func (c *Client) ClusterStatus(ctx context.Context, _ *ClusterStatusRequest) (*ClusterStatusResponse, error) {
	body, err := cmds.Encode(nil, cmds.ClusterStatus, &ClusterStatusRequest{})
	if err != nil {
		return nil, err
	}

	resp, err := c.Send(ctx, &Request{
		Body: body,
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data ClusterStatusResponse
	if err := decodeResponse(resp, cmds.ClusterStatus, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// EditCluster edits the cluster definition of the KMS server req.Host.
// If req.Host is empty, the first host of the client's host list is used.
//
// Usually, editing the cluster definition directly is only ever necessary
// when repairing a cluster that has lost some nodes permanently. Hence,
// applications should only edit the cluster definition of one particular
// KMS server node and only when some cluster nodes are permanently
// unavailable.
//
// The client does not retry the request in case of a network error.
// Applications should make sure that the server node is available
// before editing its cluster definition. Refer to ServerStatus or
// ClusterStatus.
//
// It requires SysAdmin privileges.
//
// The returned error is of type *HostError.
func (c *Client) EditCluster(ctx context.Context, req *EditClusterRequest) error {
	body, err := cmds.Encode(nil, cmds.ClusterEdit, req)
	if err != nil {
		return err
	}

	resp, err := c.Send(ctx, &Request{
		Host: req.Host,
		Body: body,
	})
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// AddNode adds the KMS server at req.Host to the current KMS cluster.
// It returns an error if the server is already part of the cluster.
//
// Nodes can only join a cluster if the cluster has a leader. The KMS
// server at req.Host must be fresh in the sense that it must not be
// part of a multi-node cluster already.
//
// It requires SysAdmin privileges.
//
// The returned error is of type *HostError.
func (c *Client) AddNode(ctx context.Context, req *AddClusterNodeRequest) error {
	body, err := cmds.Encode(nil, cmds.ClusterAddNode, req)
	if err != nil {
		return err
	}

	resp, err := c.Send(ctx, &Request{
		Body: body,
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	c.lb.Hosts = append(c.lb.Hosts, req.Host)
	return nil
}

// RemoveNode removes the KMS server at req.Host from the current KMS
// cluster. It returns an error if the server is not part of the cluster.
//
// It requires SysAdmin privileges.
//
// The returned error is of type *HostError.
func (c *Client) RemoveNode(ctx context.Context, req *RemoveClusterNodeRequest) error {
	body, err := cmds.Encode(nil, cmds.ClusterRemoveNode, req)
	if err != nil {
		return err
	}

	resp, err := c.Send(ctx, &Request{
		Body: body,
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	hosts := make([]string, 0, len(c.lb.Hosts))
	for _, host := range c.lb.Hosts {
		if host != req.Host {
			hosts = append(hosts, host)
		}
	}
	c.lb.Hosts = hosts
	return nil
}

// ReadDB returns a snapshot of current KMS server database.
// The returned ReadDBResponse must be closed by the caller.
//
// It requires SysAdmin privileges.
//
// The returned error is of type *HostError.
func (c *Client) ReadDB(ctx context.Context) (*ReadDBResponse, error) {
	const (
		Method   = http.MethodGet
		Path     = api.PathDB
		StatusOK = http.StatusOK
	)

	url, host, err := c.lb.URL(Path)
	if err != nil {
		return nil, hostError(host, err)
	}
	r, err := http.NewRequestWithContext(ctx, Method, url, nil)
	if err != nil {
		return nil, hostError(host, err)
	}
	r.Header.Add(headers.Accept, headers.ContentTypeAppAny)
	r.Header.Add(headers.Accept, headers.ContentEncodingGZIP)

	resp, err := c.client.Do(r)
	if err != nil {
		return nil, hostError(host, err)
	}
	if resp.StatusCode != StatusOK {
		return nil, hostError(host, readError(resp))
	}

	// Decompress the response body if the HTTP client doesn't
	// decompress automatically.
	body := resp.Body
	if resp.Header.Get(headers.ContentEncoding) == headers.ContentEncodingGZIP {
		z, err := gzip.NewReader(body)
		if err != nil {
			return nil, hostError(host, err)
		}
		body = gzipReadCloser{
			gzip:   z,
			closer: body,
		}
	}
	return &ReadDBResponse{
		Body: body,
	}, nil
}

// CreateEnclave creates a new enclave with the name req.Name.
//
// It returns ErrEnclaveExists if such an enclave already exists
// wrapped in HostError.
//
// It requires SysAdmin privileges.
//
// The returned error is of type *HostError.
func (c *Client) CreateEnclave(ctx context.Context, req *CreateEnclaveRequest) error {
	body, err := cmds.Encode(nil, cmds.EnclaveCreate, req)
	if err != nil {
		return err
	}

	resp, err := c.Send(ctx, &Request{
		Body: body,
	})
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// DescribeEnclave returns metadata about the enclave with the
// the name req.Name.
//
// It returns ErrEnclaveNotFound if no such enclave exists
// wrapped in a HostError.
//
// It requires SysAdmin privileges.
//
// The returned error is of type *HostError.
func (c *Client) DescribeEnclave(ctx context.Context, req *EnclaveStatusRequest) (*EnclaveStatusResponse, error) {
	body, err := cmds.Encode(nil, cmds.EnclaveStatus, req)
	if err != nil {
		return nil, err
	}

	resp, err := c.Send(ctx, &Request{
		Body: body,
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data EnclaveStatusResponse
	if err := decodeResponse(resp, cmds.EnclaveStatus, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// DeleteEnclave deletes the enclave with the name req.Name.
//
// It returns ErrEnclaveNotFound if no such enclave exists
// wrapped in a HostError.
//
// It requires SysAdmin privileges.
//
// The returned error is of type *HostError.
func (c *Client) DeleteEnclave(ctx context.Context, req *DeleteEnclaveRequest) error {
	body, err := cmds.Encode(nil, cmds.EnclaveDelete, req)
	if err != nil {
		return err
	}

	resp, err := c.Send(ctx, &Request{
		Body: body,
	})
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// ListEnclaves returns the next page of a paginated listing of enclaves.
// All enclave names start with the req.Prefix and the first enclave name
// matches req.ContinueAt. The page contains at most req.Limit enclaves.
//
// ListEnclaves implements paginated listing. For iterating over a stream
// of enclaves combine it with an Iter.
//
// It requires SysAdmin privileges.
//
// The returned error is of type *HostError.
func (c *Client) ListEnclaves(ctx context.Context, req *ListRequest) (*Page[EnclaveStatusResponse], error) {
	body, err := cmds.Encode(nil, cmds.EnclaveList, req)
	if err != nil {
		return nil, err
	}

	resp, err := c.Send(ctx, &Request{
		Body: body,
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data pb.ListEnclavesResponse
	if err := decodeResponseMessage(resp, cmds.EnclaveList, &data); err != nil {
		return nil, err
	}

	ls := &Page[EnclaveStatusResponse]{
		Items:      make([]EnclaveStatusResponse, 0, len(data.Enclaves)),
		ContinueAt: data.ContinueAt,
	}
	for _, e := range data.Enclaves {
		var r EnclaveStatusResponse
		if err = r.UnmarshalPB(e); err != nil {
			return nil, hostError(resp.Request.URL.Host, err)
		}
		ls.Items = append(ls.Items, r)
	}
	return ls, nil
}

// CreateKey creates a new key with the name req.Name within req.Enclave.
// By default, a new key is created if and only if no such key exists. If
// req.AddVersion is true, a new key version is added to an existing key.
// The later is often referred to as key rotation.
//
// It returns ErrEnclaveNotFound if no such enclave exists and ErrKeyExists
// if such a key already exists wrapped in a HostError.
//
// The returned error is of type *HostError.
func (c *Client) CreateKey(ctx context.Context, req *CreateKeyRequest) error {
	body, err := cmds.Encode(nil, cmds.KeyCreate, req)
	if err != nil {
		return err
	}

	resp, err := c.Send(ctx, &Request{
		Enclave: req.Enclave,
		Body:    body,
	})
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// ImportKey imports an existing key with the name req.Name into req.Enclave.
// By default, a new key is created if and only if no such key exists. If
// req.AddVersion is true, a new key version is added to an existing key.
// The later is often referred to as key rotation.
//
// Keys that imported are marked by the KMS server to distinguish them from
// keys that never left the KMS boundary.
//
// It returns ErrEnclaveNotFound if no such enclave exists and ErrKeyExists
// if such a key already exists wrapped in a HostError.
//
// The returned error is of type *HostError.
func (c *Client) ImportKey(ctx context.Context, req *ImportKeyRequest) error {
	body, err := cmds.Encode(nil, cmds.KeyImport, req)
	if err != nil {
		return err
	}

	resp, err := c.Send(ctx, &Request{
		Enclave: req.Enclave,
		Body:    body,
	})
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// DescribeKeyVersion returns metadata about the key req.Name within
// the req.Enclave.
//
// It returns ErrEnclaveNotFound if no such enclave exists and
// ErrKeyNotFound if no such key exists wrapped in a HostError.
//
// The returned error is of type *HostError.
func (c *Client) DescribeKeyVersion(ctx context.Context, req *KeyStatusRequest) (*KeyStatusResponse, error) {
	body, err := cmds.Encode(nil, cmds.KeyStatus, req)
	if err != nil {
		return nil, err
	}

	resp, err := c.Send(ctx, &Request{
		Enclave: req.Enclave,
		Body:    body,
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data KeyStatusResponse
	if err := decodeResponse(resp, cmds.KeyStatus, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// DeleteKey deletes the key with the version req.Version from the key ring
// with the name req.Name within req.Enclave. It deletes the latest key
// version if no key version is specified and the entire key and all versions
// if req.AllVersions is true.
//
// It returns ErrEnclaveNotFound if no such enclave exists and ErrKeyNotFound
// if such key or key version exists wrapped in a HostError.
//
// The returned error is of type *HostError.
func (c *Client) DeleteKey(ctx context.Context, req *DeleteKeyRequest) error {
	body, err := cmds.Encode(nil, cmds.KeyDelete, req)
	if err != nil {
		return err
	}

	resp, err := c.Send(ctx, &Request{
		Enclave: req.Enclave,
		Body:    body,
	})
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// ListKeys returns the next page of a paginated listing of secret keys.
// All key names start with the req.Prefix and the first key name matches
// req.ContinueAt. The page contains at most req.Limit keys.
//
// ListKeys implements paginated listing. For iterating over a stream
// of keys combine it with an Iter.
//
// The returned error is of type *HostError.
func (c *Client) ListKeys(ctx context.Context, req *ListRequest) (*Page[KeyStatusResponse], error) {
	body, err := cmds.Encode(nil, cmds.KeyList, req)
	if err != nil {
		return nil, err
	}

	resp, err := c.Send(ctx, &Request{
		Enclave: req.Enclave,
		Body:    body,
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data pb.ListKeysResponse
	if err := decodeResponseMessage(resp, cmds.KeyList, &data); err != nil {
		return nil, err
	}

	ls := &Page[KeyStatusResponse]{
		Items:      make([]KeyStatusResponse, 0, len(data.Keys)),
		ContinueAt: data.ContinueAt,
	}
	for _, e := range data.Keys {
		var r KeyStatusResponse
		if err = r.UnmarshalPB(e); err != nil {
			return nil, hostError(resp.Request.URL.Host, err)
		}
		ls.Items = append(ls.Items, r)
	}
	return ls, nil
}

// Encrypt encrypts the req.Plaintext with the key req.Name within
// the req.Enclave.
//
// It returns ErrEnclaveNotFound if no such enclave exists and
// ErrKeyNotFound if no such key exists wrapped in a HostError.
//
// The returned error is of type *HostError.
func (c *Client) Encrypt(ctx context.Context, req *EncryptRequest) (*EncryptResponse, error) {
	body, err := cmds.Encode(nil, cmds.KeyEncrypt, req)
	if err != nil {
		return nil, err
	}

	resp, err := c.Send(ctx, &Request{
		Enclave: req.Enclave,
		Body:    body,
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data EncryptResponse
	if err := decodeResponse(resp, cmds.KeyEncrypt, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// Decrypt decrypts the req.Ciphertext with the key req.Name within
// the req.Enclave.
//
// It returns ErrEnclaveNotFound if no such enclave exists and
// ErrKeyNotFound if no such key exists wrapped in a HostError.
//
// The returned error is of type *HostError.
func (c *Client) Decrypt(ctx context.Context, req *DecryptRequest) (*DecryptResponse, error) {
	body, err := cmds.Encode(nil, cmds.KeyDecrypt, req)
	if err != nil {
		return nil, err
	}

	resp, err := c.Send(ctx, &Request{
		Enclave: req.Enclave,
		Body:    body,
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data DecryptResponse
	if err := decodeResponse(resp, cmds.KeyDecrypt, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// GenerateKey generates a new unique data encryption key. The returned
// GenerateKeyResponse contains a plaintext data encryption key with
// the requested length and a ciphertext version. The ciphertext
// is the plaintext data encryption key encrypted with the key within
// the given enclave.
//
// Applications should use, but never store, the plaintext data encryption
// key for cryptographic operations and remember the ciphertext version of
// the data encryption key. For example, encrypt a file with the plaintext
// data encryption key and store the ciphertext version of data encryption
// key alongside the encrypted file.
// The plaintext data encryption key can be obtained by decrypting the
// ciphertext data encryption key using Decrypt.
//
// Applications should also persist the key version that is used to prepare
// for future key rotation.
//
// It returns ErrEnclaveNotFound if no such enclave exists and
// ErrKeyNotFound if no such key exists wrapped in a HostError.
//
// The returned error is of type *HostError.
func (c *Client) GenerateKey(ctx context.Context, req *GenerateKeyRequest) (*GenerateKeyResponse, error) {
	body, err := cmds.Encode(nil, cmds.KeyGenerate, req)
	if err != nil {
		return nil, err
	}

	resp, err := c.Send(ctx, &Request{
		Enclave: req.Enclave,
		Body:    body,
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data GenerateKeyResponse
	if err := decodeResponse(resp, cmds.KeyGenerate, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// CreatePolicy creates a new or overwrites an exisiting policy with the
// name req.Name within req.Enclave.
//
// It returns ErrEnclaveNotFound if no such enclave exists wrapped in a
// HostError. The returned error is of type *HostError.
func (c *Client) CreatePolicy(ctx context.Context, req *CreatePolicyRequest) error {
	body, err := cmds.Encode(nil, cmds.PolicyCreate, req)
	if err != nil {
		return err
	}

	resp, err := c.Send(ctx, &Request{
		Enclave: req.Enclave,
		Body:    body,
	})
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// AssignPolicy assigns the req.Policy within req.Enclave to the req.Identity.
// Both, the policy and identity, must reside within the same enclave.
//
// It returns ErrEnclaveNotFound if no such enclave exists, ErrPolicyNotFound
// if no such policy exists and ErrIdentityNotFound if no such identity exists
// wrapped in a HostError. The returned error is of type *HostError.
func (c *Client) AssignPolicy(ctx context.Context, req *AssignPolicyRequest) error {
	body, err := cmds.Encode(nil, cmds.PolicyAssign, req)
	if err != nil {
		return err
	}

	resp, err := c.Send(ctx, &Request{
		Enclave: req.Enclave,
		Body:    body,
	})
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// DescribePolicy returns metadata about the policy req.Name within
// the req.Enclave.
//
// It returns ErrEnclaveNotFound if no such enclave exists and
// ErrPolicyNotFound if no such policy exists wrapped in a
// HostError. The returned error is of type *HostError.
func (c *Client) DescribePolicy(ctx context.Context, req *PolicyRequest) (*PolicyStatusResponse, error) {
	body, err := cmds.Encode(nil, cmds.PolicyStatus, req)
	if err != nil {
		return nil, err
	}

	resp, err := c.Send(ctx, &Request{
		Enclave: req.Enclave,
		Body:    body,
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data PolicyStatusResponse
	if err := decodeResponse(resp, cmds.PolicyStatus, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// GetPolicy fetches the policy req.Name within the req.Enclave.
//
// It returns ErrEnclaveNotFound if no such enclave exists and
// ErrPolicyNotFound if no such policy exists wrapped in a
// HostError. The returned error is of type *HostError.
func (c *Client) GetPolicy(ctx context.Context, req *PolicyRequest) (*PolicyResponse, error) {
	body, err := cmds.Encode(nil, cmds.PolicyGet, req)
	if err != nil {
		return nil, err
	}

	resp, err := c.Send(ctx, &Request{
		Enclave: req.Enclave,
		Body:    body,
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data PolicyResponse
	if err := decodeResponse(resp, cmds.PolicyGet, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// DeletePolicy deletes the policy with the name req.Name within req.Enclave.
//
// It returns ErrEnclaveNotFound if no such enclave exists and ErrPolicyNotFound
// if such policy exists wrapped in a HostError. The returned error is of type
// *HostError.
func (c *Client) DeletePolicy(ctx context.Context, req *DeletePolicyRequest) error {
	body, err := cmds.Encode(nil, cmds.PolicyDelete, req)
	if err != nil {
		return err
	}

	resp, err := c.Send(ctx, &Request{
		Enclave: req.Enclave,
		Body:    body,
	})
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// ListPolicies returns the next page of a paginated listing of policies.
// All policy names start with the req.Prefix and the first policy name
// matches req.ContinueAt. The page contains at most req.Limit policies.
//
// ListPolicies implements paginated listing. For iterating over a stream
// of policies combine it with an Iter.
//
// The returned error is of type *HostError.
func (c *Client) ListPolicies(ctx context.Context, req *ListRequest) (*Page[PolicyStatusResponse], error) {
	body, err := cmds.Encode(nil, cmds.PolicyList, req)
	if err != nil {
		return nil, err
	}

	resp, err := c.Send(ctx, &Request{
		Enclave: req.Enclave,
		Body:    body,
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data pb.ListPoliciesResponse
	if err := decodeResponseMessage(resp, cmds.PolicyList, &data); err != nil {
		return nil, err
	}

	ls := &Page[PolicyStatusResponse]{
		Items:      make([]PolicyStatusResponse, 0, len(data.Policies)),
		ContinueAt: data.ContinueAt,
	}
	for _, e := range data.Policies {
		var r PolicyStatusResponse
		if err = r.UnmarshalPB(e); err != nil {
			return nil, hostError(resp.Request.URL.Host, err)
		}
		ls.Items = append(ls.Items, r)
	}
	return ls, nil
}

// CreateIdentity creates a new or overwrites an exisiting identity with the
// name req.Identity within req.Enclave.
//
// It returns ErrEnclaveNotFound if no such enclave exists wrapped in a
// HostError. The returned error is of type *HostError.
func (c *Client) CreateIdentity(ctx context.Context, req *CreateIdentityRequest) error {
	body, err := cmds.Encode(nil, cmds.IdentityCreate, req)
	if err != nil {
		return err
	}

	resp, err := c.Send(ctx, &Request{
		Enclave: req.Enclave,
		Body:    body,
	})
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// GetIdentity returns identity req.Identity within the req.Enclave.
//
// It returns ErrEnclaveNotFound if no such enclave exists and
// ErrIdentityNotFound if no such identity exists wrapped in a
// HostError. The returned error is of type *HostError.
func (c *Client) GetIdentity(ctx context.Context, req *IdentityRequest) (*IdentityResponse, error) {
	body, err := cmds.Encode(nil, cmds.IdentityGet, req)
	if err != nil {
		return nil, err
	}

	resp, err := c.Send(ctx, &Request{
		Enclave: req.Enclave,
		Body:    body,
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data IdentityResponse
	if err := decodeResponse(resp, cmds.IdentityGet, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// DeleteIdentity deletes the identity with the name req.Identity within req.Enclave.
//
// It returns ErrEnclaveNotFound if no such enclave exists and ErrIdentityNotFound
// if such identity exists wrapped in a HostError. The returned error is of type
// *HostError.
func (c *Client) DeleteIdentity(ctx context.Context, req *DeleteIdentityRequest) error {
	body, err := cmds.Encode(nil, cmds.IdentityDelete, req)
	if err != nil {
		return err
	}

	resp, err := c.Send(ctx, &Request{
		Enclave: req.Enclave,
		Body:    body,
	})
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// ListIdentities returns the next page of a paginated listing of identites.
// All identities start with the req.Prefix and the first identity matches
// req.ContinueAt. The page contains at most req.Limit identities.
//
// ListIdentities implements paginated listing. For iterating over a stream
// of identities combine it with an Iter.
//
// The returned error is of type *HostError.
func (c *Client) ListIdentities(ctx context.Context, req *ListRequest) (*Page[IdentityResponse], error) {
	body, err := cmds.Encode(nil, cmds.IdentityList, req)
	if err != nil {
		return nil, err
	}

	resp, err := c.Send(ctx, &Request{
		Enclave: req.Enclave,
		Body:    body,
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data pb.ListIdentitiesResponse
	if err := decodeResponseMessage(resp, cmds.IdentityList, &data); err != nil {
		return nil, err
	}

	ls := &Page[IdentityResponse]{
		Items:      make([]IdentityResponse, 0, len(data.Identities)),
		ContinueAt: data.ContinueAt,
	}
	for _, k := range data.Identities {
		var r IdentityResponse
		if err = r.UnmarshalPB(k); err != nil {
			return nil, hostError(resp.Request.URL.Host, err)
		}
		ls.Items = append(ls.Items, r)
	}
	return ls, nil
}

// httpsURL turns the endpoint into an HTTPS endpoint.
func httpsURL(endpoint string) string {
	endpoint = strings.TrimPrefix(endpoint, "http://")

	if !strings.HasPrefix(endpoint, "https://") {
		endpoint = "https://" + endpoint
	}
	return endpoint
}

func generateCertificate(key APIKey) (tls.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: key.Identity().String(),
		},
		NotBefore: time.Now().UTC(),
		NotAfter:  time.Now().UTC().Add(90 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key.Private())
	if err != nil {
		return tls.Certificate{}, err
	}
	privPKCS8, err := x509.MarshalPKCS8PrivateKey(key.Private())
	if err != nil {
		return tls.Certificate{}, err
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privPKCS8}),
	)
	if err != nil {
		return tls.Certificate{}, err
	}
	if cert.Leaf == nil {
		cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}
	return cert, nil
}
