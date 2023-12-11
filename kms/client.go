// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kms

import (
	"bytes"
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
	"strconv"
	"strings"
	"time"

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
		tlsConf.GetClientCertificate = func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
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

// ServerStatus returns the status of the KMS node at the given endpoint.
// For status information about the entire KMS cluster use Status.
func (c *Client) ServerStatus(ctx context.Context, endpoint string, _ *NodeStatusRequest) (*ServerStatusResponse, error) {
	const (
		Method      = http.MethodGet
		Path        = api.PathStatus
		StatusOK    = http.StatusOK
		ContentType = headers.ContentTypeAppAny // accept JSON or protobuf
	)

	url, err := url.JoinPath(httpsURL(endpoint), Path)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, Method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(headers.Accept, ContentType)

	resp, err := c.direct.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return nil, readError(resp)
	}

	var data ServerStatusResponse
	if err := readResponse(resp, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// ClusterStatus returns status information about the entire KMS cluster.
// The returned ClusterStatusResponse contains status information for all
// nodes within the cluster.
func (c *Client) ClusterStatus(ctx context.Context, _ *StatusRequest) (*ClusterStatusResponse, error) {
	const (
		Method      = http.MethodGet
		Path        = api.PathClusterStatus
		StatusOK    = http.StatusOK
		ContentType = headers.ContentTypeAppAny // accept JSON or protobuf
	)

	url, err := c.lb.URL(Path)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, Method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(headers.Accept, ContentType)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return nil, readError(resp)
	}

	var data ClusterStatusResponse
	if err := readResponse(resp, &data); err != nil {
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
func (c *Client) EditCluster(ctx context.Context, req *EditClusterRequest) error {
	const (
		Method      = http.MethodPatch
		Path        = api.PathClusterEdit
		StatusOK    = http.StatusOK
		ContentType = headers.ContentTypeAppAny // accept JSON or protobuf
	)

	body, err := pb.Marshal(req)
	if err != nil {
		return err
	}

	host := req.Host
	if host == "" {
		host = c.lb.Hosts[0]
	}
	url, err := url.JoinPath(httpsURL(host), Path)
	if err != nil {
		return err
	}
	r, err := http.NewRequestWithContext(ctx, Method, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	r.Header.Set(headers.Accept, ContentType)

	resp, err := c.client.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return readError(resp)
	}
	return nil
}

// AddNode adds the KMS server at req.Host to the current KMS cluster.
// It returns an error if the server is already part of the cluster.
//
// Nodes can only join a cluster if the cluster has a leader. The KMS
// server at req.Host must be fresh in the sense that it must not be
// part of a multi-node cluster already.
func (c *Client) AddNode(ctx context.Context, req *AddNodeRequest) error {
	const (
		Method      = http.MethodPatch
		Path        = api.PathClusterAdd
		StatusOK    = http.StatusOK
		ContentType = headers.ContentTypeAppAny // accept JSON or protobuf
	)

	url, err := c.lb.URL(Path, req.Host)
	if err != nil {
		return err
	}
	r, err := http.NewRequestWithContext(ctx, Method, url, nil)
	if err != nil {
		return err
	}
	r.Header.Set(headers.Accept, ContentType)

	resp, err := c.client.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return readError(resp)
	}

	c.lb.Hosts = append(c.lb.Hosts, req.Host)
	return nil
}

// RemoveNode removes the KMS server at req.Host from the current KMS
// cluster. It returns an error if the server is not part of the cluster.
func (c *Client) RemoveNode(ctx context.Context, req *RemoveNodeRequest) error {
	const (
		Method      = http.MethodPatch
		Path        = api.PathClusterRemove
		StatusOK    = http.StatusOK
		ContentType = headers.ContentTypeAppAny // accept JSON or protobuf
	)

	url, err := c.lb.URL(Path, req.Host)
	if err != nil {
		return err
	}
	r, err := http.NewRequestWithContext(ctx, Method, url, nil)
	if err != nil {
		return err
	}
	r.Header.Set(headers.Accept, ContentType)

	resp, err := c.client.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return readError(resp)
	}

	hosts := make([]string, 0, len(c.lb.Hosts))
	for _, host := range c.lb.Hosts {
		if host != req.Host {
			hosts = append(hosts, host)
		}
	}
	c.lb.Hosts = hosts
	return nil
}

// CreateEnclave creates a new enclave with the name req.Name.
//
// It returns ErrEnclaveExists if such an enclave already exists.
func (c *Client) CreateEnclave(ctx context.Context, req *CreateEnclaveRequest) error {
	const (
		Method      = http.MethodPut
		Path        = api.PathEnclaveCreate
		StatusOK    = http.StatusOK
		ContentType = headers.ContentTypeAppAny // accept JSON or protobuf
	)

	url, err := c.lb.URL(Path, req.Name)
	if err != nil {
		return err
	}
	r, err := http.NewRequestWithContext(ctx, Method, url, nil)
	if err != nil {
		return err
	}
	r.Header.Set(headers.Accept, ContentType)

	resp, err := c.client.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return readError(resp)
	}
	return nil
}

// DescribeEnclave returns metadata about the enclave with the
// the name req.Name.
//
// It returns ErrEnclaveNotFound if no such enclave exists.
func (c *Client) DescribeEnclave(ctx context.Context, req *DescribeEnclaveRequest) (*DescribeEnclaveResponse, error) {
	const (
		Method      = http.MethodGet
		Path        = api.PathEnclaveDescribe
		StatusOK    = http.StatusOK
		ContentType = headers.ContentTypeAppAny // accept JSON or protobuf
	)

	url, err := c.lb.URL(Path, req.Name)
	if err != nil {
		return nil, err
	}
	r, err := http.NewRequestWithContext(ctx, Method, url, nil)
	if err != nil {
		return nil, err
	}
	r.Header.Set(headers.Accept, ContentType)

	resp, err := c.client.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return nil, readError(resp)
	}

	var data DescribeEnclaveResponse
	if err := readResponse(resp, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// DeleteEnclave deletes the enclave with the name req.Name.
//
// It returns ErrEnclaveNotFound if no such enclave exists.
func (c *Client) DeleteEnclave(ctx context.Context, req *DeleteEnclaveRequest) error {
	const (
		Method      = http.MethodDelete
		Path        = api.PathEnclaveDelete
		StatusOK    = http.StatusOK
		ContentType = headers.ContentTypeAppAny // accept JSON or protobuf
	)

	url, err := c.lb.URL(Path, req.Name)
	if err != nil {
		return err
	}
	r, err := http.NewRequestWithContext(ctx, Method, url, nil)
	if err != nil {
		return err
	}
	r.Header.Set(headers.Accept, ContentType)

	resp, err := c.client.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return readError(resp)
	}
	return nil
}

// ListEnclaveNames returns a list of enclaves names. The list starts at
// the given req.Prefix and req.ContinueAt and contains at most req.Limit
// names.
//
// ListEnclaveNames implements paginated listing. For iterating over a stream
// of enclave names combine it with an Iter.
func (c *Client) ListEnclaveNames(ctx context.Context, req *ListRequest) (*ListResponse[string], error) {
	const (
		Method      = http.MethodGet
		Path        = api.PathEnclaveList
		StatusOK    = http.StatusOK
		ContentType = headers.ContentTypeAppAny // accept JSON or protobuf

		QueryContinue = api.QueryListContinue
		QueryLimit    = api.QueryListLimit
	)

	query := url.Values{}
	if req.ContinueAt != "" {
		query[QueryContinue] = []string{req.ContinueAt}
	}
	if req.Limit > 0 {
		query[QueryLimit] = []string{strconv.Itoa(req.Limit)}
	}

	url, err := c.lb.URL(Path, req.Prefix)
	if err != nil {
		return nil, err
	}
	if len(query) > 0 {
		url += "?" + query.Encode()
	}
	r, err := http.NewRequestWithContext(ctx, Method, url, nil)
	if err != nil {
		return nil, err
	}
	r.Header.Set(headers.Accept, ContentType)

	resp, err := c.client.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return nil, readError(resp)
	}

	var data pb.ListEnclaveNamesResponse
	if err = readProtoResponse(resp, &data); err != nil {
		return nil, err
	}
	return &ListResponse[string]{
		Items:      data.Names,
		ContinueAt: data.ContinueAt,
	}, nil
}

// CreateKey creates a new key with the name req.Name within req.Enclave
// if and only if no such key exists already. For adding key versions to
// an existing key use AddKeyVersion.
//
// It returns ErrEnclaveNotFound if no such enclave exists and ErrKeyExists
// if such a key already exists.
func (c *Client) CreateKey(ctx context.Context, req *CreateKeyRequest) error {
	const (
		Method      = http.MethodPut
		Path        = api.PathSecretKeyCreate
		StatusOK    = http.StatusOK
		ContentType = headers.ContentTypeAppAny // accept JSON or protobuf
	)

	body, err := pb.Marshal(req)
	if err != nil {
		return err
	}

	url, err := c.lb.URL(Path, req.Name)
	if err != nil {
		return err
	}
	r, err := http.NewRequestWithContext(ctx, Method, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	r.Header.Set(headers.Accept, ContentType)
	r.Header.Set(headers.Enclave, req.Enclave)

	resp, err := c.client.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return readError(resp)
	}
	return nil
}

// AddKeyVersion adds a new key version to an existing key with the name req.Name
// within req.Enclave. If no such key exists, it creates the key. For creating a
// key without adding a new key versions use CreateKey.
//
// It returns ErrEnclaveNotFound if no such enclave exists.
func (c *Client) AddKeyVersion(ctx context.Context, req *AddKeyVersionRequest) error {
	const (
		Method      = http.MethodPatch
		Path        = api.PathSecretKeyAdd
		StatusOK    = http.StatusOK
		ContentType = headers.ContentTypeAppAny // accept JSON or protobuf
	)

	body, err := pb.Marshal(req)
	if err != nil {
		return err
	}

	url, err := c.lb.URL(Path, req.Name)
	if err != nil {
		return err
	}
	r, err := http.NewRequestWithContext(ctx, Method, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	r.Header.Set(headers.Accept, ContentType)
	r.Header.Set(headers.Enclave, req.Enclave)

	resp, err := c.client.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return readError(resp)
	}
	return nil
}

// RemoveKeyVersion removes the version req.Version from the key with the name
// req.Name within req.Enclave. Once a key version has been removed, it cannot
// be added again. When a key contains just a single key version, RemoveKeyVersion
// deletes the key.
//
// It returns ErrEnclaveNotFound if no such enclave exists and ErrKeyNotFound if
// no such a key or key version exists.
func (c *Client) RemoveKeyVersion(ctx context.Context, req *RemoveKeyVersionRequest) error {
	const (
		Method      = http.MethodPatch
		Path        = api.PathSecretKeyRemove
		StatusOK    = http.StatusOK
		ContentType = headers.ContentTypeAppAny // accept JSON or protobuf
	)

	body, err := pb.Marshal(req)
	if err != nil {
		return err
	}

	url, err := c.lb.URL(Path, req.Name)
	if err != nil {
		return err
	}
	r, err := http.NewRequestWithContext(ctx, Method, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	r.Header.Set(headers.Accept, ContentType)
	r.Header.Set(headers.Enclave, req.Enclave)

	resp, err := c.client.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return readError(resp)
	}
	return nil
}

// DescribeKeyVersion returns metadata about the key req.Name within
// the req.Enclave.
//
// It returns ErrEnclaveNotFound if no such enclave exists and
// ErrKeyNotFound if no such key exists.
func (c *Client) DescribeKeyVersion(ctx context.Context, req *DescribeKeyVersionRequest) (*DescribeKeyVersionResponse, error) {
	const (
		Method      = http.MethodGet
		Path        = api.PathSecretKeyDescribe
		StatusOK    = http.StatusOK
		ContentType = headers.ContentTypeAppAny // accept JSON or protobuf
	)

	url, err := c.lb.URL(Path, req.Name)
	if err != nil {
		return nil, err
	}
	r, err := http.NewRequestWithContext(ctx, Method, url, nil)
	if err != nil {
		return nil, err
	}
	r.Header.Set(headers.Accept, ContentType)
	r.Header.Set(headers.Enclave, req.Enclave)

	resp, err := c.client.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return nil, readError(resp)
	}

	var data DescribeKeyVersionResponse
	if err := readResponse(resp, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// DeleteKey deletes the key with the version req.Version from the key ring
// with the name req.Name within req.Enclave. It deletes the latest key
// version if no key version is specified.
//
// It returns ErrEnclaveNotFound if no such enclave exists and ErrKeyNotFound
// if such key or key version exists.
func (c *Client) DeleteKey(ctx context.Context, req *DeleteKeyRequest) error {
	const (
		Method      = http.MethodDelete
		Path        = api.PathSecretKeyDelete
		StatusOK    = http.StatusOK
		ContentType = headers.ContentTypeAppAny // accept JSON or protobuf
	)

	url, err := c.lb.URL(Path, req.Name)
	if err != nil {
		return err
	}
	r, err := http.NewRequestWithContext(ctx, Method, url, nil)
	if err != nil {
		return err
	}
	r.Header.Set(headers.Accept, ContentType)
	r.Header.Set(headers.Enclave, req.Enclave)

	resp, err := c.client.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return readError(resp)
	}
	return nil
}

// ListKeyNames returns a list of key names. The list starts at the given
// req.Prefix and req.ContinueAt and contains at most req.Limit names.
//
// ListKeyNames implements paginated listing. For iterating over a stream
// of key names combine it with an Iter.
func (c *Client) ListKeyNames(ctx context.Context, req *ListRequest) (*ListResponse[string], error) {
	const (
		Method      = http.MethodGet
		Path        = api.PathSecretKeyList
		StatusOK    = http.StatusOK
		ContentType = headers.ContentTypeAppAny // accept JSON or protobuf

		QueryContinue = api.QueryListContinue
		QueryLimit    = api.QueryListLimit
	)

	query := url.Values{}
	if req.ContinueAt != "" {
		query[QueryContinue] = []string{req.ContinueAt}
	}
	if req.Limit > 0 {
		query[QueryLimit] = []string{strconv.Itoa(req.Limit)}
	}

	url, err := c.lb.URL(Path, req.Prefix)
	if err != nil {
		return nil, err
	}
	if len(query) > 0 {
		url += "?" + query.Encode()
	}
	r, err := http.NewRequestWithContext(ctx, Method, url, nil)
	if err != nil {
		return nil, err
	}
	r.Header.Set(headers.Accept, ContentType)
	r.Header.Set(headers.Enclave, req.Enclave)

	resp, err := c.client.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return nil, readError(resp)
	}

	var data pb.ListKeyNamesResponse
	if err = readProtoResponse(resp, &data); err != nil {
		return nil, err
	}
	return &ListResponse[string]{
		Items:      data.Names,
		ContinueAt: data.ContinueAt,
	}, nil
}

// Encrypt encrypts the req.Plaintext with the key req.Name within
// the req.Enclave.
//
// It returns ErrEnclaveNotFound if no such enclave exists and
// ErrKeyNotFound if no such key exists.
func (c *Client) Encrypt(ctx context.Context, req *EncryptRequest) (*EncryptResponse, error) {
	const (
		Method      = http.MethodPost
		Path        = api.PathSecretKeyEncrypt
		StatusOK    = http.StatusOK
		ContentType = headers.ContentTypeAppAny // accept JSON or protobuf
	)

	body, err := pb.Marshal(req)
	if err != nil {
		return nil, err
	}

	url, err := c.lb.URL(Path, req.Name)
	if err != nil {
		return nil, err
	}
	r, err := http.NewRequestWithContext(ctx, Method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	r.Header.Set(headers.Accept, ContentType)
	r.Header.Set(headers.Enclave, req.Enclave)

	resp, err := c.client.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return nil, readError(resp)
	}

	var data EncryptResponse
	if err := readResponse(resp, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// Decrypt decrypts the req.Ciphertext with the key req.Name within
// the req.Enclave.
//
// It returns ErrEnclaveNotFound if no such enclave exists and
// ErrKeyNotFound if no such key exists.
func (c *Client) Decrypt(ctx context.Context, req *DecryptRequest) (*DecryptResponse, error) {
	const (
		Method      = http.MethodPost
		Path        = api.PathSecretKeyDecrypt
		StatusOK    = http.StatusOK
		ContentType = headers.ContentTypeAppAny // accept JSON or protobuf
	)

	body, err := pb.Marshal(req)
	if err != nil {
		return nil, err
	}

	url, err := c.lb.URL(Path, req.Name)
	if err != nil {
		return nil, err
	}
	r, err := http.NewRequestWithContext(ctx, Method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	r.Header.Set(headers.Accept, ContentType)
	r.Header.Set(headers.Enclave, req.Enclave)

	resp, err := c.client.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return nil, readError(resp)
	}

	var data DecryptResponse
	if err := readResponse(resp, &data); err != nil {
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
// ErrKeyNotFound if no such key exists.
func (c *Client) GenerateKey(ctx context.Context, req *GenerateKeyRequest) (*GenerateKeyResponse, error) {
	const (
		Method      = http.MethodPost
		Path        = api.PathSecretKeyGenerate
		StatusOK    = http.StatusOK
		ContentType = headers.ContentTypeAppAny // accept JSON or protobuf
	)

	body, err := pb.Marshal(req)
	if err != nil {
		return nil, err
	}

	url, err := c.lb.URL(Path, req.Name)
	if err != nil {
		return nil, err
	}
	r, err := http.NewRequestWithContext(ctx, Method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	r.Header.Set(headers.Accept, ContentType)
	r.Header.Set(headers.Enclave, req.Enclave)

	resp, err := c.client.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return nil, readError(resp)
	}

	var data GenerateKeyResponse
	if err := readResponse(resp, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// CreatePolicy creates a new or overwrites an exisiting policy with the
// name req.Name within req.Enclave.
//
// It returns ErrEnclaveNotFound if no such enclave exists.
func (c *Client) CreatePolicy(ctx context.Context, req *CreatePolicyRequest) error {
	const (
		Method      = http.MethodPut
		Path        = api.PathPolicyCreate
		StatusOK    = http.StatusOK
		ContentType = headers.ContentTypeAppAny // accept JSON or protobuf
	)

	body, err := pb.Marshal(req)
	if err != nil {
		return err
	}

	url, err := c.lb.URL(Path, req.Name)
	if err != nil {
		return err
	}
	r, err := http.NewRequestWithContext(ctx, Method, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	r.Header.Set(headers.Accept, ContentType)
	r.Header.Set(headers.Enclave, req.Enclave)

	resp, err := c.client.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return readError(resp)
	}
	return nil
}

// DescribePolicy returns metadata about the policy req.Name within
// the req.Enclave.
//
// It returns ErrEnclaveNotFound if no such enclave exists and
// ErrPolicyNotFound if no such policy exists.
func (c *Client) DescribePolicy(ctx context.Context, req *DescribePolicyRequest) (*DescribePolicyResponse, error) {
	const (
		Method      = http.MethodGet
		Path        = api.PathPolicyDescribe
		StatusOK    = http.StatusOK
		ContentType = headers.ContentTypeAppAny // accept JSON or protobuf
	)

	url, err := c.lb.URL(Path, req.Name)
	if err != nil {
		return nil, err
	}
	r, err := http.NewRequestWithContext(ctx, Method, url, nil)
	if err != nil {
		return nil, err
	}
	r.Header.Set(headers.Accept, ContentType)
	r.Header.Set(headers.Enclave, req.Enclave)

	resp, err := c.client.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return nil, readError(resp)
	}

	var data DescribePolicyResponse
	if err := readResponse(resp, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// DeletePolicy deletes the policy with the name req.Name within req.Enclave.
//
// It returns ErrEnclaveNotFound if no such enclave exists and ErrPolicyNotFound
// if such policy exists.
func (c *Client) DeletePolicy(ctx context.Context, req *DeletePolicyRequest) error {
	const (
		Method      = http.MethodDelete
		Path        = api.PathPolicyDelete
		StatusOK    = http.StatusOK
		ContentType = headers.ContentTypeAppAny // accept JSON or protobuf
	)

	url, err := c.lb.URL(Path, req.Name)
	if err != nil {
		return err
	}
	r, err := http.NewRequestWithContext(ctx, Method, url, nil)
	if err != nil {
		return err
	}
	r.Header.Set(headers.Accept, ContentType)
	r.Header.Set(headers.Enclave, req.Enclave)

	resp, err := c.client.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return readError(resp)
	}
	return nil
}

// ListPolicyNames returns a list of policy names within the req.Enclave.
// The list starts at the given req.Prefix and req.ContinueAt and contains
// at most req.Limit names.
//
// ListEnclaveNames implements paginated listing. For iterating over a stream
// of policy names combine it with an Iter.
func (c *Client) ListPolicyNames(ctx context.Context, req *ListRequest) (*ListResponse[string], error) {
	const (
		Method      = http.MethodGet
		Path        = api.PathPolicyList
		StatusOK    = http.StatusOK
		ContentType = headers.ContentTypeAppAny // accept JSON or protobuf

		QueryContinue = api.QueryListContinue
		QueryLimit    = api.QueryListLimit
	)

	query := url.Values{}
	if req.ContinueAt != "" {
		query[QueryContinue] = []string{req.ContinueAt}
	}
	if req.Limit > 0 {
		query[QueryLimit] = []string{strconv.Itoa(req.Limit)}
	}

	url, err := c.lb.URL(Path, req.Prefix)
	if err != nil {
		return nil, err
	}
	if len(query) > 0 {
		url += "?" + query.Encode()
	}
	r, err := http.NewRequestWithContext(ctx, Method, url, nil)
	if err != nil {
		return nil, err
	}
	r.Header.Set(headers.Accept, ContentType)
	r.Header.Set(headers.Enclave, req.Enclave)

	resp, err := c.client.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return nil, readError(resp)
	}

	var data pb.ListPolicyNamesResponse
	if err = readProtoResponse(resp, &data); err != nil {
		return nil, err
	}
	return &ListResponse[string]{
		Items:      data.Names,
		ContinueAt: data.ContinueAt,
	}, nil
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
