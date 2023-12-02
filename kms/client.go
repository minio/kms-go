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

// NodeStatus returns the status of the KMS node at the given endpoint.
// For status information about the entire KMS cluster use Status.
func (c *Client) NodeStatus(ctx context.Context, endpoint string, _ *NodeStatusRequest) (*NodeStatusResponse, error) {
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

	var data NodeStatusResponse
	if err := readResponse(resp, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// Status returns status information about the entire KMS cluster. The
// returned StatusResponse contains status information for all nodes
// within the cluster.
func (c *Client) Status(ctx context.Context, _ *StatusRequest) (*StatusResponse, error) {
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

	var data StatusResponse
	if err := readResponse(resp, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// Encrypt encrypts a message with the key within the given enclave.
//
// It returns ErrEnclaveNotFound if no such enclave exists and
// ErrKeyNotFound if no such key exists.
func (c *Client) Encrypt(ctx context.Context, enclave, key string, req *EncryptRequest) (*EncryptResponse, error) {
	const (
		Method      = http.MethodPut
		Path        = api.PathSecretKeyEncrypt
		StatusOK    = http.StatusOK
		ContentType = headers.ContentTypeAppAny // accept JSON or protobuf
	)

	body, err := pb.Marshal(req)
	if err != nil {
		return nil, err
	}

	url, err := c.lb.URL(Path, key)
	if err != nil {
		return nil, err
	}
	r, err := http.NewRequestWithContext(ctx, Method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	r.Header.Set(headers.Accept, ContentType)
	r.Header.Set(headers.Enclave, enclave)

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

// Decrypt decrypts a ciphertext with the key within the given enclave.
//
// It returns ErrEnclaveNotFound if no such enclave exists and
// ErrKeyNotFound if no such key exists.
func (c *Client) Decrypt(ctx context.Context, enclave, key string, req *DecryptRequest) (*DecryptResponse, error) {
	const (
		Method      = http.MethodPut
		Path        = api.PathSecretKeyDecrypt
		StatusOK    = http.StatusOK
		ContentType = headers.ContentTypeAppAny // accept JSON or protobuf
	)

	body, err := pb.Marshal(req)
	if err != nil {
		return nil, err
	}

	url, err := c.lb.URL(Path, key)
	if err != nil {
		return nil, err
	}
	r, err := http.NewRequestWithContext(ctx, Method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	r.Header.Set(headers.Accept, ContentType)
	r.Header.Set(headers.Enclave, enclave)

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
func (c *Client) GenerateKey(ctx context.Context, enclave, key string, req *GenerateKeyRequest) (*GenerateKeyResponse, error) {
	const (
		Method      = http.MethodPut
		Path        = api.PathSecretKeyGenerate
		StatusOK    = http.StatusOK
		ContentType = headers.ContentTypeAppAny // accept JSON or protobuf
	)

	body, err := pb.Marshal(req)
	if err != nil {
		return nil, err
	}

	url, err := c.lb.URL(Path, key)
	if err != nil {
		return nil, err
	}
	r, err := http.NewRequestWithContext(ctx, Method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	r.Header.Set(headers.Accept, ContentType)
	r.Header.Set(headers.Enclave, enclave)

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
