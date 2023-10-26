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
	"sync"
	"time"

	"aead.dev/mem"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

// An Enclave is an isolated area within a KES server.
// It stores cryptographic keys, policies and other
// related information securely.
//
// A KES server contains at least one Enclave and,
// depending upon its persistence layer, may be able
// to hold many Enclaves.
//
// With Enclaves, a KES server implements multi-tenancy.
type Enclave struct {
	// Name is the name of the KES server enclave.
	Name string

	// Endpoints contains one or multiple KES server
	// endpoints. For example: https://127.0.0.1:7373
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

// EnclaveInfo describes a KES enclave.
type EnclaveInfo struct {
	Name      string
	CreatedAt time.Time // Point in time when the enclave has been created
	CreatedBy Identity  // Identity that created the enclave
}

// NewEnclave returns a new Enclave that uses an API key
// for authentication.
//
// For obtaining an Enclave from a Client refer to Client.Enclave.
func NewEnclave(endpoint, name string, key APIKey, options ...CertificateOption) (*Enclave, error) {
	cert, err := GenerateCertificate(key, options...)
	if err != nil {
		return nil, err
	}
	return NewEnclaveWithConfig(endpoint, name, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}), nil
}

// NewEnclaveWithConfig returns a new Enclave with the given
// name and KES server endpoint that uses the given TLS config
// for mTLS authentication.
//
// Therefore, the config.Certificates must contain a TLS
// certificate that is valid for client authentication.
//
// NewClientWithConfig uses an http.Transport with reasonable
// defaults.
//
// For getting an Enclave from a Client refer to Client.Enclave.
func NewEnclaveWithConfig(endpoint, name string, config *tls.Config) *Enclave {
	return &Enclave{
		Name:      name,
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

// Metrics returns a KES server metric snapshot.
//
// It returns ErrNotAllowed if the client does not
// have sufficient permissions to fetch server metrics.
func (e *Enclave) Metrics(ctx context.Context) (Metric, error) {
	const (
		APIPath        = "/v1/metrics"
		Method         = http.MethodGet
		StatusOK       = http.StatusOK
		MaxResponeSize = 1 * mem.MiB
	)
	e.init.Do(e.initLoadBalancer)

	client := retry(e.HTTPClient)
	resp, err := e.lb.Send(ctx, &client, Method, APIPath, nil)
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

// CreateKey creates a new cryptographic key. The key will
// be generated by the KES server.
//
// It returns ErrKeyExists if a key with the same name already
// exists.
func (e *Enclave) CreateKey(ctx context.Context, name string) error {
	const (
		APIPath  = "/v1/key/create"
		Method   = http.MethodPost
		StatusOK = http.StatusOK
	)
	e.init.Do(e.initLoadBalancer)

	client := retry(e.HTTPClient)
	resp, err := e.lb.Send(ctx, &client, Method, join(APIPath, name), nil)
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
func (e *Enclave) ImportKey(ctx context.Context, name string, req *ImportKeyRequest) error {
	const (
		APIPath  = "/v1/key/import"
		Method   = http.MethodPost
		StatusOK = http.StatusOK
	)
	e.init.Do(e.initLoadBalancer)

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

	client := retry(e.HTTPClient)
	resp, err := e.lb.Send(ctx, &client, Method, join(APIPath, name), bytes.NewReader(body), withHeader("Content-Type", "application/json"))
	if err != nil {
		return err
	}
	if resp.StatusCode != StatusOK {
		return parseErrorResponse(resp)
	}
	return nil
}

// DescribeKey returns the KeyInfo for the given key.
//
// It returns ErrKeyNotFound if no such key exists.
func (e *Enclave) DescribeKey(ctx context.Context, name string) (*KeyInfo, error) {
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
	e.init.Do(e.initLoadBalancer)

	client := retry(e.HTTPClient)
	resp, err := e.lb.Send(ctx, &client, Method, join(APIPath, name), nil)
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
func (e *Enclave) DeleteKey(ctx context.Context, name string) error {
	const (
		APIPath  = "/v1/key/delete"
		Method   = http.MethodDelete
		StatusOK = http.StatusOK
	)
	e.init.Do(e.initLoadBalancer)

	client := retry(e.HTTPClient)
	resp, err := e.lb.Send(ctx, &client, Method, join(APIPath, name), nil)
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
func (e *Enclave) GenerateKey(ctx context.Context, name string, context []byte) (DEK, error) {
	const (
		APIPath         = "/v1/key/generate"
		Method          = http.MethodPost
		StatusOK        = http.StatusOK
		MaxResponseSize = 1 * mem.MiB
	)
	e.init.Do(e.initLoadBalancer)

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

	client := retry(e.HTTPClient)
	resp, err := e.lb.Send(ctx, &client, Method, join(APIPath, name), bytes.NewReader(body), withHeader("Content-Type", "application/json"))
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
func (e *Enclave) Encrypt(ctx context.Context, name string, plaintext, context []byte) ([]byte, error) {
	const (
		APIPath         = "/v1/key/encrypt"
		Method          = http.MethodPost
		StatusOK        = http.StatusOK
		MaxResponseSize = 1 * mem.MiB
	)
	e.init.Do(e.initLoadBalancer)

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

	client := retry(e.HTTPClient)
	resp, err := e.lb.Send(ctx, &client, Method, join(APIPath, name), bytes.NewReader(body), withHeader("Content-Type", "application/json"))
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
func (e *Enclave) Decrypt(ctx context.Context, name string, ciphertext, context []byte) ([]byte, error) {
	const (
		APIPath         = "/v1/key/decrypt"
		Method          = http.MethodPost
		StatusOK        = http.StatusOK
		MaxResponseSize = 1 * mem.MiB
	)
	e.init.Do(e.initLoadBalancer)

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

	client := retry(e.HTTPClient)
	resp, err := e.lb.Send(ctx, &client, Method, join(APIPath, name), bytes.NewReader(body), withHeader("Content-Type", "application/json"))
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

// ListKeys lists all names of cryptographic keys that match the given
// pattern. It returns a KeyIterator that iterates over all matched key
// names.
//
// The pattern matching happens on the server side. If pattern is empty
// the KeyIterator iterates over all key names.
func (e *Enclave) ListKeys(ctx context.Context, prefix string, n int) ([]string, string, error) {
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
	e.init.Do(e.initLoadBalancer)

	client := retry(e.HTTPClient)
	resp, err := e.lb.Send(ctx, &client, Method, join(APIPath, prefix), nil)
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

// CreateSecret creates a new secret with the given name.
//
// It returns ErrSecretExists if a secret with the same name
// already exists.
func (e *Enclave) CreateSecret(ctx context.Context, name string, value []byte, options *SecretOptions) error {
	const (
		APIPath  = "/v1/secret/create"
		Method   = http.MethodPost
		StatusOK = http.StatusOK
	)
	e.init.Do(e.initLoadBalancer)

	type Request struct {
		Secret []byte     `json:"secret"`
		Type   SecretType `json:"type,omitempty"`
	}

	req := Request{
		Secret: value,
		Type:   SecretGeneric,
	}
	if options != nil {
		req.Type = options.Type
	}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	client := retry(e.HTTPClient)
	resp, err := e.lb.Send(ctx, &client, Method, join(APIPath, name), bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return parseErrorResponse(resp)
	}
	return nil
}

// DescribeSecret returns the SecretInfo for the given secret.
//
// It returns ErrSecretNotFound if no such secret exists.
func (e *Enclave) DescribeSecret(ctx context.Context, name string) (*SecretInfo, error) {
	const (
		APIPath         = "/v1/secret/describe"
		Method          = http.MethodGet
		StatusOK        = http.StatusOK
		MaxResponseSize = 1 * mem.MiB
	)
	e.init.Do(e.initLoadBalancer)

	type Response struct {
		Name      string     `json:"name"`
		Type      SecretType `json:"type"`
		CreatedAt time.Time  `json:"created_at"`
		CreatedBy Identity   `json:"created_by"`
	}

	client := retry(e.HTTPClient)
	resp, err := e.lb.Send(ctx, &client, Method, join(APIPath, name), nil)
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
	return &SecretInfo{
		Name:      name,
		Type:      response.Type,
		CreatedAt: response.CreatedAt,
		CreatedBy: response.CreatedBy,
	}, nil
}

// ReadSecret returns the secret with the given name.
//
// It returns ErrSecretNotFound if no such secret exists.
func (e *Enclave) ReadSecret(ctx context.Context, name string) ([]byte, *SecretInfo, error) {
	const (
		APIPath         = "/v1/secret/read"
		Method          = http.MethodGet
		StatusOK        = http.StatusOK
		MaxResponseSize = 1 * mem.MiB
	)
	e.init.Do(e.initLoadBalancer)

	type Response struct {
		Bytes     []byte     `json:"bytes"`
		Name      string     `json:"name"`
		Type      SecretType `json:"type"`
		CreatedAt time.Time  `json:"created_at"`
		CreatedBy Identity   `json:"created_by"`
	}

	client := retry(e.HTTPClient)
	resp, err := e.lb.Send(ctx, &client, Method, join(APIPath, name), nil)
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
	return response.Bytes, &SecretInfo{
		Name:      name,
		Type:      response.Type,
		CreatedAt: response.CreatedAt,
		CreatedBy: response.CreatedBy,
	}, nil
}

// DeleteSecret deletes the secret with the given name.
//
// It returns ErrSecretNotFound if no such secret exists.
func (e *Enclave) DeleteSecret(ctx context.Context, name string) error {
	const (
		APIPath  = "/v1/secret/delete"
		Method   = http.MethodDelete
		StatusOK = http.StatusOK
	)
	e.init.Do(e.initLoadBalancer)

	client := retry(e.HTTPClient)
	resp, err := e.lb.Send(ctx, &client, Method, join(APIPath, name), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return parseErrorResponse(resp)
	}
	return nil
}

// ListSecrets returns a SecretIter that iterates over all secrets
// matching the pattern.
//
// The '*' pattern matches any secret. If pattern is empty the
// SecretIter iterates over all secrets names.
func (e *Enclave) ListSecrets(ctx context.Context, prefix string, n int) ([]string, string, error) {
	const (
		APIPath         = "/v1/secret/list"
		Method          = http.MethodGet
		StatusOK        = http.StatusOK
		MaxResponseSize = 1 * mem.MiB
	)
	type Response struct {
		Names      []string `json:"names"`
		ContinueAt string   `json:"continue_at"`
	}
	e.init.Do(e.initLoadBalancer)

	client := retry(e.HTTPClient)
	resp, err := e.lb.Send(ctx, &client, Method, join(APIPath, prefix), nil)
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

// AssignPolicy assigns the policy to the identity.
// The KES admin identity cannot be assigned to any
// policy.
//
// AssignPolicy returns PolicyNotFound if no such policy exists.
func (e *Enclave) AssignPolicy(ctx context.Context, policy string, identity Identity) error {
	const (
		APIPath  = "/v1/policy/assign"
		Method   = http.MethodPost
		StatusOK = http.StatusOK
	)
	e.init.Do(e.initLoadBalancer)

	type Request struct {
		Identity Identity `json:"identity"`
	}

	body, err := json.Marshal(Request{Identity: identity})
	if err != nil {
		return err
	}
	client := retry(e.HTTPClient)
	resp, err := e.lb.Send(ctx, &client, Method, join(APIPath, policy), bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return parseErrorResponse(resp)
	}
	return nil
}

// CreatePolicy creates a new policy.
//
// It returns ErrPolicyExists if such a policy already exists.
func (e *Enclave) CreatePolicy(ctx context.Context, name string, policy *Policy) error {
	const (
		APIPath  = "/v1/policy/create"
		Method   = http.MethodPut
		StatusOK = http.StatusOK
	)
	e.init.Do(e.initLoadBalancer)

	body, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	client := retry(e.HTTPClient)
	resp, err := e.lb.Send(ctx, &client, Method, join(APIPath, name), bytes.NewReader(body), withHeader("Content-Type", "application/json"))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return parseErrorResponse(resp)
	}
	return nil
}

// DescribePolicy returns the PolicyInfo for the given policy.
// It returns ErrPolicyNotFound if no such policy exists.
func (e *Enclave) DescribePolicy(ctx context.Context, name string) (*PolicyInfo, error) {
	const (
		APIPath         = "/v1/policy/describe"
		Method          = http.MethodGet
		StatusOK        = http.StatusOK
		MaxResponseSize = 1 * mem.MiB
	)
	e.init.Do(e.initLoadBalancer)

	type Response struct {
		CreatedAt time.Time `json:"created_at"`
		CreatedBy Identity  `json:"created_by"`
	}
	client := retry(e.HTTPClient)
	resp, err := e.lb.Send(ctx, &client, Method, join(APIPath, name), nil)
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
func (e *Enclave) GetPolicy(ctx context.Context, name string) (*Policy, error) {
	const (
		APIPath         = "/v1/policy/read"
		Method          = http.MethodGet
		StatusOK        = http.StatusOK
		MaxResponseSize = 1 * mem.MiB
	)
	e.init.Do(e.initLoadBalancer)

	type Response struct {
		Allow     map[string]Rule `json:"allow"`
		Deny      map[string]Rule `json:"deny"`
		CreatedAt time.Time       `json:"created_at"`
		CreatedBy Identity        `json:"created_by"`
	}
	client := retry(e.HTTPClient)
	resp, err := e.lb.Send(ctx, &client, Method, join(APIPath, name), nil)
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

// DeletePolicy deletes the policy with the given name. Any
// assigned identities will be removed as well.
//
// It returns ErrPolicyNotFound if no such policy exists.
func (e *Enclave) DeletePolicy(ctx context.Context, name string) error {
	const (
		APIPath  = "/v1/policy/delete"
		Method   = http.MethodDelete
		StatusOK = http.StatusOK
	)
	e.init.Do(e.initLoadBalancer)

	client := retry(e.HTTPClient)
	resp, err := e.lb.Send(ctx, &client, Method, join(APIPath, name), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return parseErrorResponse(resp)
	}
	return nil
}

// ListPolicies lists all policy names that match the given pattern.
//
// The pattern matching happens on the server side. If pattern is empty
// ListPolicies returns all policy names.
func (e *Enclave) ListPolicies(ctx context.Context, prefix string, n int) ([]string, string, error) {
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
	e.init.Do(e.initLoadBalancer)

	client := retry(e.HTTPClient)
	resp, err := e.lb.Send(ctx, &client, Method, join(APIPath, prefix), nil)
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

// CreateIdentity returns an IdentityInfo describing the given identity.
func (e *Enclave) CreateIdentity(ctx context.Context, identity Identity, req *CreateIdentityRequest) error {
	const (
		APIPath         = "/v1/identity/create"
		Method          = http.MethodPut
		StatusOK        = http.StatusOK
		MaxResponseSize = 1 * mem.MiB
	)
	type Request struct {
		Policy string `json:"policy"`
		Admin  bool   `json:"admin"`
		TTL    string `json:"ttl"`
	}
	e.init.Do(e.initLoadBalancer)

	var (
		policy string
		admin  bool
		ttl    string
	)
	if req != nil {
		policy, admin, ttl = req.Policy, req.Admin, req.TTL.String()
	}
	body, err := json.Marshal(Request{
		Policy: policy,
		Admin:  admin,
		TTL:    ttl,
	})
	if err != nil {
		return err
	}

	client := retry(e.HTTPClient)
	resp, err := e.lb.Send(ctx, &client, Method, join(APIPath, identity.String()), bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return parseErrorResponse(resp)
	}
	return nil
}

// DescribeIdentity returns an IdentityInfo describing the given identity.
func (e *Enclave) DescribeIdentity(ctx context.Context, identity Identity) (*IdentityInfo, error) {
	const (
		APIPath         = "/v1/identity/describe"
		Method          = http.MethodGet
		StatusOK        = http.StatusOK
		MaxResponseSize = 1 * mem.MiB
	)
	e.init.Do(e.initLoadBalancer)

	type Response struct {
		Policy    string     `json:"policy"`
		IsAdmin   bool       `json:"admin"`
		TTL       string     `json:"ttl"`
		ExpiresAt time.Time  `json:"expires_at"`
		CreatedAt time.Time  `json:"created_at"`
		CreatedBy Identity   `json:"created_by"`
		Children  []Identity `json:"children"`
	}

	client := retry(e.HTTPClient)
	resp, err := e.lb.Send(ctx, &client, Method, join(APIPath, identity.String()), nil)
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
func (e *Enclave) DescribeSelf(ctx context.Context) (*IdentityInfo, *Policy, error) {
	const (
		APIPath         = "/v1/identity/self/describe"
		Method          = http.MethodGet
		StatusOK        = http.StatusOK
		MaxResponseSize = 1 * mem.MiB
	)
	e.init.Do(e.initLoadBalancer)

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

	client := retry(e.HTTPClient)
	resp, err := e.lb.Send(ctx, &client, Method, APIPath, nil)
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

// DeleteIdentity removes the identity. Once removed, any
// operation issued by this identity will fail with
// ErrNotAllowed.
//
// The KES admin identity cannot be removed.
func (e *Enclave) DeleteIdentity(ctx context.Context, identity Identity) error {
	const (
		APIPath  = "/v1/identity/delete"
		Method   = http.MethodDelete
		StatusOK = http.StatusOK
	)
	e.init.Do(e.initLoadBalancer)

	client := retry(e.HTTPClient)
	resp, err := e.lb.Send(ctx, &client, Method, join(APIPath, identity.String()), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return parseErrorResponse(resp)
	}
	return nil
}

// ListIdentities lists all identites that match the given pattern.
//
// The pattern matching happens on the server side. If pattern is empty
// ListIdentities returns all identities.
func (e *Enclave) ListIdentities(ctx context.Context, prefix string, n int) ([]Identity, string, error) {
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
	e.init.Do(e.initLoadBalancer)

	client := retry(e.HTTPClient)
	resp, err := e.lb.Send(ctx, &client, Method, join(APIPath, prefix), nil)
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

func (e *Enclave) initLoadBalancer() {
	if e.lb == nil {
		e.lb = newLoadBalancer(e.Name)
		e.lb.prepareLoadBalancer(e.Endpoints)
	}
}
