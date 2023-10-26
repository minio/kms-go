// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"context"
	"errors"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

type dnsResolver interface {
	LookupHost(ctx context.Context, host string) (addrs []string, err error)
}

type randomNumberGenerator interface {
	Intn(n int) int
}

type loadBalancer struct {
	enclave          string
	endpoints        []*loadBalancerEndpoint
	rand             randomNumberGenerator
	DNSResolver      dnsResolver
	getLocalNetworks func() ([]net.Addr, error)
	sendRequest      func(context.Context, *endpointRequest) (*http.Response, error)
}

func newLoadBalancer(enclaveName string) *loadBalancer {
	return &loadBalancer{
		enclave:          enclaveName,
		DNSResolver:      new(net.Resolver),
		getLocalNetworks: net.InterfaceAddrs,
		sendRequest:      sendRequest,
		rand:             rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

type loadBalancerEndpoint struct {
	lock sync.Mutex
	addr string
	err  error

	// local, if set to true, indicates that this endpoint
	// is located on the same local network as the current host.
	local bool
	// localhost, if set to true, indicates that this endpoint
	// is listening locally on IPv4 or IPv6.
	localhost bool
	// timeout is a timestamp indicating when this endpoint was
	// placed in a timed-out state.
	timeout time.Time
	// timeoutProbe, if set to true, indicates that there is
	// currently a probe request being made to determine the
	// status of this endpoint.
	timeoutProbe bool
}

func (le *loadBalancerEndpoint) isInTimeout() (timedOut, shouldProbe bool) {
	defer le.lock.Unlock()
	le.lock.Lock()
	if le.timeout.IsZero() {
		return false, false
	} else if time.Since(le.timeout).Seconds() < 30 {
		return true, false
	}

	if !le.timeoutProbe {
		le.timeoutProbe = true
		return false, true
	}

	return true, false
}

func (le *loadBalancerEndpoint) setTimeout(asProbe bool) {
	defer le.lock.Unlock()
	le.lock.Lock()
	if le.timeout.IsZero() {
		le.timeout = time.Now()
	}
	if asProbe {
		le.timeoutProbe = false
		le.timeout = time.Now()
	}
}

func (le *loadBalancerEndpoint) clearTimeout() {
	defer le.lock.Unlock()
	le.lock.Lock()
	le.timeout = time.Time{}
	le.timeoutProbe = false
}

func (lb *loadBalancer) prepareLoadBalancer(endpoints []string) {
	if len(endpoints) < 1 {
		return
	}
	if lb.getLocalNetworks == nil {
		lb.getLocalNetworks = net.InterfaceAddrs
	}
	if lb.DNSResolver == nil {
		lb.DNSResolver = new(net.Resolver)
	}
	if lb.sendRequest == nil {
		lb.sendRequest = sendRequest
	}
	if lb.rand == nil {
		lb.rand = rand.New(rand.NewSource(time.Now().UnixNano()))
	}

	ifNetworks := make(map[string]*net.IPNet)
	ifs, err := lb.getLocalNetworks()
	if err == nil {
		for _, v := range ifs {
			netIP, ipNet, err := net.ParseCIDR(v.String())
			if err == nil {
				ifNetworks[netIP.String()] = ipNet
			}
		}
	}

	endpointCh := make(chan *loadBalancerEndpoint, len(endpoints))
	for _, e := range endpoints {
		go func(ep string) {
			urlx, err := url.Parse(ep)
			if err != nil {
				endpointCh <- &loadBalancerEndpoint{err: err, addr: ep}
				return
			}

			host := urlx.Hostname()
			if host == "localhost" || host == "127.0.0.1" {
				endpointCh <- &loadBalancerEndpoint{localhost: true, addr: ep}
				return
			}

			IP := net.ParseIP(host)
			if IP == nil {
				ctx, cancelFunc := context.WithTimeout(
					context.Background(),
					time.Second*2,
				)
				defer cancelFunc()

				addrs, err := lb.DNSResolver.LookupHost(ctx, host)
				if err == nil && len(addrs) > 0 {
					IP = net.ParseIP(addrs[0])
				}
			}

			if IP != nil {
				for i, v := range ifNetworks {
					if i == IP.String() {
						endpointCh <- &loadBalancerEndpoint{localhost: true, addr: ep}
						return
					}
					if v.Contains(IP) {
						endpointCh <- &loadBalancerEndpoint{local: true, addr: ep}
						return
					}
				}
			}

			endpointCh <- &loadBalancerEndpoint{addr: ep}
		}(e)
	}

	lb.endpoints = make([]*loadBalancerEndpoint, 0)
	timeout := time.After(time.Second * 10)
	returnCount := 0
	for {
		select {
		case ea := <-endpointCh:
			lb.endpoints = append(lb.endpoints, ea)
			returnCount++
			if returnCount == len(endpoints) {
				goto DONE
			}
		case <-timeout:
			goto DONE
		}
	}

DONE:
	close(endpointCh)
	// Endpoints that are bound to local interfaces are sorted in the lowest indexes.
	// Followed by endpoints that are within the local interface networks (CIDRs).
	// Followed by endpoints that are NOT within the local interface networks (CIDRs).
	slices.SortFunc(lb.endpoints, func(a, b *loadBalancerEndpoint) int {
		if a.localhost {
			return -1
		} else if a.local && !b.localhost {
			return -1
		}
		return 1
	})
}

// retryBody takes an io.ReadSeeker and converts it
// into an io.ReadCloser that can be used as request
// body for retryable requests.
//
// The body must implement io.Seeker to ensure that
// the entire body is sent again when retrying a request.
//
// If body is nil, retryBody returns nil.
func retryBody(body io.ReadSeeker) io.ReadCloser {
	if body == nil {
		return nil
	}

	var closer io.Closer
	if c, ok := body.(io.Closer); ok {
		closer = c
	} else {
		closer = io.NopCloser(body)
	}

	type ReadSeekCloser struct {
		io.ReadSeeker
		io.Closer
	}
	return ReadSeekCloser{
		ReadSeeker: body,
		Closer:     closer,
	}
}

// requestOption is and optional parameter of an HTTP request.
type requestOption func(*http.Request)

// withHeader returns a requestOption that sets the given
// key-value pair as HTTP header.
func withHeader(key, value string) requestOption {
	return func(req *http.Request) {
		req.Header.Set(key, value)
	}
}

// Send
// This method uses `loadBalancerEndpoint` from `loadBalancer.endpoints`
// to send requests to KES instances.
//
// If loadBalancer.endpoints[0] is of type localhost then it will be prioritized
// above other endpoints, but not excluded from timeouts due to errors.
//
// an endpoint will be selected at random if loadBalancer.endpoint[0] is in a timed-out
// state or is NOT of type localhost.
//
// An endpoint will be placed in a timed-out state if an error occures during
// connection or transmission, more specifically if loadBalancer.sendRequest()
// returns an error.
//
// Additionally 5xx error responses will trigger a timed-out state,
// excluding 501 ( Not Implemented ).
//
// Endpoint timeouts will last for 30 seconds. Once the endpoint timeout
// expires, a SINGLE request will be allowed to probe the endpoint in
// order to determine its current status.
func (lb *loadBalancer) Send(ctx context.Context, client *retry, method string, path string, body io.ReadSeeker, options ...requestOption) (*http.Response, error) {
	if len(lb.endpoints) < 1 {
		return nil, errors.New("kes: no server endpoint")
	}

	endpoint := lb.endpoints[0]
	if endpoint.addr == "" {
		return nil, errors.New("kes: invalid server endpoint")
	}

	endpointRequest := endpointRequest{
		client:  client,
		enclave: lb.enclave,
		method:  method,
		path:    path,
		body:    body,
		options: options,
		addr:    endpoint.addr,
	}

	if len(lb.endpoints) == 1 {
		return lb.sendRequest(ctx, &endpointRequest)
	}

	var (
		resp *http.Response
		err  error
	)

	if endpoint.localhost {
		isTimedout, shouldProbe := endpoint.isInTimeout()
		if !isTimedout || shouldProbe {
			resp, err = lb.sendRequest(ctx, &endpointRequest)
			if err != nil || resp == nil {
				endpoint.setTimeout(shouldProbe)
			} else {
				if resp.StatusCode >= http.StatusInternalServerError && resp.StatusCode != http.StatusNotImplemented {
					endpoint.setTimeout(shouldProbe)
				} else {
					if shouldProbe {
						endpoint.clearTimeout()
					}
					return resp, nil
				}
			}
		}
	}

	var (
		endpointCount     = len(lb.endpoints)
		tryCount          = 0
		fullRetry         = false
		R                 = lb.rand.Intn(len(lb.endpoints))
		nextEndpointIndex int
	)

retry:
	for tryCount < endpointCount {
		tryCount++
		nextEndpointIndex = (tryCount + R) % endpointCount
		endpoint = lb.endpoints[nextEndpointIndex]
		endpointRequest.addr = endpoint.addr
		isTimedout, shouldProbe := endpoint.isInTimeout()
		if !fullRetry && !shouldProbe && isTimedout {
			continue
		}
		resp, err = lb.sendRequest(ctx, &endpointRequest)
		if err != nil || resp == nil {
			endpoint.setTimeout(shouldProbe)
			continue
		}
		if resp.StatusCode >= http.StatusInternalServerError && resp.StatusCode != http.StatusNotImplemented {
			endpoint.setTimeout(shouldProbe)
			continue
		}
		if shouldProbe || fullRetry {
			endpoint.clearTimeout()
		}
		return resp, nil
	}

	if !fullRetry && resp == nil && err == nil {
		fullRetry = true
		tryCount = 0
		goto retry
	}
	return resp, err
}

// endpointRequest wraps input parameters for the sendRequest function
type endpointRequest struct {
	client  *retry
	addr    string
	enclave string
	method  string
	path    string
	body    io.ReadSeeker
	options []requestOption
}

func sendRequest(ctx context.Context, epr *endpointRequest) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, epr.method, endpoint(epr.addr, epr.path), retryBody(epr.body))
	if err != nil {
		return nil, err
	}
	if epr.enclave != "" {
		request.Header.Set("Kes-Enclave", epr.enclave)
	}
	for _, opt := range epr.options {
		opt(request)
	}
	response, err := epr.client.Do(request)
	if errors.Is(err, context.Canceled) {
		return nil, err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return nil, err
	}
	if urlErr, ok := err.(*url.Error); ok {
		if connErr, ok := urlErr.Err.(*ConnError); ok {
			return nil, connErr
		}
	}
	return response, err
}

// retry is an http.Client that implements
// a retry mechanism for requests that fail
// due to a temporary network error.
//
// It provides a similar interface as the http.Client
// but requires that the request body implements io.Seeker.
// Otherwise, it cannot guarantee that the entire request
// body gets sent when retrying a request.
type retry http.Client

// Get issues a GET to the specified URL.
// It is a wrapper around retry.Do.
func (r *retry) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, retryBody(nil))
	if err != nil {
		return nil, err
	}
	return r.Do(req)
}

// Post issues a POST to the specified URL.
// It is a wrapper around retry.Do.
func (r *retry) Post(url, contentType string, body io.ReadSeeker) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, url, retryBody(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return r.Do(req)
}

// Do sends an HTTP request and returns an HTTP response using
// the underlying http.Client. If the request fails b/c of a
// temporary error Do retries the request a few times. If the
// request keeps failing, Do will give up and return a descriptive
// error.
func (r *retry) Do(req *http.Request) (*http.Response, error) {
	type RetryReader interface {
		io.Reader
		io.Seeker
		io.Closer
	}

	// If the request body is not a RetryReader it cannot
	// be retried. The caller has to ensure that the actual
	// body content is an io.ReadCloser + io.Seeker.
	// The retry.NewRequest method does that.
	//
	// A request can only be retried if we can seek to the
	// start of the request body. Otherwise, we may send a
	// partial response body when we retry the request.
	var body RetryReader
	if req.Body != nil {
		var ok bool
		body, ok = req.Body.(RetryReader)
		if !ok {
			// We cannot convert the req.Body to an io.Seeker.
			// If we would proceed we may introduce hard to find
			// bugs. Also, there is no point in returning an
			// error since the caller has specified a wrong type.
			panic("kes: request cannot be retried")
		}

		// If there is a request body, additionally set the
		// GetBody callback - if not set already. The underlying
		// HTTP stack will use the GetBody callback to obtain a new
		// copy of the request body - e.g. in case of a redirect.
		if req.GetBody == nil {
			req.GetBody = func() (io.ReadCloser, error) {
				if _, err := body.Seek(0, io.SeekStart); err != nil {
					return nil, err
				}
				return body, nil
			}
		}
	}

	const (
		MinRetryDelay     = 200 * time.Millisecond
		MaxRandRetryDelay = 800
	)
	var (
		retry  = 2 // For now, we retry 2 times before we give up
		client = (*http.Client)(r)
	)
	resp, err := client.Do(req)
	for retry > 0 && (isNetworkError(err) || (resp != nil && resp.StatusCode == http.StatusServiceUnavailable)) {
		randomRetryDelay := time.Duration(rand.Intn(MaxRandRetryDelay)) * time.Millisecond
		time.Sleep(MinRetryDelay + randomRetryDelay)
		retry--

		// If there is a body we have to reset it. Otherwise, we may send
		// only partial data to the server when we retry the request.
		if body != nil {
			if _, err = body.Seek(0, io.SeekStart); err != nil {
				return nil, err
			}
			req.Body = body
		}

		resp, err = client.Do(req) // Now, retry.
	}
	if isNetworkError(err) {
		// If the request still fails with a temporary error
		// we wrap the error to provide more information to the
		// caller.
		return nil, &url.Error{
			Op:  req.Method,
			URL: req.URL.String(),
			Err: &ConnError{
				Host: req.URL.Host,
				Err:  err,
			},
		}
	}
	return resp, err
}

// isNetworkError reports whether err is network error.
//
// A network error may occur due to a timeout or other
// network-related issues, like premature closing a
// network connection.
//
// A network error may also indicate that the remote
// peer is not reachable or not responding.
func isNetworkError(err error) bool {
	if err == nil { // fast path
		return false
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return true
		}

		// If a connection drops (e.g. server dies) while sending the request
		// http.Do returns either io.EOF or io.ErrUnexpected. We treat that as
		// temp. since the server may get restarted such that the retry may succeed.
		if errors.Is(netErr, io.EOF) || errors.Is(netErr, io.ErrUnexpectedEOF) {
			return true
		}

		// The http.Client.Do method always returns an *url.Error.
		// In this case, we check whether its inner error is a
		// net.Error.
		if urlErr, ok := netErr.(*url.Error); ok {
			if errors.As(urlErr.Err, &netErr) {
				return true
			}
		}
	}

	// A best-effort attempt to detect some low-level network timeouts
	switch msg := err.Error(); {
	case strings.Contains(msg, "TLS handshake timeout"): // TLS handshake timeout
		return true
	case strings.Contains(msg, "i/o timeout"): // TCP timeout
		return true
	}
	return false
}
