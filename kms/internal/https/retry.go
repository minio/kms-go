// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package https

import (
	"context"
	"errors"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// LoadBalancer is an http.RoundTripper that implements client-side
// load balancing.
//
// A LoadBalancer distributes requests uniformly across a list of hosts.
// Clients should use the Host or URL method to construct a request to
// one of these hosts.
//
// If a request to one of these hosts fails, the LoadBalancer retries
// the request with different hosts until either the request succeeds
// or there are no hosts remaining resp. the retry limit is reached.
// Hosts for which requests fail are temporarily excluded and no longer
// selected for subsequent requests.
type LoadBalancer struct {
	// Underlying RoundTripper used to send requests.
	http.RoundTripper

	// List of hosts the requests are distributed over.
	//
	// If a request fails and its URL host is not part of
	// this list then the LoadBalancer will not retry the
	// request.
	Hosts []string

	// Timeout controls how long a host is excluded if a
	// request to this host fails. If 0, defaults to 30
	// seconds.
	Timeout time.Duration

	// Retry specifies how often the LoadBalancer retries
	// a request with different hosts bef
	Retry int

	mu      sync.RWMutex
	timeout map[string]time.Time
}

// URL returns an URL string with the next host and the provided
// path elements joined to the existing path of base and the
// resulting path cleaned of any ./ or ../ elements.
//
// The scheme of the returned URL is "https://".
// The second return value is the URL's host.
func (lb *LoadBalancer) URL(elems ...string) (string, string, error) {
	host, err := lb.Host()
	if err != nil {
		return "", host, err
	}

	const Scheme = "https://"
	if !strings.HasPrefix(host, Scheme) {
		host = Scheme + host
	}
	url, err := url.JoinPath(host, elems...)
	return url, host, err
}

// Host returns the next host to send requests to. It
// prefers hosts that aren't currently suspended.
//
// It returns an error if the list of hosts is empty
// but not if there are no non-suspended hosts.
func (lb *LoadBalancer) Host() (string, error) {
	switch len(lb.Hosts) {
	case 0:
		return "", errors.New("https: no hosts provided")
	case 1:
		return lb.Hosts[0], nil
	default:
		t, r := timeout(lb.Timeout), rand.Intn(len(lb.Hosts))

		lb.mu.RLock()
		defer lb.mu.RUnlock()

		now := time.Now()
		for i := 0; i < len(lb.Hosts); i++ {
			if timeout, ok := lb.timeout[lb.Hosts[r]]; !ok || now.Sub(timeout) > t {
				return lb.Hosts[r], nil
			}
			r = (r + 1) % len(lb.Hosts)
		}
		return lb.Hosts[r], nil
	}
}

// RoundTrip executes the HTTP request and returns the corresponding
// response on success.
//
// If the request execution fails with a retryable error, RoundTrip
// retries the request with other hosts for which requests have
// succeeded before. It stops retrying once the request succeeds,
// there are no more non-suspended hosts remaining or the retry limit
// is reached.
// Hosts, for which requests fail, are temporarily excluded and no longer
// selected for subsequent requests or retries.
func (lb *LoadBalancer) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := lb.RoundTripper.RoundTrip(req)
	if err != nil && isRetryable(err) {
		r := slices.Index(lb.Hosts, req.URL.Host)
		if r < 0 {
			return resp, err
		}

		now := time.Now()
		lb.mu.Lock()
		if lb.timeout == nil {
			lb.timeout = map[string]time.Time{}
		}
		lb.timeout[req.URL.Host] = now
		lb.mu.Unlock()

		t := timeout(lb.Timeout)
		for i := 1; i < len(lb.Hosts); i++ {
			r = (r + 1) % len(lb.Hosts)

			lb.mu.RLock()
			timeout, ok := lb.timeout[lb.Hosts[r]]
			lb.mu.RUnlock()

			if ok && now.Sub(timeout) < t {
				continue
			}
			closeResponseBody(resp)

			req.URL.Host = lb.Hosts[r]
			resp, err = lb.RoundTripper.RoundTrip(req)
			if err == nil || !isRetryable(err) {
				return resp, err
			}

			lb.mu.Lock()
			lb.timeout[req.URL.Host] = time.Now()
			lb.mu.Unlock()
		}
	}
	return resp, err
}

func timeout(d time.Duration) time.Duration {
	if d <= 0 {
		return 30 * time.Second
	}
	return d
}

func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}

	return true
}

func closeResponseBody(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}

	const maxBodySlurpSize = 2 << 10
	if resp.ContentLength == -1 || resp.ContentLength <= maxBodySlurpSize {
		io.CopyN(io.Discard, resp.Body, maxBodySlurpSize)
	}
	resp.Body.Close()
}
