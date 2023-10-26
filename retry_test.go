// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

var retryBodyTests = []struct {
	Body io.ReadSeeker
}{
	{Body: nil},
	{Body: bytes.NewReader(nil)},
}

func TestRetryBody(t *testing.T) {
	for i, test := range retryBodyTests {
		body := retryBody(test.Body)
		if test.Body == nil && body != nil {
			t.Fatalf("Test %d: invalid retry body: got %v - want %v", i, body, test.Body)
		}
		if test.Body != nil {
			if _, ok := body.(io.Seeker); !ok {
				t.Fatalf("Test %d: retry body does not implement io.Seeker", i)
			}
		}
	}
}

var isNetworkErrorTests = []struct {
	Err            error
	IsNetworkError bool
}{
	{Err: nil, IsNetworkError: false},
	{Err: io.EOF, IsNetworkError: false},
	{Err: url.InvalidHostError(""), IsNetworkError: false},
	{
		Err: &url.Error{
			Op:  "GET",
			URL: "http://127.0.0.1",
			Err: net.UnknownNetworkError("unknown"),
		},
		IsNetworkError: true,
	},
	{
		Err: &url.Error{
			Op:  "GET",
			URL: "http://127.0.0.1",
			Err: &net.DNSError{},
		},
		IsNetworkError: true,
	},
	{
		Err: &url.Error{
			Op:  "GET",
			URL: "http://127.0.0.1",
			Err: io.EOF,
		},
		IsNetworkError: true,
	},
}

func TestIsNetworkError(t *testing.T) {
	for i, test := range isNetworkErrorTests {
		temp := isNetworkError(test.Err)
		switch {
		case test.IsNetworkError == true && temp == false:
			t.Fatalf("Test %d: err should be a network error but it is not", i)
		case test.IsNetworkError == false && temp == true:
			t.Fatalf("Test %d: err should not be a network error but it is", i)
		}
	}
}

type MockResolver struct {
	DNSRecords map[string][]string
}

func (m *MockResolver) LookupHost(_ context.Context, host string) (addrs []string, err error) {
	var ok bool
	addrs, ok = m.DNSRecords[host]
	if !ok {
		return nil, errors.New("Unable to lookup host")
	}
	return
}

func MockSendRequestWithCounter(code int, returnError bool) (*atomic.Uint32, func(ctx context.Context, epr *endpointRequest) (*http.Response, error)) {
	counter := atomic.Uint32{}
	return &counter, func(_ context.Context, epr *endpointRequest) (*http.Response, error) {
		counter.Add(1)
		if !returnError {
			resp := new(http.Response)
			resp.StatusCode = code
			resp.Proto = epr.addr
			return resp, nil
		}
		return nil, errors.New(epr.addr)
	}
}

func MockSendRequest(code int, returnError bool) func(ctx context.Context, epr *endpointRequest) (*http.Response, error) {
	return func(_ context.Context, epr *endpointRequest) (*http.Response, error) {
		if !returnError {
			resp := new(http.Response)
			resp.StatusCode = code
			resp.Proto = epr.addr
			return resp, nil
		}
		return nil, errors.New(epr.addr)
	}
}

type MockRandomNumber struct {
	Number int
}

func (m *MockRandomNumber) Intn(_ int) int {
	return m.Number
}

func MockGetInterfaces() (ifs []net.Addr, err error) {
	ifs, err = net.InterfaceAddrs()
	if err != nil {
		return
	}

	newInterface := new(net.IPNet)
	newInterface.IP = net.IP{171, 171, 0, 1}
	newInterface.Mask = net.IPMask{255, 255, 255, 0}
	ifs = append(ifs, newInterface)

	newInterface2 := new(net.IPNet)
	newInterface2.IP = net.IP{182, 182, 0, 1}
	newInterface2.Mask = net.IPMask{255, 255, 255, 0}
	ifs = append(ifs, newInterface2)

	return
}

func TestPrepareLoadBalancer(t *testing.T) {
	Resolver := new(MockResolver)
	Resolver.DNSRecords = make(map[string][]string)
	Resolver.DNSRecords["minio.remote"] = []string{"1.1.1.1", "8.8.8.8"}
	Resolver.DNSRecords["minio.remote2"] = []string{"123.121.123.13", "123.121.123.12", "123.121.123.15"}
	Resolver.DNSRecords["minio.remote3"] = []string{"8e6e:dd85:041c:5e77:4f44:3484:c050:be7e"}
	Resolver.DNSRecords["minio.local"] = []string{"127.0.0.1"}
	Resolver.DNSRecords["minio.local2"] = []string{"171.171.0.10", "171.171.0.11"}
	Resolver.DNSRecords["minio.local3"] = []string{"182.182.0.10", "182.182.0.11"}

	lb := &loadBalancer{
		enclave:          "",
		DNSResolver:      Resolver,
		getLocalNetworks: MockGetInterfaces,
		rand:             rand.New(rand.NewSource(time.Now().UnixNano())),
	}

	dnsErrorEndpoint := "https://minio.404:7373"
	endpoints := []string{
		dnsErrorEndpoint,
		"https://127.0.0.1:7373",
		"https://localhost:7373",
		"https://minio.local:7373",
		"https://minio.local2:7373",
		"https://minio.local3:7373",
		"https://minio.remote:7373",
		"https://minio.remote2:7373",
		"https://minio.remote3:7373",
	}

	lb.prepareLoadBalancer(endpoints)
	notFoundInList := false
	for i, v := range lb.endpoints {
		if v.addr == dnsErrorEndpoint {
			notFoundInList = true
		}
		switch i {
		case 0, 1, 2:
			if !v.localhost {
				t.Fatalf("Expected endpoint at index %d to be localhost: %s", i, v.addr)
			}
			if v.local {
				t.Fatalf("Expected endpoint at index %d to not be local: %s", i, v.addr)
			}
		case 3, 4:
			if v.localhost {
				t.Fatalf("Expected endpoint at index %d to not be localhost: %s", i, v.addr)
			}
			if !v.local {
				t.Fatalf("Expected endpoint at index %d to be local: %s", i, v.addr)
			}
		default:
			if v.localhost || v.local {
				t.Fatalf("Expected endpoint at index %d to not be localhost or local: %s", i, v.addr)
			}
		}
	}

	if !notFoundInList {
		t.Fatalf("minio.404 not found in list.")
	}
}

func TestLoadBalancerSend_SingleHost(t *testing.T) {
	Resolver := new(MockResolver)
	Resolver.DNSRecords = make(map[string][]string)
	Resolver.DNSRecords["minio.local"] = []string{"127.0.0.1"}

	lb := &loadBalancer{
		enclave:          "",
		DNSResolver:      Resolver,
		getLocalNetworks: MockGetInterfaces,
		sendRequest:      MockSendRequest(200, false),
		rand:             rand.New(rand.NewSource(time.Now().UnixNano())),
	}

	retryClient := new(retry)
	ctx := context.Background()
	path := "/bucket1/object1"
	method := "POST"
	var options []requestOption

	endpoints := []string{
		"https://minio.local:7373",
	}

	lb.prepareLoadBalancer(endpoints)

	// This test ensures that localhost is prioritized and that
	// it is not placed in a timed-out state.
	resp, _ := lb.Send(ctx, retryClient, method, path, nil, options...)
	if resp.Proto != endpoints[0] {
		t.Fatalf("Expected response.Proto (%s) to equal endpoint (%s)", resp.Proto, endpoints[0])
	}

	for _, v := range lb.endpoints {
		if !v.timeout.IsZero() {
			t.Fatalf("Endpoint %s was expected to NOT be timed-out", v.addr)
		}
	}

	lb.sendRequest = MockSendRequest(0, true)
	// We do not want to place an endpoint in a timed-out state if
	// we only have one. This test ensures that a load balancer with
	// only a single endpoint never places that endpoint in a timed-out state.
	_, err := lb.Send(ctx, retryClient, method, path, nil, options...)
	if err == nil {
		t.Fatalf("Endpoint was expected to return an error")
	}
	lb.sendRequest = MockSendRequest(500, false)
	resp, _ = lb.Send(ctx, retryClient, method, path, nil, options...)
	if resp.Proto != endpoints[0] {
		t.Fatalf("Expected response.Proto (%s) to equal endpoint (%s)", resp.Proto, endpoints[0])
	}

	for _, v := range lb.endpoints {
		if !v.timeout.IsZero() {
			t.Fatalf("Endpoint %s was expected to NOT be timed-out", v.addr)
		}
	}
}

func TestLoadBalancerSend_MultiHost(t *testing.T) {
	Resolver := new(MockResolver)
	Resolver.DNSRecords = make(map[string][]string)
	Resolver.DNSRecords["minio.remote"] = []string{"1.1.1.1", "8.8.8.8"}
	Resolver.DNSRecords["minio.remote2"] = []string{"1.1.1.1", "8.8.8.8"}
	Resolver.DNSRecords["minio.remote3"] = []string{"1.1.1.1", "8.8.8.8"}
	Resolver.DNSRecords["minio.remote4"] = []string{"1.1.1.1", "8.8.8.8"}
	Resolver.DNSRecords["minio.remote5"] = []string{"123.121.123.13", "123.121.123.12", "123.121.123.15"}
	Resolver.DNSRecords["minio.local"] = []string{"127.0.0.1"}

	lb := &loadBalancer{
		enclave:          "",
		DNSResolver:      Resolver,
		getLocalNetworks: MockGetInterfaces,
		sendRequest:      MockSendRequest(200, false),
		rand:             rand.New(rand.NewSource(time.Now().UnixNano())),
	}

	retryClient := new(retry)
	ctx := context.Background()
	path := "/bucket1/object1"
	method := "POST"
	var options []requestOption

	endpoints := []string{
		"https://minio.local:7373",
		"https://minio.remote:7373",
		"https://minio.remote2:7373",
		"https://minio.remote3:7373",
		"https://minio.remote4:7373",
		"https://minio.remote5:7373",
	}
	lb.prepareLoadBalancer(endpoints)

	// This test will ensure that a localhost endpoint is present
	// at index 0 and is prioritized during load balancing.
	resp, _ := lb.Send(ctx, retryClient, method, path, nil, options...)
	if resp.Proto != endpoints[0] {
		t.Fatalf("Expected response.Proto (%s) to equal endpoint (%s)", resp.Proto, endpoints[0])
	}

	endpoints = []string{
		"https://minio.remote:7373",
		"https://minio.remote2:7373",
		"https://minio.remote3:7373",
		"https://minio.remote4:7373",
		"https://minio.remote5:7373",
	}
	lb.prepareLoadBalancer(endpoints)

	// This test will return a 500 error code for all requests
	// which places all endpoints into a timed-out state.
	counter, sendFunc := MockSendRequestWithCounter(500, false)
	lb.sendRequest = sendFunc
	_, _ = lb.Send(ctx, retryClient, method, path, nil, options...)
	for _, v := range lb.endpoints {
		if v.timeout.IsZero() {
			t.Fatalf("Endpoint %s was expected to be timed-out", v.addr)
		}
	}

	// This test will make a request while all endpoints are
	// in a timed-out state.
	// When all endpoints are in a timed-out state, the retry
	// mechanism kicks in. During a retry all timeouts are ignored
	// and we should see the number of requests be equal to the
	// number of endpoints.
	counter.Store(0)
	_, _ = lb.Send(ctx, retryClient, method, path, nil, options...)
	count := counter.Load()
	if count != 5 {
		t.Fatalf("Request count expected to be 5 but was %d", count)
	}

	// This test ensures that status code 501 does not
	// place the endpoint in a timed-out state.
	lb.prepareLoadBalancer(endpoints)
	lb.sendRequest = MockSendRequest(501, false)
	_, _ = lb.Send(ctx, retryClient, method, path, nil, options...)
	for _, v := range lb.endpoints {
		if !v.timeout.IsZero() {
			t.Fatalf("Endpoint %s was expected to NOT be timed-out", v.addr)
		}
	}

	// This test ensures that an error response will
	// place and endpoint in a timed-out state.
	lb.prepareLoadBalancer(endpoints)
	lb.sendRequest = MockSendRequest(0, true)
	_, _ = lb.Send(ctx, retryClient, method, path, nil, options...)
	for _, v := range lb.endpoints {
		if v.timeout.IsZero() {
			t.Fatalf("Endpoint %s was expected to be timed-out", v.addr)
		}
	}

	// This request ensures all endpoints are placed in a timed-out state.
	lb.prepareLoadBalancer(endpoints)
	lb.sendRequest = MockSendRequest(0, true)
	_, _ = lb.Send(ctx, retryClient, method, path, nil, options...)

	// We want to shift the timeout timestamps to a date in the past
	// in order to trigger probing.
	for i := range lb.endpoints {
		lb.endpoints[i].timeout = time.Now().AddDate(0, 0, -1)
	}

	// This test triggers a probe on all endpoints in order
	// to clear all timeouts
	mockRandom := new(MockRandomNumber)
	lb.rand = mockRandom
	mockRandom.Number = 0
	lb.sendRequest = MockSendRequest(200, false)
	for i := 0; i < len(endpoints); i++ {
		_, _ = lb.Send(ctx, retryClient, method, path, nil, options...)
		mockRandom.Number++
	}

	for _, v := range lb.endpoints {
		if !v.timeout.IsZero() {
			t.Fatalf("Endpoint %s was expected to NOT be timed-out", v.addr)
		}
	}
}
