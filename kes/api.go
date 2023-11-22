// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// State is a KES server status snapshot.
type State struct {
	Version    string        // KES server version
	OS         string        // OS running the KES server
	Arch       string        // CPU architecture the KES server is running on
	UpTime     time.Duration // Time the KES server has been up and running
	CPUs       int           // Number of available logical CPU cores
	UsableCPUs int           // Number of usbale logical CPU cores
	HeapAlloc  uint64        // Number of bytes currently allocated on the heap
	StackAlloc uint64        // Number of bytes currently allocated on the stack

	KeyStoreLatency   time.Duration // The latency of the KES key store. Zero when the key store is not accessible
	KeyStoreReachable bool          // Indicates whether the key store is reachable
	KeystoreAvailable bool          // Indicates whether the key store is available and reachable
}

// MarshalJSON returns the State's JSON representation.
func (s State) MarshalJSON() ([]byte, error) {
	type JSON struct {
		Version             string        `json:"version,omitempty"`
		OS                  string        `json:"os,omitempty"`
		Arch                string        `json:"arch,omitempty"`
		UpTime              time.Duration `json:"uptime,omitempty"`
		CPUs                int           `json:"num_cpu,omitempty"`
		UsableCPUs          int           `json:"num_cpu_used,omitempty"`
		HeapAlloc           uint64        `json:"mem_heap_used,omitempty"`
		StackAlloc          uint64        `json:"mem_stack_used,omitempty"`
		KeyStoreLatency     time.Duration `json:"keystore_latency,omitempty"`
		KeyStoreUnreachable bool          `json:"keystore_unreachable,omitempty"`
		KeyStoreUnavailable bool          `json:"keystore_unavailable,omitempty"`
	}
	if s.CPUs < 0 {
		return nil, fmt.Errorf("kes: invalid number of CPUs '%d'", s.CPUs)
	}
	if s.UsableCPUs < 0 {
		return nil, fmt.Errorf("kes: invalid number of usable CPUs '%d'", s.UsableCPUs)
	}
	if !s.KeyStoreReachable && s.KeystoreAvailable {
		return nil, errors.New("kes: keystore is unreachable but available")
	}
	return json.Marshal(JSON{
		Version:             s.Version,
		OS:                  s.OS,
		Arch:                s.Arch,
		UpTime:              s.UpTime,
		CPUs:                s.CPUs,
		UsableCPUs:          s.UsableCPUs,
		HeapAlloc:           s.HeapAlloc,
		StackAlloc:          s.StackAlloc,
		KeyStoreLatency:     s.KeyStoreLatency,
		KeyStoreUnreachable: !s.KeyStoreReachable,
		KeyStoreUnavailable: !s.KeystoreAvailable,
	})
}

// UnmarshalJSON unmarshal the JSON data into State.
func (s *State) UnmarshalJSON(data []byte) error {
	type JSON struct {
		Version             string        `json:"version"`
		OS                  string        `json:"os"`
		Arch                string        `json:"arch"`
		UpTime              time.Duration `json:"uptime"`
		CPUs                int           `json:"num_cpu"`
		UsableCPUs          int           `json:"num_cpu_used"`
		HeapAlloc           uint64        `json:"mem_heap_used"`
		StackAlloc          uint64        `json:"mem_stack_used"`
		KeyStoreLatency     time.Duration `json:"keystore_latency"`
		KeyStoreUnreachable bool          `json:"keystore_unreachable"`
		KeyStoreUnavailable bool          `json:"keystore_unavailable"`
	}

	var v JSON
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	if v.CPUs < 0 {
		return fmt.Errorf("kes: invalid number of CPUs '%d'", v.CPUs)
	}
	if v.UsableCPUs < 0 {
		return fmt.Errorf("kes: invalid number of usable CPUs '%d'", v.UsableCPUs)
	}
	if v.KeyStoreUnreachable && !v.KeyStoreUnavailable {
		return errors.New("kes: keystore is unreachable but not unavailable")
	}

	s.Version = v.Version
	s.OS = v.OS
	s.Arch = v.Arch
	s.UpTime = v.UpTime
	s.CPUs = v.CPUs
	s.UsableCPUs = v.UsableCPUs
	s.HeapAlloc = v.HeapAlloc
	s.StackAlloc = v.StackAlloc
	s.KeyStoreLatency = v.KeyStoreLatency
	s.KeyStoreReachable = !v.KeyStoreUnreachable
	s.KeystoreAvailable = !v.KeyStoreUnavailable
	return nil
}

// API describes a KES server API.
type API struct {
	Method  string        // The HTTP method
	Path    string        // The API path without its arguments. For example: "/v1/status"
	MaxBody int64         // The max. size of request bodies accepted
	Timeout time.Duration // Amount of time after which request will time out
}

// MarshalJSON returns the API's JSON representation.
func (a API) MarshalJSON() ([]byte, error) {
	type JSON struct {
		Method  string `json:"method,omitempty"`
		Path    string `json:"path,omitempty"`
		MaxBody int64  `json:"max_body,omitempty"`
		Timeout int64  `json:"timeout,omitempty"`
	}
	if a.Timeout < 0 {
		return nil, fmt.Errorf("kes: invalid API timeout '%ds'", a.Timeout)
	}
	if a.MaxBody < 0 {
		return nil, fmt.Errorf("kes: invalid API max body '%d'", a.MaxBody)
	}
	return json.Marshal(JSON{
		Method:  a.Method,
		Path:    a.Path,
		MaxBody: a.MaxBody,
		Timeout: int64(a.Timeout.Truncate(time.Second).Seconds()),
	})
}

// UnmarshalJSON unmarshal the JSON data into API.
func (a *API) UnmarshalJSON(data []byte) error {
	type JSON struct {
		Method  string `json:"method"`
		Path    string `json:"path"`
		MaxBody int64  `json:"max_body"`
		Timeout int64  `json:"timeout"`
	}

	var v JSON
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	if v.Timeout < 0 {
		return fmt.Errorf("kes: invalid API timeout '%ds'", v.Timeout)
	}
	if v.MaxBody < 0 {
		return fmt.Errorf("kes: invalid API max body '%d'", v.MaxBody)
	}

	a.Method = v.Method
	a.Path = v.Path
	a.MaxBody = v.MaxBody
	a.Timeout = time.Duration(v.Timeout) * time.Second
	return nil
}
