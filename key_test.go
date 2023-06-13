// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"strconv"
	"testing"
)

func TestKeyAlgorithm_String(t *testing.T) {
	for i, test := range keyAlgorithmStringTests {
		if s := test.Algorithm.String(); s != test.String {
			t.Fatalf("Test %d: got '%s' - want '%s'", i, s, test.String)
		}
	}
}

var keyAlgorithmStringTests = []struct {
	Algorithm KeyAlgorithm
	String    string
}{
	{Algorithm: AES256, String: "AES256"},
	{Algorithm: ChaCha20, String: "ChaCha20"},
	{Algorithm: ChaCha20 + 1, String: "%!" + strconv.Itoa(int(ChaCha20+1))},
}

func TestKeyAlgorithm_MarshalText(t *testing.T) {
	for i, test := range keyAlgorithmMarshalTextTests {
		text, err := test.Algorithm.MarshalText()
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d: should have failed", i)
		}
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: failed to marshal to text: %v", i, err)
		}
		if err == nil {
			if s := string(text); s != test.String {
				t.Fatalf("Test %d: got '%s' - want '%s'", i, s, test.String)
			}
		}
	}
}

var keyAlgorithmMarshalTextTests = []struct {
	Algorithm  KeyAlgorithm
	String     string
	ShouldFail bool
}{
	{Algorithm: AES256, String: "AES256"},
	{Algorithm: ChaCha20, String: "ChaCha20"},
	{Algorithm: ChaCha20 + 1, ShouldFail: true},
}

func TestKeyAlgorithm_UnmarshalText(t *testing.T) {
	for i, test := range keyAlgorithmUnmarshalTextTests {
		var algorithm KeyAlgorithm
		err := algorithm.UnmarshalText([]byte(test.String))
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d: should have failed", i)
		}
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: failed to unmarshal from text: %v", i, err)
		}
		if err == nil {
			if algorithm != test.Algorithm {
				t.Fatalf("Test %d: got '%s' - want '%s'", i, algorithm, test.Algorithm)
			}
		}
	}
}

var keyAlgorithmUnmarshalTextTests = []struct {
	String     string
	Algorithm  KeyAlgorithm
	ShouldFail bool
}{
	{String: "AES256", Algorithm: AES256},
	{String: "ChaCha20", Algorithm: ChaCha20},

	{String: "AES256-GCM-SHA256", ShouldFail: true},
}
