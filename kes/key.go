// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"encoding/json"
	"errors"
	"strconv"
	"time"
)

// ImportKeyRequest is the request type for importing a key
// into a KES server.
type ImportKeyRequest struct {
	Key    []byte
	Cipher KeyAlgorithm
}

// DEK is a data encryption key. It has a plaintext
// and a ciphertext representation.
//
// Applications should use the plaintext for cryptographic
// operations and store the ciphertext at a durable
// location.
//
// If the DEK is used to e.g. encrypt some data then it's
// safe to store the DEK's ciphertext representation next
// to the encrypted data. The ciphertext representation
// does not need to stay secret.
type DEK struct {
	Plaintext  []byte
	Ciphertext []byte
}

// All valid cryptographic algorithms that can be used with keys.
const (
	AES256 = iota
	ChaCha20
)

// KeyAlgorithm is an enum representing the algorithm
// a cryptographic key can be used with.
type KeyAlgorithm uint

// String returns the KeyAlgorithm's string representation.
func (a KeyAlgorithm) String() string {
	switch a {
	case AES256:
		return "AES256"
	case ChaCha20:
		return "ChaCha20"
	default:
		return "%!" + strconv.Itoa(int(a))
	}
}

// MarshalText returns the KeyAlgorithm's text representation.
// In contrast to String, it represents KeyAlgorithmUndefined
// as empty string and returns an error if the KeyAlgorithm
// isn't valid.
func (a KeyAlgorithm) MarshalText() ([]byte, error) {
	switch a {
	case AES256:
		return []byte("AES256"), nil
	case ChaCha20:
		return []byte("ChaCha20"), nil
	default:
		return nil, errors.New("kes: invalid key algorithm '" + strconv.Itoa(int(a)) + "'")
	}
}

// UnmarshalText parses text as KeyAlgorithm text representation.
func (a *KeyAlgorithm) UnmarshalText(text []byte) error {
	switch s := string(text); s {
	case "AES256", "AES256-GCM_SHA256":
		*a = AES256
		return nil
	case "ChaCha20", "XCHACHA20-POLY1305":
		*a = ChaCha20
		return nil
	default:
		return errors.New("kes: invalid key algorithm '" + s + "'")
	}
}

// KeyInfo describes a cryptographic key at a KES server.
type KeyInfo struct {
	Name      string       // Name of the cryptographic key
	Algorithm KeyAlgorithm // Cryptographic algorithm the key can be used with
	CreatedAt time.Time    // Point in time when the key was created
	CreatedBy Identity     // Identity that created the key
}

// MarshalJSON returns the KeyInfo's JSON representation.
func (k *KeyInfo) MarshalJSON() ([]byte, error) {
	type JSON struct {
		Name      string       `json:"name"`
		Algorithm KeyAlgorithm `json:"algorithm,omitempty"`
		CreatedAt time.Time    `json:"created_at,omitempty"`
		CreatedBy Identity     `json:"created_by,omitempty"`
	}
	return json.Marshal(JSON{
		Name:      k.Name,
		Algorithm: k.Algorithm,
		CreatedAt: k.CreatedAt,
		CreatedBy: k.CreatedBy,
	})
}

// UnmarshalJSON parses text as KeyInfo JSON representation.
func (k *KeyInfo) UnmarshalJSON(text []byte) error {
	type JSON struct {
		Name      string       `json:"name"`
		Algorithm KeyAlgorithm `json:"algorithm"`
		CreatedAt time.Time    `json:"created_at"`
		CreatedBy Identity     `json:"created_by"`
	}
	var v JSON
	if err := json.Unmarshal(text, &v); err != nil {
		return err
	}

	k.Name = v.Name
	k.Algorithm = v.Algorithm
	k.CreatedAt = v.CreatedAt
	k.CreatedBy = v.CreatedBy
	return nil
}
