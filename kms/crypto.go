// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kms

import (
	"fmt"
	"strconv"
)

// ParseSecretKeyType returns a SecretKeyType from its string representation.
func ParseSecretKeyType(s string) (SecretKeyType, error) {
	switch s {
	case "AES256":
		return AES256, nil
	case "ChaCha20":
		return ChaCha20, nil
	default:
		return 0, fmt.Errorf("kms: key type '%s' is not supported", s)
	}
}

// SecretKeyType defines the type of a secret key. Secret keys with
// different types are not compatible since they may differ in the
// encryption algorithm, key length, cipher mode, etc.
type SecretKeyType uint

// Supported secret key types.
const (
	// AES256 represents the AES-256-GCM secret key type.
	AES256 SecretKeyType = iota + 1

	// ChaCha20 represents the ChaCha20-Poly1305 secret key type.
	ChaCha20
)

// String returns the string representation of the SecretKeyType.
func (s SecretKeyType) String() string {
	switch s {
	case AES256:
		return "AES256"
	case ChaCha20:
		return "ChaCha20"
	default:
		return "!INVALID:" + strconv.Itoa(int(s))
	}
}
