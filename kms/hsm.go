// Copyright 2024 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kms

import (
	"context"
	"io"

	"aead.dev/mtls"
)

// HSM is a (hardware) security module that seals and unseals
// cryptographic keys.
type HSM interface {
	// Name returns the name of the HSM. Each HSM implementation
	// should have an unique name.
	Name() string

	// Seal seals the given plaintext and returns the
	// corresponding ciphertext.
	Seal(ctx context.Context, plaintext []byte) ([]byte, error)

	// Unseal unseals the given ciphertext and returns the
	// corresponding plaintext.
	Unseal(ctx context.Context, ciphertext []byte) ([]byte, error)

	// PrivateKey returns a new TLS private key for the given seed.
	// The seed may be nil or empty.
	PrivateKey(ctx context.Context, seed []byte) (mtls.PrivateKey, error)

	io.Closer
}
