// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kms

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
)

// An Identity uniquely identifies a private/public key pair.
// It is a hex-encoded string computed from the DER-encoded
// X.509 certificate public key info.
//
// For example:
//
//	shasum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
//	identity := hex.EncodeToString(shasum[:])
//
// By verifying the peer's identity, two parties can detect
// MitM¹ attacks during a protocol handshake, like in TLS.
// An identity pins the public key, similar to SSH² or HPKP³.
//
// The empty string represents a pseudo identity and indicates
// that no public key has been provided.
//
// Ref:
// [1] https://en.wikipedia.org/wiki/Man-in-the-middle_attack
// [2] https://en.wikipedia.org/wiki/Key_fingerprint
// [3] https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning
type Identity string

// An APIKey represents a public/private key pair.
//
// An API key can be used to authenticate to a TLS server via
// mTLS¹ by generating a X.509 certificate from the API key's
// public key.
//
// Ref:
// [1] https://en.wikipedia.org/wiki/Mutual_authentication#mTLS
type APIKey interface {
	// Public returns the API key's public key.
	Public() crypto.PublicKey

	// Private returns the API key's private key.
	Private() crypto.PrivateKey

	// Identity returns the Identity associated with the
	// public key.
	Identity() Identity

	// String returns the API key's string representation.
	String() string
}

// GenerateAPIKey generates a new API key using the given
// io.Reader as source of randomness.
//
// If random is nil, the standard library crypto/rand.Reader
// is used.
func GenerateAPIKey(random io.Reader) (APIKey, error) {
	pub, priv, err := ed25519.GenerateKey(random)
	if err != nil {
		return nil, err
	}

	id, err := ed25519Identity(pub)
	if err != nil {
		return nil, err
	}
	return &apiKey{
		key:      priv,
		identity: id,
	}, nil
}

// ParseAPIKey parses s as formatted API key.
func ParseAPIKey(s string) (APIKey, error) {
	const Ed25519 = 0

	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 1+ed25519.SeedSize {
		return nil, errors.New("kes: invalid API key: invalid length")
	}
	if b[0] != Ed25519 {
		return nil, errors.New("kes: invalid API key: unsupported type")
	}

	key := ed25519.NewKeyFromSeed(b[1:])
	id, err := ed25519Identity(key[ed25519.SeedSize:])
	if err != nil {
		return nil, err
	}
	return &apiKey{
		key:      key,
		identity: id,
	}, nil
}

// apiKey is an APIKey implementation using Ed25519 public/private keys.
type apiKey struct {
	key      ed25519.PrivateKey
	identity Identity
}

func (ak *apiKey) Public() crypto.PublicKey { return ak.key.Public() }

func (ak *apiKey) Private() crypto.PrivateKey {
	private := make([]byte, 0, len(ak.key))
	return ed25519.PrivateKey(append(private, ak.key...))
}

func (ak *apiKey) Identity() Identity { return ak.identity }

func (ak *apiKey) String() string {
	const Ed25519Type = 0
	k := make([]byte, 0, 1+ed25519.SeedSize)
	k = append(k, Ed25519Type)
	k = append(k, ak.key[:ed25519.SeedSize]...)
	return base64.StdEncoding.EncodeToString(k)
}

func ed25519Identity(pubKey []byte) (Identity, error) {
	type publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}

	derPublicKey, err := asn1.Marshal(publicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 3, 101, 112},
		},
		PublicKey: asn1.BitString{BitLength: len(pubKey) * 8, Bytes: pubKey},
	})
	if err != nil {
		return "", err
	}
	id := sha256.Sum256(derPublicKey)
	return Identity(hex.EncodeToString(id[:])), nil
}
