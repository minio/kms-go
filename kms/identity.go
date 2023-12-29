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
	"errors"
	"io"
	"strconv"
	"strings"
)

// An Identity uniquely identifies a private/public key pair.
// It consists of a prefix for the hash function followed by
// the URL base64-encoded hash of the public key.
//
// For example:
//
//	h1:BPbFim5DqUozIYOjcaRAtImU6TdD6W2_chOgxDyCuDw
//
// This package uses the "h1:" prefix for SHA-256 and computes
// the hash of X.509 certificates from the certificate's
// DER-encoded public key info.
//
// For example:
//
//	shasum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
//	identity := "h1:" + base64.RawURLEncoding.EncodeToString(shasum[:])
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

func (i Identity) String() string { return string(i) }

// Privilege represents an access control role of identities.
// An identity with a higher privilege has access to more APIs.
//
// As a general security best practice, identities should have
// the lowest privilege required to perform their tasks.
type Privilege uint

// Supported privileges.
const (
	// SysAdmin is the highest privilege within the KMS, similar to
	// root on unix systems. An identity with the SysAdmin privilege
	// has access to all public APIs. Identities with the SysAdmin
	// privilege should be used for provisioning and to manage the
	// KMS cluster.
	SysAdmin Privilege = iota + 1

	// Admin is the privilege that allows identities to perform all
	// operations within an enclave. In contrast to sysadmins, admins
	// cannot peform cluster management tasks or manage enclaves.
	Admin

	// User is the privilege with limited access within an enclave.
	// Identities with the User privilege can only perform operations
	// within an enclave and only with an associated policy allowing
	// the API operation.
	User
)

// ParsePrivilege parses s as privilege string representation.
func ParsePrivilege(s string) (Privilege, error) {
	switch s {
	default:
		return 0, errors.New("kms: invalid privilege '" + s + "'")
	case "SysAdmin":
		return SysAdmin, nil
	case "Admin":
		return Admin, nil
	case "User":
		return User, nil
	}
}

// String returns the string representation of the Privilege.
func (p Privilege) String() string {
	switch p {
	case SysAdmin:
		return "SysAdmin"
	case Admin:
		return "Admin"
	case User:
		return "User"
	default:
		return "!INVALID:" + strconv.Itoa(int(p))
	}
}

// An APIKey represents a public/private key pair.
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
	s, found := strings.CutPrefix(s, "k1:")
	if !found {
		return nil, errors.New("kms: invalid API key type")
	}

	if base64.RawURLEncoding.DecodedLen(len(s)) != ed25519.SeedSize {
		return nil, errors.New("kms: invalid API key length")
	}

	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.SeedSize {
		return nil, errors.New("kms: invalid API key length")
	}

	key := ed25519.NewKeyFromSeed(b)
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
	return "k1:" + base64.RawURLEncoding.EncodeToString(ak.key[:ed25519.SeedSize])
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
	return "h1:" + Identity(base64.RawURLEncoding.EncodeToString(id[:])), nil
}
