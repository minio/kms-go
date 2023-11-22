// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"time"
)

// IdentityUnknown is the identity returned
// by an IdentityFunc if it cannot map a
// particular X.509 certificate to an actual
// identity.
const IdentityUnknown Identity = ""

// An Identity should uniquely identify a client and
// is computed from the X.509 certificate presented
// by the client during the TLS handshake using an
// IdentityFunc.
type Identity string

// IsUnknown returns true if and only if the
// identity is IdentityUnknown.
func (id Identity) IsUnknown() bool { return id == IdentityUnknown }

// String returns the string representation of
// the identity.
func (id Identity) String() string { return string(id) }

// IdentityInfo describes a KES identity.
type IdentityInfo struct {
	Identity  Identity
	IsAdmin   bool      // Indicates whether the identity has admin privileges
	Policy    string    // Name of the associated policy
	CreatedAt time.Time // Point in time when the identity was created
	CreatedBy Identity  // Identity that created the identity
	ExpiresAt time.Time
	TTL       time.Duration
}

// CreateIdentityRequest is the request type for creating
// a new identity at a KES server.
type CreateIdentityRequest struct {
	Policy string
	Admin  bool
	TTL    time.Duration
}
