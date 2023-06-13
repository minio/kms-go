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

// SecretOptions is a struct containing customization
// options for secret - like the Secret type.
type SecretOptions struct {
	// Type specifies the type of the Secret.
	// Its default vaule is SecretGeneric.
	Type SecretType
}

// All valid secret types.
const (
	SecretGeneric SecretType = iota
)

// SecretType is an enum representing the type of a Secret.
type SecretType uint

// String returns the SecretType string representation.
func (s SecretType) String() string {
	switch s {
	case SecretGeneric:
		return "generic"
	default:
		return "%!" + strconv.Itoa(int(s))
	}
}

// MarshalText returns the SecretType text representation.
// In contrast to String, it returns an error if s is not
// a valid SecretType.
func (s SecretType) MarshalText() ([]byte, error) {
	switch s {
	case SecretGeneric:
		return []byte("generic"), nil
	default:
		return nil, errors.New("kes: invalid secret type '" + strconv.Itoa(int(s)) + "'")
	}
}

// UnmarshalText decodes the given SecretType text
// representation into s. It returns an error if
// text is not a valid SecretType.
func (s *SecretType) UnmarshalText(text []byte) error {
	switch v := string(text); v {
	case "generic":
		*s = SecretGeneric
		return nil
	default:
		return errors.New("kes: invalid secret type '" + v + "'")
	}
}

// SecretInfo describes a secret at a KES server.
type SecretInfo struct {
	Name      string     // The name of the secret
	Type      SecretType // The type of secret
	CreatedAt time.Time  // Point in time when the secret was created
	CreatedBy Identity   // Identity that created the secret
}

// MarshalJSON returns the SecretInfo JSON representation.
func (s *SecretInfo) MarshalJSON() ([]byte, error) {
	type JSON struct {
		Name      string     `json:"name,omitempty"`
		Type      SecretType `json:"type,omitempty"`
		CreatedAt time.Time  `json:"created_at,omitempty"`
		CreatedBy Identity   `json:"created_by,omitempty"`
	}
	return json.Marshal(JSON{
		Name:      s.Name,
		Type:      s.Type,
		CreatedAt: s.CreatedAt,
		CreatedBy: s.CreatedBy,
	})
}

// UnmarshalJSON decodes the given JSON data into the SecretInfo.
func (s *SecretInfo) UnmarshalJSON(data []byte) error {
	type JSON struct {
		Name      string     `json:"name"`
		Type      SecretType `json:"type"`
		CreatedAt time.Time  `json:"created_at"`
		CreatedBy Identity   `json:"created_by"`
	}

	var v JSON
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	s.Name = v.Name
	s.Type = v.Type
	s.CreatedAt = v.CreatedAt
	s.CreatedBy = v.CreatedBy
	return nil
}
