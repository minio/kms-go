// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kms

import (
	pb "github.com/minio/kms-go/kms/protobuf"
)

// ListRequest contains generic options for listing elements,
// like enclaves or keys.
type ListRequest struct {
	// Prefix is an optional prefix to start the listing from.
	// For example, an application may want to list all keys
	// starting with "foo", like "foo-1" and "foobar".
	//
	// Only elements with a name that match this prefix are
	// returned by list operations. An empty prefix matches
	// any name.
	Prefix string

	// ContinueAt specifies an element name from where to
	// continue a list operation. When listing a lot of
	// elements, not all may fit into a single ListResponse.
	// Applications can paginate through a long list of
	// elements by setting a ContinueAt value.
	//
	// ContinueAt must match an element's name exactly.
	// Using a ContinueAt value that does not start with
	// the Prefix will lead to an empty listing result.
	ContinueAt string

	// Limit limits the number of elements returned by
	// a list operation. If <= 0, no limit is specified
	// and the server limits listing results to a
	// reasonable max. size.
	Limit int
}

// NodeStatusRequest contains options for fetching status
// information for one particular KMS cluster node.
type NodeStatusRequest struct{}

// StatusRequest contains options for fetching KMS cluster
// status information.
type StatusRequest struct{}

// AddNodeRequest describes which KMS server to add to an existing.
type AddNodeRequest struct {
	// Host is the KMS server that should join a cluster.
	// It must be of the form "host" or "host:port".
	Host string
}

// RemoveNodeRequest describes which server to remove from a KMS
// cluster.
type RemoveNodeRequest struct {
	// Host is the KMS server that should leave a cluster.
	// It must be of the form "host" or "host:port".
	Host string
}

// CreateEnclaveRequest contains options for creating enclaves.
type CreateEnclaveRequest struct {
	// Name is the name of the enclave to create.
	Name string
}

// DescribeEnclaveRequest contains options for fetching metadata
// about an enclave.
type DescribeEnclaveRequest struct {
	// Name is the name of the enclave to delete.
	Name string
}

// DeleteEnclaveRequest contains options for deleting enclaves.
type DeleteEnclaveRequest struct {
	// Name is the name of the enclave to delete.
	Name string
}

// CreateKeyRequest contains options for creating secret keys.
type CreateKeyRequest struct {
	// Enclave is the KMS enclave in which the key is created.
	Enclave string

	// Name is the name of the key to create.
	Name string

	// Type of the key that is created. If not set, the server
	// will pick the key type.
	Type SecretKeyType
}

// MarshalPB converts the CreateKeyRequest into its protobuf representation.
func (r *CreateKeyRequest) MarshalPB(v *pb.CreateKeyRequest) error {
	if r.Type == 0 {
		v.Type = nil
	} else {
		v.Type = new(string)
		*v.Type = r.Type.String()
	}
	return nil
}

// UnmarshalPB initializes the CreateKeyRequest from its protobuf representation.
func (r *CreateKeyRequest) UnmarshalPB(v *pb.CreateKeyRequest) error {
	if v.Type == nil {
		r.Type = 0
		return nil
	}

	t, err := secretKeyTypeFromString(v.GetType())
	if err != nil {
		return err
	}

	r.Type = t
	return nil
}

// DeleteKeyRequest contains options for deleting secret keys.
type DeleteKeyRequest struct {
	// Enclave is the KMS enclave containing the master key.
	Enclave string

	// Name is the name of the key to delete.
	Name string

	// Version is an optional version referring to the key
	// version within the key ring to delete. If <= 0, refers
	// to the latest version.
	Version int
}

// MarshalPB converts the DeleteKeyRequest into its protobuf representation.
func (r *DeleteKeyRequest) MarshalPB(v *pb.DeleteKeyRequest) error {
	if r.Version <= 0 {
		v.Version = 0
	} else {
		v.Version = uint32(r.Version)
	}
	return nil
}

// UnmarshalPB initializes the DeleteKeyRequest from its protobuf representation.
func (r *DeleteKeyRequest) UnmarshalPB(v *pb.DeleteKeyRequest) error {
	r.Version = int(v.Version)
	return nil
}

// DescribeKeyVersionRequest contains options for fetching
// metadata about a key version.
type DescribeKeyVersionRequest struct {
	// Enclave is the KMS enclave containing the master key.
	Enclave string

	// Name is the name of the master key.
	Name string
}

// EncryptRequest contains a plaintext message that should be encrypted and
// associated data that is crypto. bound to the resulting ciphertext.
type EncryptRequest struct {
	// Enclave is the KMS enclave containing the master key.
	Enclave string

	// Name is the name of the master key.
	Name string

	// Plaintext is the plain message that is encrypted.
	Plaintext []byte

	// AssociatedData is additional data that is not encrypted but crypto. bound
	// to the ciphertext. The same associated data must be provided when decrypting
	// the ciphertext.
	//
	// Associated data should describe the context of the plaintext data. For example,
	// the name of the file that gets encrypted.
	AssociatedData []byte
}

// MarshalPB converts the EncryptRequest into its protobuf representation.
func (r *EncryptRequest) MarshalPB(v *pb.EncryptRequest) error {
	v.Plaintext = r.Plaintext
	v.AssociatedData = r.AssociatedData
	return nil
}

// UnmarshalPB initializes the EncryptRequest from its protobuf representation.
func (r *EncryptRequest) UnmarshalPB(v *pb.EncryptRequest) error {
	r.Plaintext = v.Plaintext
	r.AssociatedData = v.AssociatedData
	return nil
}

// GenerateKeyRequest contains options for generating a new unique data encryption key.
type GenerateKeyRequest struct {
	// Enclave is the KMS enclave containing the master key.
	Enclave string

	// Name is the name of the master key.
	Name string

	// AssociatedData is additional data that is not encrypted but crypto. bound
	// to the ciphertext of the data encryption key. The same associated data must
	// be provided when decrypting the ciphertext.
	//
	// Associated data should describe the context within the data encryption key
	// is used. For example, the name of the file that gets encrypted with the
	// data encryption key.
	AssociateData []byte

	// Length is an optional length of the generated plaintext data encryption key
	// in bytes. At most 1024 (8192 bits). If <= 0, defaults to 32 (256 bits).
	Length int
}

// MarshalPB converts the GenerateKeyRequest into its protobuf representation.
func (r *GenerateKeyRequest) MarshalPB(v *pb.GenerateKeyRequest) error {
	v.AssociatedData = r.AssociateData
	if r.Length > 0 {
		v.Length = new(uint32)
		*v.Length = uint32(r.Length)
	}
	return nil
}

// UnmarshalPB initializes the GenerateKeyRequest from its protobuf representation.
func (r *GenerateKeyRequest) UnmarshalPB(v *pb.GenerateKeyRequest) error {
	r.AssociateData = v.AssociatedData
	if v.Length != nil {
		r.Length = int(*v.Length)
	}
	return nil
}

// DecryptRequest contains a ciphertext message that should be decrypted.
type DecryptRequest struct {
	// Enclave is the KMS enclave containing the master key.
	Enclave string

	// Name is the name of the master key.
	Name string

	// Version identifies the key version within the key ring that should be
	// used to decrypt the ciphertext.
	Version int

	// Ciphertext is the encrypted message that is decrypted.
	Ciphertext []byte

	// AssociatedData is additional data that has been crypto. bound to the
	// ciphertext.
	AssociateData []byte
}

// MarshalPB converts the DecryptKeyRequest into its protobuf representation.
func (r *DecryptRequest) MarshalPB(v *pb.DecryptRequest) error {
	v.Version = uint32(r.Version)
	v.Ciphertext = r.Ciphertext
	v.AssociatedData = r.AssociateData
	return nil
}

// UnmarshalPB initializes the DecryptKeyRequest from its protobuf representation.
func (r *DecryptRequest) UnmarshalPB(v *pb.DecryptRequest) error {
	r.Version = int(v.Version)
	r.Ciphertext = v.Ciphertext
	r.AssociateData = v.AssociatedData
	return nil
}
