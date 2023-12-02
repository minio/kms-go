// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kms

import pb "github.com/minio/kms-go/kms/protobuf"

// NodeStatusRequest contains options for fetching status
// information for one particular KMS cluster node.
type NodeStatusRequest struct{}

// StatusRequest contains options for fetching KMS cluster
// status information.
type StatusRequest struct{}

// EncryptRequest contains a plaintext message that should be encrypted and
// associated data that is crypto. bound to the resulting ciphertext.
type EncryptRequest struct {
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
