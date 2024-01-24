// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kms

import (
	"errors"

	pb "github.com/minio/kms-go/kms/protobuf"
)

// ListRequest contains generic options for listing elements,
// like enclaves or keys.
type ListRequest struct {
	// Enclave is the enclave in which to list elements. For
	// example keys or policies. It is ignored when listing
	// enclaves.
	Enclave string

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

// EditClusterRequest contains updates to the cluster definition
// and allows clients to edit the cluster definition directly without
// requiring write quorum.
type EditClusterRequest struct {
	// Host is the KMS server where the cluster definition should be
	// modified. If empty, a Client will use its first host.
	Host string

	// Remove is a list of KMS server node IDs that are removed
	// from the cluster definition of the KMS server that receives
	// the request.
	Remove []int
}

// MarshalPB converts the EditClusterRequest into its protobuf representation.
func (r *EditClusterRequest) MarshalPB(v *pb.EditClusterRequest) error {
	v.RemoveIDs = make([]uint32, 0, len(r.Remove))
	for _, id := range r.Remove {
		v.RemoveIDs = append(v.RemoveIDs, uint32(id))
	}
	return nil
}

// UnmarshalPB initializes the EditClusterRequest from its protobuf representation.
func (r *EditClusterRequest) UnmarshalPB(v *pb.EditClusterRequest) error {
	r.Remove = make([]int, 0, len(v.RemoveIDs))
	for _, id := range v.RemoveIDs {
		r.Remove = append(r.Remove, int(id))
	}
	return nil
}

// BackupDBRequest contains options for requesting a database backup from
// a KMS server.
type BackupDBRequest struct{}

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

	// Type of the key that is created. For example, AES256.
	// If not set, the server will pick a key type.
	Type SecretKeyType

	// AddVersion indicates whether a new key version is created.
	// By default, trying to create a key that already exists fails.
	// If AddVersion is true, a new key version is created.
	//
	// Adding versions to an existing key is often referred to as
	// key rotation.
	AddVersion bool
}

// MarshalPB converts the CreateKeyRequest into its protobuf representation.
func (r *CreateKeyRequest) MarshalPB(v *pb.CreateKeyRequest) error {
	if r.Type == 0 {
		v.Type = nil
	} else {
		v.Type = new(string)
		*v.Type = r.Type.String()
	}

	v.AddVersion = r.AddVersion
	return nil
}

// UnmarshalPB initializes the CreateKeyRequest from its protobuf representation.
func (r *CreateKeyRequest) UnmarshalPB(v *pb.CreateKeyRequest) error {
	var t SecretKeyType
	if v.Type != nil {
		var err error
		t, err = secretKeyTypeFromString(v.GetType())
		if err != nil {
			return err
		}
	}

	r.Type = t
	r.AddVersion = v.AddVersion
	return nil
}

// DeleteKeyRequest contains options for deleting secret keys.
//
// For removing just a single key version from a key refer to
// Client.RemoveKeyVersion and RemoveKeyVersionRequest.
type DeleteKeyRequest struct {
	// Enclave is the KMS enclave containing the master key.
	Enclave string

	// Name is the name of the key to delete.
	Name string

	// Version is the key version to remove. If <= 0, refers
	// to latest key version currently present. Once a key
	// version has been removed it cannot be added again.
	Version int

	// AllVersions indicates whether all key versions should be removed.
	// If true, Version must be 0.
	AllVersions bool
}

// MarshalPB converts the DeleteKeyRequest into its protobuf representation.
func (r *DeleteKeyRequest) MarshalPB(v *pb.DeleteKeyRequest) error {
	switch {
	case r.AllVersions && r.Version != 0:
		return errors.New("kms: invalid DeleteKeyRequest: all versions and non-zero version are incompatible")
	case r.Version < 0:
		v.Version = 0
	default:
		v.Version = uint32(r.Version)
	}
	v.AllVersions = r.AllVersions
	return nil
}

// UnmarshalPB initializes the DeleteKeyRequest from its protobuf representation.
func (r *DeleteKeyRequest) UnmarshalPB(v *pb.DeleteKeyRequest) error {
	if v.AllVersions && v.Version > 0 {
		return errors.New("kms: invalid DeleteKeyRequest: all versions and non-zero version are incompatible")
	}

	r.Version = int(v.Version)
	r.AllVersions = v.AllVersions
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

// CreatePolicyRequest contains options for creating policies.
type CreatePolicyRequest struct {
	// Enclave is the KMS enclave in which the policy is created.
	Enclave string

	// Name is the name of the policy that is created.
	Name string

	// Allow is a set of allow rules.
	Allow map[string]Rule

	// Deny is a set of deny rules.
	Deny map[string]Rule
}

// MarshalPB converts the CreatePolicyRequest into its protobuf representation.
func (r *CreatePolicyRequest) MarshalPB(v *pb.CreatePolicyRequest) error {
	v.Allow = make(map[string]string, len(r.Allow))
	for path, rule := range r.Allow {
		v.Allow[path] = rule.String()
	}

	v.Deny = make(map[string]string, len(r.Deny))
	for path, rule := range r.Deny {
		v.Deny[path] = rule.String()
	}
	return nil
}

// UnmarshalPB initializes the CreatePolicyRequest from its protobuf representation.
func (r *CreatePolicyRequest) UnmarshalPB(v *pb.CreatePolicyRequest) error {
	r.Allow = make(map[string]Rule, len(v.Allow))
	for path := range v.Allow {
		r.Allow[path] = Rule{}
	}

	r.Deny = make(map[string]Rule, len(v.Deny))
	for path := range v.Deny {
		r.Deny[path] = Rule{}
	}
	return nil
}

// AssignPolicyRequest contains options for assigning a policy to an identity.
type AssignPolicyRequest struct {
	// Enclave is the KMS enclave containing the policy and identity.
	Enclave string

	// Policy is the name of the policy that gets assigned to the identity.
	Policy string

	// Identity is the identity to which the policy should apply.
	Identity Identity
}

// MarshalPB converts the AssignPolicyRequest into its protobuf representation.
func (r *AssignPolicyRequest) MarshalPB(v *pb.AssignPolicyRequest) error {
	if r.Identity == "" {
		return errors.New("kms: identity is empty")
	}

	v.Identity = r.Identity.String()
	return nil
}

// UnmarshalPB initializes the AssignPolicyRequest from its protobuf representation.
func (r *AssignPolicyRequest) UnmarshalPB(v *pb.AssignPolicyRequest) error {
	if v.Identity == "" {
		return errors.New("kms: identity is empty")
	}

	r.Identity = Identity(v.Identity)
	return nil
}

// PolicyRequest contains options for fetching a policy and
// policy metadata.
type PolicyRequest struct {
	// Enclave is the KMS enclave containing the policy.
	Enclave string

	// Name is the name of the policy.
	Name string
}

// DeletePolicyRequest contains options for deleting a policy.
type DeletePolicyRequest struct {
	// Enclave is the KMS enclave containing the policy.
	Enclave string

	// Name is the name of the policy that is deleted.
	Name string
}

// CreateIdentityRequest contains options for creating new identities.
type CreateIdentityRequest struct {
	// Enclave is the KMS enclave in which the identity is created.
	Enclave string

	// Identity is the identity that is created.
	Identity Identity

	// Privilege is the identity's privilege. If empty, defaults to User.
	Privilege Privilege

	// IsServiceAccount indicates whether this identity is a service
	// account.
	IsServiceAccount bool
}

// MarshalPB converts the CreateIdentityequest into its protobuf representation.
func (r *CreateIdentityRequest) MarshalPB(v *pb.CreateIdentityRequest) error {
	var privilege string
	if r.Privilege != 0 {
		privilege = r.Privilege.String()
	}

	v.Privilege = privilege
	v.IsServiceAccount = r.IsServiceAccount
	return nil
}

// UnmarshalPB initializes the CreateIdentityRequest from its protobuf representation.
func (r *CreateIdentityRequest) UnmarshalPB(v *pb.CreateIdentityRequest) error {
	var privilege Privilege
	if v.Privilege != "" {
		var err error
		if privilege, err = ParsePrivilege(v.Privilege); err != nil {
			return err
		}
	}

	r.Privilege = privilege
	r.IsServiceAccount = v.IsServiceAccount
	return nil
}

// IdentityRequest contains options for fetching identity metadata.
type IdentityRequest struct {
	// Enclave is the KMS enclave containing the identity.
	Enclave string

	// Identity is the identity.
	Identity Identity
}

// DeleteIdentityRequest contains options for deleting an identity.
type DeleteIdentityRequest struct {
	// Enclave is the KMS enclave containing the identity.
	Enclave string

	// Identity is the identity that is deleted.
	Identity Identity
}
