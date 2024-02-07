// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kms

import (
	"errors"

	"github.com/minio/kms-go/kms/cmds"
	pb "github.com/minio/kms-go/kms/protobuf"
)

// Request is a structure describing a KMS request.
type Request struct {
	// Host is the DNS hostname or IP address of the
	// KMS server. If empty, the Client will pick one
	// of its KMS servers and perform client-side
	// load balancing. Providing a host explicitly
	// circumvents the client load balancer. This
	// may be desirable when trying to communicate
	// with one particular KMS server.
	//
	// Host may start with the HTTPS URI scheme "https://"
	// and can contain an optional port number.
	Host string

	// Enclave is the KMS enclave in which all KMS
	// commands specified in the request body are
	// executed.
	//
	// For KMS cluster commands, like fetching cluster
	// status information, that don't operate within
	// any enclave, Enclave is empty.
	Enclave string

	// Body is the request body. It contains one or
	// multiple encoded commands to be executed by
	// the KMS.
	Body []byte
}

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

// MarshalPB converts the ListRequest into its protobuf representation.
func (r *ListRequest) MarshalPB(v *pb.ListRequest) error {
	v.Prefix = r.Prefix
	v.ContinueAt = r.ContinueAt
	v.Limit = uint32(max(r.Limit, 0))
	return nil
}

// UnmarshalPB initializes the ListRequest from its protobuf representation.
func (r *ListRequest) UnmarshalPB(v *pb.ListRequest) error {
	r.Prefix = v.Prefix
	r.ContinueAt = v.ContinueAt
	r.Limit = int(v.Limit)
	return nil
}

// VersionRequest contains options for fetching version
// information for one or multiple KMS servers.
type VersionRequest struct {
	// List of endpoints from which version information
	// is requested. If empty, the client requests version
	// information from all known endpoints.
	Hosts []string
}

// LivenessRequest contains options for checking whether
// one or multiple KMS servers are alive.
type LivenessRequest struct {
	// List of endpoints for which the liveness state is
	// checked. If empty, the client checks the liveness
	// state on all known endpoints.
	Hosts []string
}

// ReadinessRequest contains options for checking whether
// one or multiple KMS servers are ready to serve requests.
type ReadinessRequest struct {
	// List of endpoints for which the readiness state is
	// checked. If empty, the client checks the readiness
	// state on all known endpoints.
	Hosts []string

	// Write, if true, checks whether the servers are
	// ready to serve "write" requests that change the
	// KMS state.
	Write bool
}

// ServerStatusRequest contains options for fetching status
// information for one particular KMS server.
type ServerStatusRequest struct {
	// List of endpoints from which status information
	// is requested. If empty, the client requests status
	// information from all known endpoints.
	Hosts []string
}

// ClusterStatusRequest contains options for fetching KMS cluster
// status information.
type ClusterStatusRequest struct{}

// MarshalPB converts the ClusterStatusRequest into its protobuf representation.
func (r *ClusterStatusRequest) MarshalPB(*pb.ClusterStatusRequest) error { return nil }

// UnmarshalPB initializes the ClusterStatusRequest from its protobuf representation.
func (r *ClusterStatusRequest) UnmarshalPB(*pb.ClusterStatusRequest) error { return nil }

// AddClusterNodeRequest describes which KMS server to add to an existing.
type AddClusterNodeRequest struct {
	// Host is the KMS server that should join a cluster.
	// It must be of the form "host" or "host:port".
	Host string
}

// MarshalPB converts the AddClusterNodeRequest into its protobuf representation.
func (r *AddClusterNodeRequest) MarshalPB(v *pb.AddClusterNodeRequest) error {
	v.Host = r.Host
	return nil
}

// UnmarshalPB initializes the AddClusterNodeRequest from its protobuf representation.
func (r *AddClusterNodeRequest) UnmarshalPB(v *pb.AddClusterNodeRequest) error {
	r.Host = v.Host
	return nil
}

// RemoveClusterNodeRequest describes which server to remove from a KMS
// cluster.
type RemoveClusterNodeRequest struct {
	// Host is the KMS server that should leave a cluster.
	// It must be of the form "host" or "host:port".
	Host string
}

// MarshalPB converts the RemoveClusterNodeRequest into its protobuf representation.
func (r *RemoveClusterNodeRequest) MarshalPB(v *pb.RemoveClusterNodeRequest) error {
	v.Host = r.Host
	return nil
}

// UnmarshalPB initializes the RemoveClusterNodeRequest from its protobuf representation.
func (r *RemoveClusterNodeRequest) UnmarshalPB(v *pb.RemoveClusterNodeRequest) error {
	r.Host = v.Host
	return nil
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
	v.Host = r.Host
	v.RemoveIDs = make([]uint32, 0, len(r.Remove))
	for _, id := range r.Remove {
		v.RemoveIDs = append(v.RemoveIDs, uint32(id))
	}
	return nil
}

// UnmarshalPB initializes the EditClusterRequest from its protobuf representation.
func (r *EditClusterRequest) UnmarshalPB(v *pb.EditClusterRequest) error {
	r.Host = v.Host
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

// MarshalPB converts the CreateEnclaveRequest into its protobuf representation.
func (r *CreateEnclaveRequest) MarshalPB(v *pb.CreateEnclaveRequest) error {
	v.Name = r.Name
	return nil
}

// UnmarshalPB initializes the CreateEnclaveRequest from its protobuf representation.
func (r *CreateEnclaveRequest) UnmarshalPB(v *pb.CreateEnclaveRequest) error {
	r.Name = v.Name
	return nil
}

// EnclaveStatusRequest contains options for fetching metadata
// about an enclave.
type EnclaveStatusRequest struct {
	// Name is the name of the enclave to delete.
	Name string
}

// MarshalPB converts the EnclaveStatusRequest into its protobuf representation.
func (r *EnclaveStatusRequest) MarshalPB(v *pb.CreateEnclaveRequest) error {
	v.Name = r.Name
	return nil
}

// UnmarshalPB initializes the EnclaveStatusRequest from its protobuf representation.
func (r *EnclaveStatusRequest) UnmarshalPB(v *pb.EnclaveStatusRequest) error {
	r.Name = v.Name
	return nil
}

// DeleteEnclaveRequest contains options for deleting enclaves.
type DeleteEnclaveRequest struct {
	// Name is the name of the enclave to delete.
	Name string
}

// MarshalPB converts the DeleteEnclaveRequest into its protobuf representation.
func (r *DeleteEnclaveRequest) MarshalPB(v *pb.DeleteEnclaveRequest) error {
	v.Name = r.Name
	return nil
}

// UnmarshalPB initializes the EnclaveStatusRequest from its protobuf representation.
func (r *DeleteEnclaveRequest) UnmarshalPB(v *pb.DeleteEnclaveRequest) error {
	r.Name = v.Name
	return nil
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
	if r.Type != 0 {
		v.Type = r.Type.String()
	} else {
		v.Type = ""
	}

	v.Name = r.Name
	v.AddVersion = r.AddVersion
	return nil
}

// UnmarshalPB initializes the CreateKeyRequest from its protobuf representation.
func (r *CreateKeyRequest) UnmarshalPB(v *pb.CreateKeyRequest) error {
	var t SecretKeyType
	if v.Type != "" {
		var err error
		t, err = ParseSecretKeyType(v.GetType())
		if err != nil {
			return err
		}
	}

	r.Name = v.Name
	r.Type = t
	r.AddVersion = v.AddVersion
	return nil
}

// ImportKeyRequest contains options for importing secret keys.
type ImportKeyRequest struct {
	// Enclave is the KMS enclave in which the key is created.
	Enclave string

	// Name is the name of the key to create.
	Name string

	// Type of the key that is created. For example, AES256.
	// If not set, the server will pick a key type.
	Type SecretKeyType

	// Key is the secret key imported into the KMS server.
	// It must be a valid key for the given key type.
	Key []byte
}

// MarshalPB converts the ImportKeyRequest into its protobuf representation.
func (r *ImportKeyRequest) MarshalPB(v *pb.ImportKeyRequest) error {
	if r.Type != 0 {
		v.Type = r.Type.String()
	} else {
		v.Type = ""
	}

	v.Name = r.Name
	v.Key = r.Key
	return nil
}

// UnmarshalPB initializes the ImportKeyRequest from its protobuf representation.
func (r *ImportKeyRequest) UnmarshalPB(v *pb.ImportKeyRequest) error {
	var t SecretKeyType
	if v.Type != "" {
		var err error
		t, err = ParseSecretKeyType(v.GetType())
		if err != nil {
			return err
		}
	}

	r.Name = v.Name
	r.Type = t
	r.Key = v.Key
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
	if r.AllVersions && r.Version > 0 {
		return errors.New("kms: invalid DeleteKeyRequest: all versions and non-zero version are incompatible")
	}

	v.Name = r.Name
	v.Version = uint32(max(r.Version, 0))
	v.AllVersions = r.AllVersions
	return nil
}

// UnmarshalPB initializes the DeleteKeyRequest from its protobuf representation.
func (r *DeleteKeyRequest) UnmarshalPB(v *pb.DeleteKeyRequest) error {
	if v.AllVersions && v.Version > 0 {
		return errors.New("kms: invalid DeleteKeyRequest: all versions and non-zero version are incompatible")
	}

	r.Name = v.Name
	r.Version = int(v.Version)
	r.AllVersions = v.AllVersions
	return nil
}

// KeyStatusRequest contains options for fetching
// metadata about a key version.
type KeyStatusRequest struct {
	// Enclave is the KMS enclave containing the master key.
	Enclave string

	// Name is the name of the master key.
	Name string

	// Version is the key version. If <= 0, refers to
	// latest key version currently present.
	Version int
}

// MarshalPB converts the KeyStatusRequest into its protobuf representation.
func (r *KeyStatusRequest) MarshalPB(v *pb.KeyStatusRequest) error {
	v.Name = r.Name
	v.Version = uint32(max(r.Version, 0))
	return nil
}

// UnmarshalPB initializes the KeyStatusRequest from its protobuf representation.
func (r *KeyStatusRequest) UnmarshalPB(v *pb.KeyStatusRequest) error {
	r.Name = v.Name
	r.Version = int(v.Version)
	return nil
}

// EncryptRequest contains a plaintext message that should be encrypted and
// associated data that is crypto. bound to the resulting ciphertext.
type EncryptRequest struct {
	// Enclave is the KMS enclave containing the master key.
	Enclave string

	// Name is the name of the master key.
	Name string

	// Version is the key version used for encryption.
	// If <= 0, refers to latest key version currently
	// present.
	Version int

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
	v.Name = r.Name
	v.Version = uint32(max(r.Version, 0))
	v.Plaintext = r.Plaintext
	v.AssociatedData = r.AssociatedData
	return nil
}

// UnmarshalPB initializes the EncryptRequest from its protobuf representation.
func (r *EncryptRequest) UnmarshalPB(v *pb.EncryptRequest) error {
	r.Name = v.Name
	r.Version = int(v.Version)
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

	Version int

	// AssociatedData is additional data that is not encrypted but crypto. bound
	// to the ciphertext of the data encryption key. The same associated data must
	// be provided when decrypting the ciphertext.
	//
	// Associated data should describe the context within the data encryption key
	// is used. For example, the name of the file that gets encrypted with the
	// data encryption key.
	AssociatedData []byte

	// Length is an optional length of the generated plaintext data encryption key
	// in bytes. At most 1024 (8192 bits). If <= 0, defaults to 32 (256 bits).
	Length int
}

// MarshalPB converts the GenerateKeyRequest into its protobuf representation.
func (r *GenerateKeyRequest) MarshalPB(v *pb.GenerateKeyRequest) error {
	v.Name = r.Name
	v.Version = uint32(max(r.Version, 0))
	v.AssociatedData = r.AssociatedData
	v.Length = uint32(max(r.Length, 0))
	return nil
}

// UnmarshalPB initializes the GenerateKeyRequest from its protobuf representation.
func (r *GenerateKeyRequest) UnmarshalPB(v *pb.GenerateKeyRequest) error {
	r.Name = v.Name
	r.Version = int(v.Version)
	r.AssociatedData = v.AssociatedData
	r.Length = int(v.Length)
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
	AssociatedData []byte
}

// MarshalPB converts the DecryptKeyRequest into its protobuf representation.
func (r *DecryptRequest) MarshalPB(v *pb.DecryptRequest) error {
	v.Name = r.Name
	v.Version = uint32(r.Version)
	v.Ciphertext = r.Ciphertext
	v.AssociatedData = r.AssociatedData
	return nil
}

// UnmarshalPB initializes the DecryptKeyRequest from its protobuf representation.
func (r *DecryptRequest) UnmarshalPB(v *pb.DecryptRequest) error {
	r.Name = v.Name
	r.Version = int(v.Version)
	r.Ciphertext = v.Ciphertext
	r.AssociatedData = v.AssociatedData
	return nil
}

// CreatePolicyRequest contains options for creating policies.
type CreatePolicyRequest struct {
	// Enclave is the KMS enclave in which the policy is created.
	Enclave string

	// Name is the name of the policy that is created.
	Name string

	// Allow is a set of allow rules.
	Allow map[cmds.Command]RuleSet

	// Deny is a set of deny rules.
	Deny map[cmds.Command]RuleSet
}

// MarshalPB converts the CreatePolicyRequest into its protobuf representation.
func (r *CreatePolicyRequest) MarshalPB(v *pb.CreatePolicyRequest) error {
	v.Name = r.Name

	v.Allow = make(map[string]*pb.RuleSet, len(r.Allow))
	for cmd, set := range r.Allow {
		rs := new(pb.RuleSet)
		if err := set.MarshalPB(rs); err != nil {
			return err
		}
		v.Allow[cmd.String()] = rs
	}

	v.Deny = make(map[string]*pb.RuleSet, len(r.Deny))
	for cmd, set := range r.Deny {
		rs := new(pb.RuleSet)
		if err := set.MarshalPB(rs); err != nil {
			return err
		}
		v.Deny[cmd.String()] = rs
	}
	return nil
}

// UnmarshalPB initializes the CreatePolicyRequest from its protobuf representation.
func (r *CreatePolicyRequest) UnmarshalPB(v *pb.CreatePolicyRequest) error {
	r.Name = v.Name

	r.Allow = make(map[cmds.Command]RuleSet, len(v.Allow))
	for cmd, set := range v.Allow {
		var c cmds.Command
		if err := c.UnmarshalText([]byte(cmd)); err != nil {
			return err
		}

		var rs RuleSet
		if err := rs.UnmarshalPB(set); err != nil {
			return err
		}
		r.Allow[c] = rs
	}

	r.Deny = make(map[cmds.Command]RuleSet, len(v.Deny))
	for cmd, set := range v.Deny {
		var c cmds.Command
		if err := c.UnmarshalText([]byte(cmd)); err != nil {
			return err
		}

		var rs RuleSet
		if err := rs.UnmarshalPB(set); err != nil {
			return err
		}
		r.Deny[c] = rs
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
	v.Policy = r.Policy
	return nil
}

// UnmarshalPB initializes the AssignPolicyRequest from its protobuf representation.
func (r *AssignPolicyRequest) UnmarshalPB(v *pb.AssignPolicyRequest) error {
	if v.Identity == "" {
		return errors.New("kms: identity is empty")
	}

	r.Identity = Identity(v.Identity)
	r.Policy = v.Policy
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

// MarshalPB converts the PolicyRequest into its protobuf representation.
func (r *PolicyRequest) MarshalPB(v *pb.PolicyRequest) error {
	v.Name = r.Name
	return nil
}

// UnmarshalPB initializes the PolicyRequest from its protobuf representation.
func (r *PolicyRequest) UnmarshalPB(v *pb.PolicyRequest) error {
	r.Name = v.Name
	return nil
}

// DeletePolicyRequest contains options for deleting a policy.
type DeletePolicyRequest struct {
	// Enclave is the KMS enclave containing the policy.
	Enclave string

	// Name is the name of the policy that is deleted.
	Name string
}

// MarshalPB converts the DeletePolicyRequest into its protobuf representation.
func (r *DeletePolicyRequest) MarshalPB(v *pb.DeletePolicyRequest) error {
	v.Name = r.Name
	return nil
}

// UnmarshalPB initializes the DeletePolicyRequest from its protobuf representation.
func (r *DeletePolicyRequest) UnmarshalPB(v *pb.DeletePolicyRequest) error {
	r.Name = v.Name
	return nil
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

	v.Identity = r.Identity.String()
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

	r.Identity = Identity(v.Identity)
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

// MarshalPB converts the IdentityRequest into its protobuf representation.
func (r *IdentityRequest) MarshalPB(v *pb.IdentityRequest) error {
	v.Identity = r.Identity.String()
	return nil
}

// UnmarshalPB initializes the IdentityRequest from its protobuf representation.
func (r *IdentityRequest) UnmarshalPB(v *pb.IdentityRequest) error {
	r.Identity = Identity(v.Identity)
	return nil
}

// DeleteIdentityRequest contains options for deleting an identity.
type DeleteIdentityRequest struct {
	// Enclave is the KMS enclave containing the identity.
	Enclave string

	// Identity is the identity that is deleted.
	Identity Identity
}

// MarshalPB converts the DeleteIdentityRequest into its protobuf representation.
func (r *DeleteIdentityRequest) MarshalPB(v *pb.DeleteIdentityRequest) error {
	v.Identity = r.Identity.String()
	return nil
}

// UnmarshalPB initializes the DeleteIdentityRequest from its protobuf representation.
func (r *DeleteIdentityRequest) UnmarshalPB(v *pb.DeleteIdentityRequest) error {
	r.Identity = Identity(v.Identity)
	return nil
}
