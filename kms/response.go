// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kms

import (
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/minio/kms-go/kms/cmds"
	"github.com/minio/kms-go/kms/internal/headers"
	pb "github.com/minio/kms-go/kms/protobuf"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func decodeResponse[M any, P pb.Pointer[M], T pb.Unmarshaler[P]](r *http.Response, c cmds.Command, v T) error {
	if r.ContentLength < 0 {
		return &HostError{
			Host: r.Request.Host,
			Err:  Error{http.StatusLengthRequired, "request content length is negative"},
		}
	}

	buf := make([]byte, r.ContentLength)
	if _, err := io.ReadFull(r.Body, buf); err != nil {
		return hostError(r.Request.Host, err)
	}

	b, err := cmds.Decode[M, P, T](buf, c, v)
	if err != nil {
		return hostError(r.Request.Host, err)
	}
	if len(b) != 0 {
		return &HostError{
			Host: r.Request.Host,
			Err:  errors.New("kms: response body contains additional data"),
		}
	}
	return nil
}

func decodeResponseMessage(r *http.Response, c cmds.Command, v proto.Message) error {
	if r.ContentLength < 0 {
		return &HostError{
			Host: r.Request.Host,
			Err:  Error{http.StatusLengthRequired, "request content length is negative"},
		}
	}

	buf := make([]byte, r.ContentLength)
	if _, err := io.ReadFull(r.Body, buf); err != nil {
		return hostError(r.Request.Host, err)
	}

	b, err := cmds.DecodePB(buf, c, v)
	if err != nil {
		return hostError(r.Request.Host, err)
	}
	if len(b) != 0 {
		return &HostError{
			Host: r.Request.Host,
			Err:  errors.New("kms: response body contains additional data"),
		}
	}
	return nil
}

// readResponse reads the response body into v using the
// response content encoding.
//
// readBesponse assumes that the response body is limited
// to a reasonable size. It returns an error if it cannot
// determine the response content length before decoding.
func readResponse[M any, P pb.Pointer[M], T pb.Unmarshaler[P]](r *http.Response, v T) error {
	var m M
	var p P = &m
	if err := readProtoResponse(r, p); err != nil {
		return err
	}
	return v.UnmarshalPB(p)
}

// readResponse reads the response body into v using the
// response content encoding.
//
// readBesponse assumes that the response body is limited
// to a reasonable size. It returns an error if it cannot
// determine the response content length before decoding.
func readProtoResponse(r *http.Response, v proto.Message) error {
	if r.ContentLength < 0 {
		return Error{http.StatusLengthRequired, "request content length is negative"}
	}
	// TODO(aead): consider limiting body to a max. content length

	buf := make([]byte, r.ContentLength)
	if _, err := io.ReadFull(r.Body, buf); err != nil {
		return err
	}

	if r.Header.Get(headers.ContentType) == headers.ContentTypeBinary {
		return proto.Unmarshal(buf, v)
	}
	return protojson.Unmarshal(buf, v)
}

// A Page contains the next items of type T from a paginated listing.
// It's ContinueAt pointer refers to the next page, if any.
type Page[T any] struct {
	Items []T // The next items from the listing.

	// ContinueAt refers to the first item on the next
	// page from where to resume the listing. Empty at
	// the end of the listing.
	ContinueAt string
}

// VersionResponse contains version information about a KMS server.
type VersionResponse struct {
	// Version is the version of the KMS server. It's the timestamp of
	// the latest commit formatted as 'yyyy-mm-ddThh-mm-ssZ'. For example,
	// "2023-12-01T16-06-52Z"
	Version string

	// Commit is the commit ID of the most latest code change of the KMS
	// server.
	Commit string

	// APIVersion is the API version supported by the KMS server.
	// For example, "v1".
	APIVersion string

	// Host is the KMS server endpoint as 'host' or 'host:port'.
	Host string
}

// MarshalPB converts the VersionResponse into its protobuf representation.
func (r *VersionResponse) MarshalPB(v *pb.VersionResponse) error {
	v.Version = r.Version
	v.Commit = r.Commit
	v.APIVersion = r.APIVersion
	v.Host = r.Host
	return nil
}

// UnmarshalPB initializes the VersionResponse from its protobuf representation.
func (r *VersionResponse) UnmarshalPB(v *pb.VersionResponse) error {
	r.Version = v.Version
	r.Commit = v.Commit
	r.APIVersion = v.APIVersion
	r.Host = v.Host
	return nil
}

// ServerStatusResponse contains status information about a single
// KMS server.
type ServerStatusResponse struct {
	// Version is the version of the KMS server. It's the timestamp of
	// the latest commit formatted as 'yyyy-mm-ddThh-mm-ssZ'. For example,
	// "2023-12-01T16-06-52Z"
	Version string

	// APIVersion is the API version supported by the KMS server.
	// For example, "v1".
	APIVersion string

	// Host is the KMS server endpoint as 'host' or 'host:port'.
	Host string

	// UpTime is the amount of time the KMS server is up and running.
	UpTime time.Duration

	// Role is the current role the KMS server node has within the cluster.
	// Either, "Leader", "Follower" or "Candidate".
	Role string

	// Commit is the number of state changes applied to this KMS server.
	Commit uint64

	// Nodes is a list of KMS server nodes within the KMS cluster as a map
	// of node IDs to KMS server addresses of the form 'host' or 'host:port'.
	Nodes map[int]string

	// ID is the node ID of this KMS server. It only changes if the node
	// joins a cluster.
	ID int

	// LeaderID is the ID of the current cluster leader or negative if
	// the cluster has no leader.
	LeaderID int

	// LastHeartbeat is the duration since the KMS server has sent or received
	// a heartbeat. As long as there is a cluster leader, it should be lower
	// than the ElectionTimeout.
	LastHeartbeat time.Duration

	// HeartbeatInterval defines the frequency in which this KMS server, as cluster
	// leader, sends heartbeats to its follower nodes. All nodes within a cluster
	// should use the same heartbeat interval.
	HeartbeatInterval time.Duration

	// ElectionTimeout defines how long a KMS server node waits for heartbeats before
	// it considers the cluster leaders as down and starts a leader election to become
	// the cluster leader itself.
	//
	// Each cluster node should have a slightly different election timeout to avoid
	// spliting votes. Typically, base election timeout + random jitter. The average
	// or base election timeout of all cluster nodes should be balanced with the
	// HeartbeatInterval to prevent nodes from starting elections even though a leader
	// is present. A reasonable default may be:
	//
	//   ElectionTimeout = 3 * HeartbeatInterval.
	ElectionTimeout time.Duration

	// OS identifies the operating system the KMS server is running on.
	// For example, "linux" or "darwin".
	OS string

	// CPUArch is the CPU architecture of the KMS server. For example, "amd64".
	CPUArch string

	// CPUs is the number of logical CPUs that can execite the KMS server process.
	// However, the KMS server may not use all of these CPUs. It might be limited
	// to fewer CPUs.
	CPUs uint

	// UsableCPUs is the number of CPUs actually used by the KMS server process.
	// Unless the KMS server has been limited to fewer CPUs, equal to CPUs field.
	UsableCPUs uint

	// HeapMemInUse is the amount of heap memory currently occupied by the KMS server.
	// The total amount of memory used by the KMS server process is HeapMemInUse +
	// StackMemInUse.
	HeapMemInUse uint64

	// StackMemInUse is the amount of stack memory currently occupied by the KMS server.
	// The total amount of memory used by the KMS server process is HeapMemInUse +
	// StackMemInUse.
	StackMemInUse uint64
}

// MarshalPB converts the ServerStatusResponse into its protobuf representation.
func (s *ServerStatusResponse) MarshalPB(v *pb.ServerStatusResponse) error {
	v.Version = s.Version
	v.APIVersion = s.APIVersion
	v.Host = s.Host
	v.UpTime = pb.Duration(s.UpTime)
	v.Role = s.Role
	v.Commit = s.Commit
	v.Nodes = make(map[uint32]string, len(s.Nodes))
	for id, node := range s.Nodes {
		v.Nodes[uint32(id)] = node
	}
	v.ID = uint32(s.ID)
	v.LeaderID = int64(s.LeaderID)
	v.LastHeartbeat = pb.Duration(s.LastHeartbeat)
	v.HeartbeatInterval = pb.Duration(s.HeartbeatInterval)
	v.ElectionTimeout = pb.Duration(s.ElectionTimeout)
	v.OS = s.OS
	v.Arch = s.CPUArch
	v.CPUs = uint32(s.CPUs)
	v.UsableCPUs = uint32(s.UsableCPUs)
	v.HeapMemInUse = s.HeapMemInUse
	v.StackMemInUse = s.StackMemInUse
	return nil
}

// UnmarshalPB initializes the ServerStatusResponse from its protobuf representation.
func (s *ServerStatusResponse) UnmarshalPB(v *pb.ServerStatusResponse) error {
	s.Version = v.Version
	s.APIVersion = v.APIVersion
	s.Host = v.Host
	s.UpTime = v.UpTime.AsDuration()
	s.Role = v.Role
	s.Commit = v.Commit
	s.Nodes = make(map[int]string, len(v.Nodes))
	for id, node := range v.Nodes {
		s.Nodes[int(id)] = node
	}
	s.ID = int(v.ID)
	s.LeaderID = int(v.LeaderID)
	s.LastHeartbeat = v.LastHeartbeat.AsDuration()
	s.HeartbeatInterval = v.HeartbeatInterval.AsDuration()
	s.ElectionTimeout = v.ElectionTimeout.AsDuration()
	s.OS = v.OS
	s.CPUArch = v.Arch
	s.CPUs = uint(v.CPUs)
	s.UsableCPUs = uint(v.UsableCPUs)
	s.HeapMemInUse = v.HeapMemInUse
	s.StackMemInUse = v.StackMemInUse
	return nil
}

// ClusterStatusResponse contains status information about a KMS cluster.
//
// The overall view of the current cluster status, in particular
// which nodes are reachable, may vary from node to node in case
// of network partitions. For example, two nodes within two network
// partitions will consider themselves as up and their peer as down.
type ClusterStatusResponse struct {
	// NodesUp is a map of node IDs to the corresponding node status
	// information.
	NodesUp map[int]*ServerStatusResponse

	// NodesDown is a map of node IDs to node addresses containing
	// all nodes that were not reachable or failed to respond in time.
	NodesDown map[int]string
}

// MarshalPB converts the ClusterStatusResponse into its protobuf representation.
func (s *ClusterStatusResponse) MarshalPB(v *pb.ClusterStatusResponse) error {
	v.NodesUp = make(map[uint32]*pb.ServerStatusResponse, len(s.NodesUp))
	for id, resp := range s.NodesUp {
		stat := new(pb.ServerStatusResponse)
		if err := resp.MarshalPB(stat); err != nil {
			return err
		}
		v.NodesUp[uint32(id)] = stat
	}

	v.NodesDown = make(map[uint32]string, len(s.NodesDown))
	for id, addr := range s.NodesDown {
		v.NodesDown[uint32(id)] = addr
	}
	return nil
}

// UnmarshalPB initializes the ClusterStatusResponse from its protobuf representation.
func (s *ClusterStatusResponse) UnmarshalPB(v *pb.ClusterStatusResponse) error {
	s.NodesUp = make(map[int]*ServerStatusResponse, len(v.NodesUp))
	for id, resp := range v.NodesUp {
		stat := new(ServerStatusResponse)
		if err := stat.UnmarshalPB(resp); err != nil {
			return err
		}
		s.NodesUp[int(id)] = stat
	}

	s.NodesDown = make(map[int]string, len(v.NodesDown))
	for id, addr := range v.NodesDown {
		s.NodesDown[int(id)] = addr
	}
	return nil
}

// ReadDBResponse contains the database content received from a KMS server.
type ReadDBResponse struct {
	Body io.ReadCloser // The database content
}

// Read reads data from the response body into b.
func (r *ReadDBResponse) Read(b []byte) (int, error) {
	n, err := r.Body.Read(b)
	if errors.Is(err, io.EOF) {
		r.Body.Close()
	}
	return n, err
}

// Close closes the underlying response body.
func (r *ReadDBResponse) Close() error {
	return r.Body.Close()
}

// gzipReadCloser wraps a gzip.Reader. It's Close method
// closes the underlying HTTP response body and the gzip
// reader.
type gzipReadCloser struct {
	gzip   *gzip.Reader
	closer io.Closer
}

func (r gzipReadCloser) Read(b []byte) (int, error) { return r.gzip.Read(b) }

func (r gzipReadCloser) Close() error {
	err := r.closer.Close()
	if gzipErr := r.gzip.Close(); err == nil {
		return gzipErr
	}
	return err
}

// EnclaveStatusResponse contains information about an enclave.
type EnclaveStatusResponse struct {
	// Name is the name of the enclave.
	Name string

	// CreatedAt is the point in time when the enclave has been created.
	CreatedAt time.Time

	// CreatedBy is the identity that created the enclave.
	CreatedBy Identity
}

// MarshalPB converts the EnclaveStatusResponse into its protobuf representation.
func (r *EnclaveStatusResponse) MarshalPB(v *pb.EnclaveStatusResponse) error {
	v.Name = r.Name
	v.CreatedAt = pb.Time(r.CreatedAt)
	v.CreatedBy = r.CreatedBy.String()
	return nil
}

// UnmarshalPB initializes the EnclaveStatusResponse from its protobuf representation.
func (r *EnclaveStatusResponse) UnmarshalPB(v *pb.EnclaveStatusResponse) error {
	r.Name = v.Name
	r.CreatedAt = v.CreatedAt.AsTime()
	r.CreatedBy = Identity(v.CreatedBy)
	return nil
}

// KeyStatusResponse contains information about a secret key version.
type KeyStatusResponse struct {
	// Name is the name of the secret key ring.
	Name string

	// Version is the verion of this key identifying it within the key ring.
	Version int

	// Type is the type of the secret key. For example, AES256.
	Type SecretKeyType

	// CreatedAt is the point in time when this key version has been created.
	CreatedAt time.Time

	// CreatedBy is the identity that created this key version.
	CreatedBy Identity
}

// MarshalPB converts the KeyStatusResponse into its protobuf representation.
func (r *KeyStatusResponse) MarshalPB(v *pb.KeyStatusResponse) error {
	v.Name = r.Name
	v.Version = uint32(r.Version)
	v.Type = r.Type.String()
	v.CreatedAt = pb.Time(r.CreatedAt)
	v.CreatedBy = r.CreatedBy.String()
	return nil
}

// UnmarshalPB initializes the KeyStatusResponse from its protobuf representation.
func (r *KeyStatusResponse) UnmarshalPB(v *pb.KeyStatusResponse) error {
	t, err := ParseSecretKeyType(v.Type)
	if err != nil {
		return err
	}

	r.Name = v.Name
	r.Type = t
	r.Version = int(v.Version)
	r.CreatedAt = v.CreatedAt.AsTime()
	r.CreatedBy = Identity(v.CreatedBy)
	return nil
}

// EncryptResponse contains the ciphertext of an encrypted message
// and the key version used to encrypt the message.
type EncryptResponse struct {
	// Version identifies the particular key within a key ring used to encrypt
	// the message.
	Version int

	// Ciphertext is the encrypted message.
	Ciphertext []byte
}

// MarshalPB converts the EncryptResponse into its protobuf representation.
func (r *EncryptResponse) MarshalPB(v *pb.EncryptResponse) error {
	v.Version = uint32(r.Version)
	v.Ciphertext = r.Ciphertext
	return nil
}

// UnmarshalPB initializes the EncryptResponse from its protobuf representation.
func (r *EncryptResponse) UnmarshalPB(v *pb.EncryptResponse) error {
	r.Version = int(v.Version)
	r.Ciphertext = v.Ciphertext
	return nil
}

// DecryptResponse contains the decrypted plaintext message.
type DecryptResponse struct {
	// Plaintext is the decrypted message.
	Plaintext []byte
}

// MarshalPB converts the DecryptResponse into its protobuf representation.
func (r *DecryptResponse) MarshalPB(v *pb.DecryptResponse) error {
	v.Plaintext = r.Plaintext
	return nil
}

// UnmarshalPB initializes the DecryptResponse from its protobuf representation.
func (r *DecryptResponse) UnmarshalPB(v *pb.DecryptResponse) error {
	r.Plaintext = v.Plaintext
	return nil
}

// GenerateKeyResponse contains data encryption key that consists of a plaintext
// data encryption key and an encrypted ciphertext. Applications should use, but
// never store, the plaintext data encryption key for crypto. operations and store
// the ciphertext and key version.
type GenerateKeyResponse struct {
	// Version identifies the particular key within a key ring used to generate
	// and encrypt this data encryption key.
	Version int

	// Plaintext is the plain data encryption key. It may be used by applications
	// to perform crypto. operations.
	Plaintext []byte

	// Ciphertext is the encrypted data encryption key. Applications should store
	// it to obtain the plain data encryption key in the future again.
	Ciphertext []byte
}

// MarshalPB converts the GenerateKeyResponse into its protobuf representation.
func (r *GenerateKeyResponse) MarshalPB(v *pb.GenerateKeyResponse) error {
	v.Version = uint32(r.Version)
	v.Plaintext = r.Plaintext
	v.Ciphertext = r.Ciphertext
	return nil
}

// UnmarshalPB initializes the GenerateKeyResponse from its protobuf representation.
func (r *GenerateKeyResponse) UnmarshalPB(v *pb.GenerateKeyResponse) error {
	r.Version = int(v.Version)
	r.Plaintext = v.Plaintext
	r.Ciphertext = v.Ciphertext
	return nil
}

// PolicyStatusResponse contains information about a policy.
type PolicyStatusResponse struct {
	// Name is the name of the policy.
	Name string

	// CreatedAt is the point in time when the policy has been created.
	CreatedAt time.Time

	// CreatedBy is the identity that created the policy.
	CreatedBy Identity
}

// MarshalPB converts the PolicyStatusResponse into its protobuf representation.
func (r *PolicyStatusResponse) MarshalPB(v *pb.PolicyStatusResponse) error {
	v.Name = r.Name
	v.CreatedAt = pb.Time(r.CreatedAt)
	v.CreatedBy = r.CreatedBy.String()
	return nil
}

// UnmarshalPB initializes the PolicyStatusResponse from its protobuf representation.
func (r *PolicyStatusResponse) UnmarshalPB(v *pb.PolicyStatusResponse) error {
	r.Name = v.Name
	r.CreatedAt = v.CreatedAt.AsTime()
	r.CreatedBy = Identity(v.CreatedBy)
	return nil
}

// PolicyResponse contains information about a policy and the policy definition.
type PolicyResponse struct {
	// Name is the name of the policy.
	Name string

	// Allow is the set of allow rules.
	Allow map[cmds.Command]RuleSet

	// Deny is the set of deny rules.
	Deny map[cmds.Command]RuleSet

	// CreatedAt is the point in time when the policy has been created.
	CreatedAt time.Time

	// CreatedBy is the identity that created the policy.
	CreatedBy Identity
}

// MarshalPB converts the PolicyResponse into its protobuf representation.
func (r *PolicyResponse) MarshalPB(v *pb.PolicyResponse) error {
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

	v.CreatedAt = pb.Time(r.CreatedAt)
	v.CreatedBy = r.CreatedBy.String()
	return nil
}

// UnmarshalPB initializes the PolicyResponse from its protobuf representation.
func (r *PolicyResponse) UnmarshalPB(v *pb.PolicyResponse) error {
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

	r.CreatedAt = v.CreatedAt.AsTime()
	r.CreatedBy = Identity(v.CreatedBy)
	return nil
}

// IdentityResponse contains information about an identity.
type IdentityResponse struct {
	// Identity is the identity referring to a private/public key pair.
	Identity Identity

	// Privilege is the identity's privilege.
	Privilege Privilege

	// Policy is the name of the assigned policy, if any. It is empty
	// if the identity's privilege is Admin or SysAdmin.
	Policy string

	// CreatedAt is the point in time when this identity was created.
	CreatedAt time.Time

	// CreatedBy is the identity that created this identity.
	CreatedBy Identity

	// IsServiceAccount indicates whether this identity is a service
	// account. By default, service accounts inherit the permissions
	// of their parent identity. Service accounts are removed
	// automatically when their parent identity is deleted.
	IsServiceAccount bool

	// ServiceAccounts contains all service accounts of this identity.
	ServiceAccounts []Identity
}

// MarshalPB converts the IdentityResponse into its protobuf representation.
func (r *IdentityResponse) MarshalPB(v *pb.IdentityResponse) error {
	v.Identity = r.Identity.String()
	v.Privilege = uint32(r.Privilege)
	v.Policy = r.Policy
	v.CreatedAt = pb.Time(r.CreatedAt)
	v.CreatedBy = r.CreatedBy.String()
	v.IsServiceAccount = r.IsServiceAccount
	v.ServiceAccounts = make([]string, 0, len(r.ServiceAccounts))
	for _, a := range r.ServiceAccounts {
		v.ServiceAccounts = append(v.ServiceAccounts, a.String())
	}
	return nil
}

// UnmarshalPB initializes the IdentityResponse from its protobuf representation.
func (r *IdentityResponse) UnmarshalPB(v *pb.IdentityResponse) error {
	r.Identity = Identity(v.Identity)
	r.Privilege = Privilege(v.Privilege)
	r.Policy = v.Policy
	r.CreatedAt = v.CreatedAt.AsTime()
	r.CreatedBy = Identity(v.CreatedBy)
	r.IsServiceAccount = v.IsServiceAccount
	r.ServiceAccounts = make([]Identity, 0, len(v.ServiceAccounts))
	for _, a := range v.ServiceAccounts {
		r.ServiceAccounts = append(r.ServiceAccounts, Identity(a))
	}
	return nil
}
