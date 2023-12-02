// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

// Generate the Go protobuf code by running the protobuf compiler
// from the repository root:
//
//   $ protoc -I=./kms/protobuf --go_out=. ./kms/protobuf/*.proto

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v4.25.1
// source: response.proto

package protobuf

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type ErrResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Message string `protobuf:"bytes,1,opt,name=Message,json=message,proto3" json:"Message,omitempty"`
}

func (x *ErrResponse) Reset() {
	*x = ErrResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_response_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ErrResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ErrResponse) ProtoMessage() {}

func (x *ErrResponse) ProtoReflect() protoreflect.Message {
	mi := &file_response_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ErrResponse.ProtoReflect.Descriptor instead.
func (*ErrResponse) Descriptor() ([]byte, []int) {
	return file_response_proto_rawDescGZIP(), []int{0}
}

func (x *ErrResponse) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

type NodeStatusResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Version is the version of the KMS server. It's the timestamp of
	// the latest commit formatted as 'yyyy-mm-ddThh-mm-ssZ'. For example,
	// "2023-12-01T16-06-52Z"
	Version string `protobuf:"bytes,1,opt,name=Version,json=version,proto3" json:"Version,omitempty"`
	// APIVersion is the API version supported by the KMS server.
	// For example, "v1".
	APIVersion string `protobuf:"bytes,2,opt,name=APIVersion,json=api_version,proto3" json:"APIVersion,omitempty"`
	// Addr is the KMS server address as 'host' or 'host:port'.
	Addr string `protobuf:"bytes,3,opt,name=Addr,json=address,proto3" json:"Addr,omitempty"`
	// Role is the current role the KMS server node has within the cluster.
	// Either, "Leader", "Follower" or "Candidate".
	Role string `protobuf:"bytes,4,opt,name=Role,json=role,proto3" json:"Role,omitempty"`
	// Commit is the number of state changes applied to this KMS server.
	Commit uint64 `protobuf:"varint,5,opt,name=Commit,json=commit,proto3" json:"Commit,omitempty"`
	// Nodes is a list of KMS server nodes within the KMS cluster as a map
	// of node IDs to KMS server addresses of the form 'host' or 'host:port'.
	Nodes map[uint32]string `protobuf:"bytes,6,rep,name=Nodes,json=nodes,proto3" json:"Nodes,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	// ID is the node ID of this KMS server. It only changes if the node
	// joins a cluster.
	ID uint32 `protobuf:"varint,7,opt,name=ID,json=node_id,proto3" json:"ID,omitempty"`
	// LeaderID is the ID of the current cluster leader or negative if
	// the cluster has no leader.
	LeaderID int64 `protobuf:"zigzag64,8,opt,name=LeaderID,json=leader_id,proto3" json:"LeaderID,omitempty"`
	// LastHeartbeat is the duration since the KMS server has sent or received
	// a heartbeat. As long as there is a cluster leader, it should be lower
	// than the ElectionTimeout.
	LastHeartbeat *durationpb.Duration `protobuf:"bytes,9,opt,name=LastHeartbeat,json=last_heartbeat,proto3" json:"LastHeartbeat,omitempty"`
	// HeartbeatInterval defines the frequency in which this KMS server, as cluster
	// leader, sends heartbeats to its follower nodes. All nodes within a cluster
	// should use the same heartbeat interval.
	HeartbeatInterval *durationpb.Duration `protobuf:"bytes,10,opt,name=HeartbeatInterval,json=heartbeat_interval,proto3" json:"HeartbeatInterval,omitempty"`
	// ElectionTimeout defines how long a KMS server node waits for heartbeats before
	// it considers the cluster leaders as down and starts a leader election to become
	// the cluster leader itself.
	// Each cluster node should have a slightly different election timeout to avoid
	// spliting votes. Typically, base election timeout + random jitter. The average
	// or base election timeout of all cluster nodes should be balanced with the
	// HeartbeatInterval to prevent nodes from starting elections even though a leader
	// is present. A reasonable default may be ElectionTimeout = 3 * HeartbeatInterval.
	ElectionTimeout *durationpb.Duration `protobuf:"bytes,11,opt,name=ElectionTimeout,json=election_timeout,proto3" json:"ElectionTimeout,omitempty"`
	// UpTime is the amount of time the KMS server is up and running.
	UpTime *durationpb.Duration `protobuf:"bytes,12,opt,name=UpTime,json=sys_uptime,proto3" json:"UpTime,omitempty"`
	// OS identifies the operating system the KMS server is running on.
	// For example, "linux" or "darwin".
	OS string `protobuf:"bytes,13,opt,name=OS,json=sys_os,proto3" json:"OS,omitempty"`
	// Arch is the CPU architecture of the KMS server. For example, "amd64".
	Arch string `protobuf:"bytes,14,opt,name=Arch,json=sys_cpu_arch,proto3" json:"Arch,omitempty"`
	// CPUs is the number of logical CPUs that can execite the KMS server process.
	// However, the KMS server may not use all of these CPUs. It might be limited
	// to fewer CPUs.
	CPUs uint32 `protobuf:"varint,15,opt,name=CPUs,json=sys_cpu_num,proto3" json:"CPUs,omitempty"`
	// UsableCPUs is the number of CPUs actually used by the KMS server process.
	// Unless the KMS server has been limited to fewer CPUs, equal to CPUs field.
	UsableCPUs uint32 `protobuf:"varint,16,opt,name=UsableCPUs,json=sys_cpu_used,proto3" json:"UsableCPUs,omitempty"`
	// HeapMemInUse is the amount of heap memory currently occupied by the KMS server.
	// The total amount of memory used by the KMS server process is HeapMemInUse +
	// StackMemInUse.
	HeapMemInUse uint64 `protobuf:"varint,17,opt,name=HeapMemInUse,json=sys_mem_heap_used,proto3" json:"HeapMemInUse,omitempty"`
	// StackMemInUse is the amount of stack memory currently occupied by the KMS server.
	// The total amount of memory used by the KMS server process is HeapMemInUse +
	// StackMemInUse.
	StackMemInUse uint64 `protobuf:"varint,18,opt,name=StackMemInUse,json=sys_mem_stack_used,proto3" json:"StackMemInUse,omitempty"`
}

func (x *NodeStatusResponse) Reset() {
	*x = NodeStatusResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_response_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NodeStatusResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NodeStatusResponse) ProtoMessage() {}

func (x *NodeStatusResponse) ProtoReflect() protoreflect.Message {
	mi := &file_response_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NodeStatusResponse.ProtoReflect.Descriptor instead.
func (*NodeStatusResponse) Descriptor() ([]byte, []int) {
	return file_response_proto_rawDescGZIP(), []int{1}
}

func (x *NodeStatusResponse) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *NodeStatusResponse) GetAPIVersion() string {
	if x != nil {
		return x.APIVersion
	}
	return ""
}

func (x *NodeStatusResponse) GetAddr() string {
	if x != nil {
		return x.Addr
	}
	return ""
}

func (x *NodeStatusResponse) GetRole() string {
	if x != nil {
		return x.Role
	}
	return ""
}

func (x *NodeStatusResponse) GetCommit() uint64 {
	if x != nil {
		return x.Commit
	}
	return 0
}

func (x *NodeStatusResponse) GetNodes() map[uint32]string {
	if x != nil {
		return x.Nodes
	}
	return nil
}

func (x *NodeStatusResponse) GetID() uint32 {
	if x != nil {
		return x.ID
	}
	return 0
}

func (x *NodeStatusResponse) GetLeaderID() int64 {
	if x != nil {
		return x.LeaderID
	}
	return 0
}

func (x *NodeStatusResponse) GetLastHeartbeat() *durationpb.Duration {
	if x != nil {
		return x.LastHeartbeat
	}
	return nil
}

func (x *NodeStatusResponse) GetHeartbeatInterval() *durationpb.Duration {
	if x != nil {
		return x.HeartbeatInterval
	}
	return nil
}

func (x *NodeStatusResponse) GetElectionTimeout() *durationpb.Duration {
	if x != nil {
		return x.ElectionTimeout
	}
	return nil
}

func (x *NodeStatusResponse) GetUpTime() *durationpb.Duration {
	if x != nil {
		return x.UpTime
	}
	return nil
}

func (x *NodeStatusResponse) GetOS() string {
	if x != nil {
		return x.OS
	}
	return ""
}

func (x *NodeStatusResponse) GetArch() string {
	if x != nil {
		return x.Arch
	}
	return ""
}

func (x *NodeStatusResponse) GetCPUs() uint32 {
	if x != nil {
		return x.CPUs
	}
	return 0
}

func (x *NodeStatusResponse) GetUsableCPUs() uint32 {
	if x != nil {
		return x.UsableCPUs
	}
	return 0
}

func (x *NodeStatusResponse) GetHeapMemInUse() uint64 {
	if x != nil {
		return x.HeapMemInUse
	}
	return 0
}

func (x *NodeStatusResponse) GetStackMemInUse() uint64 {
	if x != nil {
		return x.StackMemInUse
	}
	return 0
}

type StatusResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	NodesUp   map[uint32]*NodeStatusResponse `protobuf:"bytes,1,rep,name=nodesUp,json=nodes_up,proto3" json:"nodesUp,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	NodesDown map[uint32]string              `protobuf:"bytes,2,rep,name=nodesDown,json=nodes_down,proto3" json:"nodesDown,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *StatusResponse) Reset() {
	*x = StatusResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_response_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StatusResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StatusResponse) ProtoMessage() {}

func (x *StatusResponse) ProtoReflect() protoreflect.Message {
	mi := &file_response_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StatusResponse.ProtoReflect.Descriptor instead.
func (*StatusResponse) Descriptor() ([]byte, []int) {
	return file_response_proto_rawDescGZIP(), []int{2}
}

func (x *StatusResponse) GetNodesUp() map[uint32]*NodeStatusResponse {
	if x != nil {
		return x.NodesUp
	}
	return nil
}

func (x *StatusResponse) GetNodesDown() map[uint32]string {
	if x != nil {
		return x.NodesDown
	}
	return nil
}

type EncryptResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Version identifies the particular key within a key ring used to encrypt
	// the message.
	Version uint32 `protobuf:"varint,1,opt,name=Version,json=version,proto3" json:"Version,omitempty"`
	// Ciphertext is the encrypted message.
	Ciphertext []byte `protobuf:"bytes,2,opt,name=Ciphertext,json=ciphertext,proto3" json:"Ciphertext,omitempty"`
}

func (x *EncryptResponse) Reset() {
	*x = EncryptResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_response_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EncryptResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EncryptResponse) ProtoMessage() {}

func (x *EncryptResponse) ProtoReflect() protoreflect.Message {
	mi := &file_response_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EncryptResponse.ProtoReflect.Descriptor instead.
func (*EncryptResponse) Descriptor() ([]byte, []int) {
	return file_response_proto_rawDescGZIP(), []int{3}
}

func (x *EncryptResponse) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *EncryptResponse) GetCiphertext() []byte {
	if x != nil {
		return x.Ciphertext
	}
	return nil
}

type DecryptResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Plaintext is the decrypted message.
	Plaintext []byte `protobuf:"bytes,1,opt,name=Plaintext,json=plaintext,proto3" json:"Plaintext,omitempty"`
}

func (x *DecryptResponse) Reset() {
	*x = DecryptResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_response_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DecryptResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DecryptResponse) ProtoMessage() {}

func (x *DecryptResponse) ProtoReflect() protoreflect.Message {
	mi := &file_response_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DecryptResponse.ProtoReflect.Descriptor instead.
func (*DecryptResponse) Descriptor() ([]byte, []int) {
	return file_response_proto_rawDescGZIP(), []int{4}
}

func (x *DecryptResponse) GetPlaintext() []byte {
	if x != nil {
		return x.Plaintext
	}
	return nil
}

type GenerateKeyResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Version identifies the particular key within a key ring used to generate
	// and encrypt this data encryption key.
	Version uint32 `protobuf:"varint,1,opt,name=Version,json=version,proto3" json:"Version,omitempty"`
	// Plaintext is the plain data encryption key. It may be used by clients to
	// perform crypto. operations.
	Plaintext []byte `protobuf:"bytes,2,opt,name=Plaintext,json=plaintext,proto3" json:"Plaintext,omitempty"`
	// Ciphertext is the encrypted data encryption key. Clients should store it
	// to obtain the plain data encryption key in the future again.
	Ciphertext []byte `protobuf:"bytes,3,opt,name=Ciphertext,json=ciphertext,proto3" json:"Ciphertext,omitempty"`
}

func (x *GenerateKeyResponse) Reset() {
	*x = GenerateKeyResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_response_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GenerateKeyResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GenerateKeyResponse) ProtoMessage() {}

func (x *GenerateKeyResponse) ProtoReflect() protoreflect.Message {
	mi := &file_response_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GenerateKeyResponse.ProtoReflect.Descriptor instead.
func (*GenerateKeyResponse) Descriptor() ([]byte, []int) {
	return file_response_proto_rawDescGZIP(), []int{5}
}

func (x *GenerateKeyResponse) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *GenerateKeyResponse) GetPlaintext() []byte {
	if x != nil {
		return x.Plaintext
	}
	return nil
}

func (x *GenerateKeyResponse) GetCiphertext() []byte {
	if x != nil {
		return x.Ciphertext
	}
	return nil
}

var File_response_proto protoreflect.FileDescriptor

var file_response_proto_rawDesc = []byte{
	0x0a, 0x0e, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x09, 0x6d, 0x69, 0x6e, 0x69, 0x6f, 0x2e, 0x6b, 0x6d, 0x73, 0x1a, 0x1e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x64, 0x75, 0x72,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x27, 0x0a, 0x0b, 0x45,
	0x72, 0x72, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x4d, 0x65,
	0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x6d, 0x65, 0x73,
	0x73, 0x61, 0x67, 0x65, 0x22, 0x88, 0x06, 0x0a, 0x12, 0x4e, 0x6f, 0x64, 0x65, 0x53, 0x74, 0x61,
	0x74, 0x75, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x56,
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x76, 0x65,
	0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x1f, 0x0a, 0x0a, 0x41, 0x50, 0x49, 0x56, 0x65, 0x72, 0x73,
	0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x61, 0x70, 0x69, 0x5f, 0x76,
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x15, 0x0a, 0x04, 0x41, 0x64, 0x64, 0x72, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x12, 0x0a,
	0x04, 0x52, 0x6f, 0x6c, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x72, 0x6f, 0x6c,
	0x65, 0x12, 0x16, 0x0a, 0x06, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28,
	0x04, 0x52, 0x06, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x12, 0x3e, 0x0a, 0x05, 0x4e, 0x6f, 0x64,
	0x65, 0x73, 0x18, 0x06, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x28, 0x2e, 0x6d, 0x69, 0x6e, 0x69, 0x6f,
	0x2e, 0x6b, 0x6d, 0x73, 0x2e, 0x4e, 0x6f, 0x64, 0x65, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x4e, 0x6f, 0x64, 0x65, 0x73, 0x45, 0x6e, 0x74,
	0x72, 0x79, 0x52, 0x05, 0x6e, 0x6f, 0x64, 0x65, 0x73, 0x12, 0x13, 0x0a, 0x02, 0x49, 0x44, 0x18,
	0x07, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x6e, 0x6f, 0x64, 0x65, 0x5f, 0x69, 0x64, 0x12, 0x1b,
	0x0a, 0x08, 0x4c, 0x65, 0x61, 0x64, 0x65, 0x72, 0x49, 0x44, 0x18, 0x08, 0x20, 0x01, 0x28, 0x12,
	0x52, 0x09, 0x6c, 0x65, 0x61, 0x64, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x12, 0x40, 0x0a, 0x0d, 0x4c,
	0x61, 0x73, 0x74, 0x48, 0x65, 0x61, 0x72, 0x74, 0x62, 0x65, 0x61, 0x74, 0x18, 0x09, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x19, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2e, 0x44, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0e, 0x6c,
	0x61, 0x73, 0x74, 0x5f, 0x68, 0x65, 0x61, 0x72, 0x74, 0x62, 0x65, 0x61, 0x74, 0x12, 0x48, 0x0a,
	0x11, 0x48, 0x65, 0x61, 0x72, 0x74, 0x62, 0x65, 0x61, 0x74, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x76,
	0x61, 0x6c, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x44, 0x75, 0x72, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x52, 0x12, 0x68, 0x65, 0x61, 0x72, 0x74, 0x62, 0x65, 0x61, 0x74, 0x5f, 0x69,
	0x6e, 0x74, 0x65, 0x72, 0x76, 0x61, 0x6c, 0x12, 0x44, 0x0a, 0x0f, 0x45, 0x6c, 0x65, 0x63, 0x74,
	0x69, 0x6f, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x19, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2e, 0x44, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x10, 0x65, 0x6c, 0x65,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x12, 0x35, 0x0a,
	0x06, 0x55, 0x70, 0x54, 0x69, 0x6d, 0x65, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x44, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0a, 0x73, 0x79, 0x73, 0x5f, 0x75, 0x70,
	0x74, 0x69, 0x6d, 0x65, 0x12, 0x12, 0x0a, 0x02, 0x4f, 0x53, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x06, 0x73, 0x79, 0x73, 0x5f, 0x6f, 0x73, 0x12, 0x1a, 0x0a, 0x04, 0x41, 0x72, 0x63, 0x68,
	0x18, 0x0e, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x73, 0x79, 0x73, 0x5f, 0x63, 0x70, 0x75, 0x5f,
	0x61, 0x72, 0x63, 0x68, 0x12, 0x19, 0x0a, 0x04, 0x43, 0x50, 0x55, 0x73, 0x18, 0x0f, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x0b, 0x73, 0x79, 0x73, 0x5f, 0x63, 0x70, 0x75, 0x5f, 0x6e, 0x75, 0x6d, 0x12,
	0x20, 0x0a, 0x0a, 0x55, 0x73, 0x61, 0x62, 0x6c, 0x65, 0x43, 0x50, 0x55, 0x73, 0x18, 0x10, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x0c, 0x73, 0x79, 0x73, 0x5f, 0x63, 0x70, 0x75, 0x5f, 0x75, 0x73, 0x65,
	0x64, 0x12, 0x27, 0x0a, 0x0c, 0x48, 0x65, 0x61, 0x70, 0x4d, 0x65, 0x6d, 0x49, 0x6e, 0x55, 0x73,
	0x65, 0x18, 0x11, 0x20, 0x01, 0x28, 0x04, 0x52, 0x11, 0x73, 0x79, 0x73, 0x5f, 0x6d, 0x65, 0x6d,
	0x5f, 0x68, 0x65, 0x61, 0x70, 0x5f, 0x75, 0x73, 0x65, 0x64, 0x12, 0x29, 0x0a, 0x0d, 0x53, 0x74,
	0x61, 0x63, 0x6b, 0x4d, 0x65, 0x6d, 0x49, 0x6e, 0x55, 0x73, 0x65, 0x18, 0x12, 0x20, 0x01, 0x28,
	0x04, 0x52, 0x12, 0x73, 0x79, 0x73, 0x5f, 0x6d, 0x65, 0x6d, 0x5f, 0x73, 0x74, 0x61, 0x63, 0x6b,
	0x5f, 0x75, 0x73, 0x65, 0x64, 0x1a, 0x38, 0x0a, 0x0a, 0x4e, 0x6f, 0x64, 0x65, 0x73, 0x45, 0x6e,
	0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x22,
	0xb5, 0x02, 0x0a, 0x0e, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x12, 0x41, 0x0a, 0x07, 0x6e, 0x6f, 0x64, 0x65, 0x73, 0x55, 0x70, 0x18, 0x01, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x26, 0x2e, 0x6d, 0x69, 0x6e, 0x69, 0x6f, 0x2e, 0x6b, 0x6d, 0x73, 0x2e,
	0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x4e,
	0x6f, 0x64, 0x65, 0x73, 0x55, 0x70, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x08, 0x6e, 0x6f, 0x64,
	0x65, 0x73, 0x5f, 0x75, 0x70, 0x12, 0x47, 0x0a, 0x09, 0x6e, 0x6f, 0x64, 0x65, 0x73, 0x44, 0x6f,
	0x77, 0x6e, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x28, 0x2e, 0x6d, 0x69, 0x6e, 0x69, 0x6f,
	0x2e, 0x6b, 0x6d, 0x73, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x2e, 0x4e, 0x6f, 0x64, 0x65, 0x73, 0x44, 0x6f, 0x77, 0x6e, 0x45, 0x6e, 0x74,
	0x72, 0x79, 0x52, 0x0a, 0x6e, 0x6f, 0x64, 0x65, 0x73, 0x5f, 0x64, 0x6f, 0x77, 0x6e, 0x1a, 0x59,
	0x0a, 0x0c, 0x4e, 0x6f, 0x64, 0x65, 0x73, 0x55, 0x70, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10,
	0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x6b, 0x65, 0x79,
	0x12, 0x33, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1d, 0x2e, 0x6d, 0x69, 0x6e, 0x69, 0x6f, 0x2e, 0x6b, 0x6d, 0x73, 0x2e, 0x4e, 0x6f, 0x64, 0x65,
	0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x52, 0x05,
	0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x1a, 0x3c, 0x0a, 0x0e, 0x4e, 0x6f, 0x64,
	0x65, 0x73, 0x44, 0x6f, 0x77, 0x6e, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b,
	0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a,
	0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61,
	0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x22, 0x4b, 0x0a, 0x0f, 0x45, 0x6e, 0x63, 0x72, 0x79,
	0x70, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x56, 0x65,
	0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x76, 0x65, 0x72,
	0x73, 0x69, 0x6f, 0x6e, 0x12, 0x1e, 0x0a, 0x0a, 0x43, 0x69, 0x70, 0x68, 0x65, 0x72, 0x74, 0x65,
	0x78, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0a, 0x63, 0x69, 0x70, 0x68, 0x65, 0x72,
	0x74, 0x65, 0x78, 0x74, 0x22, 0x2f, 0x0a, 0x0f, 0x44, 0x65, 0x63, 0x72, 0x79, 0x70, 0x74, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x50, 0x6c, 0x61, 0x69, 0x6e,
	0x74, 0x65, 0x78, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x70, 0x6c, 0x61, 0x69,
	0x6e, 0x74, 0x65, 0x78, 0x74, 0x22, 0x6d, 0x0a, 0x13, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74,
	0x65, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x18, 0x0a, 0x07,
	0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x76,
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x1c, 0x0a, 0x09, 0x50, 0x6c, 0x61, 0x69, 0x6e, 0x74,
	0x65, 0x78, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x70, 0x6c, 0x61, 0x69, 0x6e,
	0x74, 0x65, 0x78, 0x74, 0x12, 0x1e, 0x0a, 0x0a, 0x43, 0x69, 0x70, 0x68, 0x65, 0x72, 0x74, 0x65,
	0x78, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0a, 0x63, 0x69, 0x70, 0x68, 0x65, 0x72,
	0x74, 0x65, 0x78, 0x74, 0x42, 0x0e, 0x5a, 0x0c, 0x6b, 0x6d, 0x73, 0x2f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_response_proto_rawDescOnce sync.Once
	file_response_proto_rawDescData = file_response_proto_rawDesc
)

func file_response_proto_rawDescGZIP() []byte {
	file_response_proto_rawDescOnce.Do(func() {
		file_response_proto_rawDescData = protoimpl.X.CompressGZIP(file_response_proto_rawDescData)
	})
	return file_response_proto_rawDescData
}

var file_response_proto_msgTypes = make([]protoimpl.MessageInfo, 9)
var file_response_proto_goTypes = []interface{}{
	(*ErrResponse)(nil),         // 0: minio.kms.ErrResponse
	(*NodeStatusResponse)(nil),  // 1: minio.kms.NodeStatusResponse
	(*StatusResponse)(nil),      // 2: minio.kms.StatusResponse
	(*EncryptResponse)(nil),     // 3: minio.kms.EncryptResponse
	(*DecryptResponse)(nil),     // 4: minio.kms.DecryptResponse
	(*GenerateKeyResponse)(nil), // 5: minio.kms.GenerateKeyResponse
	nil,                         // 6: minio.kms.NodeStatusResponse.NodesEntry
	nil,                         // 7: minio.kms.StatusResponse.NodesUpEntry
	nil,                         // 8: minio.kms.StatusResponse.NodesDownEntry
	(*durationpb.Duration)(nil), // 9: google.protobuf.Duration
}
var file_response_proto_depIdxs = []int32{
	6, // 0: minio.kms.NodeStatusResponse.Nodes:type_name -> minio.kms.NodeStatusResponse.NodesEntry
	9, // 1: minio.kms.NodeStatusResponse.LastHeartbeat:type_name -> google.protobuf.Duration
	9, // 2: minio.kms.NodeStatusResponse.HeartbeatInterval:type_name -> google.protobuf.Duration
	9, // 3: minio.kms.NodeStatusResponse.ElectionTimeout:type_name -> google.protobuf.Duration
	9, // 4: minio.kms.NodeStatusResponse.UpTime:type_name -> google.protobuf.Duration
	7, // 5: minio.kms.StatusResponse.nodesUp:type_name -> minio.kms.StatusResponse.NodesUpEntry
	8, // 6: minio.kms.StatusResponse.nodesDown:type_name -> minio.kms.StatusResponse.NodesDownEntry
	1, // 7: minio.kms.StatusResponse.NodesUpEntry.value:type_name -> minio.kms.NodeStatusResponse
	8, // [8:8] is the sub-list for method output_type
	8, // [8:8] is the sub-list for method input_type
	8, // [8:8] is the sub-list for extension type_name
	8, // [8:8] is the sub-list for extension extendee
	0, // [0:8] is the sub-list for field type_name
}

func init() { file_response_proto_init() }
func file_response_proto_init() {
	if File_response_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_response_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ErrResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_response_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*NodeStatusResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_response_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StatusResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_response_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EncryptResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_response_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DecryptResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_response_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GenerateKeyResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_response_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   9,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_response_proto_goTypes,
		DependencyIndexes: file_response_proto_depIdxs,
		MessageInfos:      file_response_proto_msgTypes,
	}.Build()
	File_response_proto = out.File
	file_response_proto_rawDesc = nil
	file_response_proto_goTypes = nil
	file_response_proto_depIdxs = nil
}
