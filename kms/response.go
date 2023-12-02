// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kms

import (
	"io"
	"net/http"
	"time"

	"github.com/minio/kms-go/kms/internal/headers"
	pb "github.com/minio/kms-go/kms/protobuf"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// readResponse reads the response body into v using the
// response content encoding.
//
// readBesponse assumes that the response body is limited
// to a reasonable size. It returns an error if it cannot
// determine the response content length before decoding.
func readResponse(r *http.Response, v proto.Message) error {
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

// NodeStatusResponse contains status information about a single
// KMS cluster node.
type NodeStatusResponse struct {
	Version           string
	Endpoint          string
	State             string
	Commit            uint64
	Nodes             map[int]string
	ID                int
	LeaderID          int
	LastHeartbeat     time.Duration
	HeartbeatInterval time.Duration
	ElectionTimeout   time.Duration
	UpTime            time.Duration
	OS                string
	CPUArch           string
	CPUs              uint
	UsableCPUs        uint
	HeapMemInUse      uint64
	StackMemInUse     uint64
}

// MarshalPB converts the NodeStatusResponse into its protobuf representation.
func (s *NodeStatusResponse) MarshalPB(v *pb.NodeStatusResponse) error {
	v.Version = s.Version
	v.Addr = s.Endpoint
	v.State = s.State
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

// UnmarshalPB initializes the NodeStatusResponse from its protobuf representation.
func (s *NodeStatusResponse) UnmarshalPB(v *pb.NodeStatusResponse) error {
	s.Version = v.Version
	s.Endpoint = v.Addr
	s.State = v.State
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

// StatusResponse contains status information about a KMS cluster.
//
// The overall view of the current cluster status, in particular
// which nodes are reachable, may vary from node to node in case
// of network partitions. For example, two nodes within two network
// partitions will consider themselves as up and their peer as down.
type StatusResponse struct {
	// NodesUp is a map of node IDs to the corresponding node status
	// information.
	NodesUp map[int]*NodeStatusResponse

	// NodesDown is a map of node IDs to node addresses containing
	// all nodes that were not reachable or failed to respond in time.
	NodesDown map[int]string
}

// MarshalPB converts the StatusResponse into its protobuf representation.
func (s *StatusResponse) MarshalPB(v *pb.StatusResponse) error {
	v.NodesUp = make(map[uint32]*pb.NodeStatusResponse, len(s.NodesUp))
	for id, resp := range s.NodesUp {
		stat := new(pb.NodeStatusResponse)
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

// UnmarshalPB initializes the StatusResponse from its protobuf representation.
func (s *StatusResponse) UnmarshalPB(v *pb.StatusResponse) error {
	s.NodesUp = make(map[int]*NodeStatusResponse, len(v.NodesUp))
	for id, resp := range v.NodesUp {
		stat := new(NodeStatusResponse)
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
