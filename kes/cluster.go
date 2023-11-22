// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

// ClusterInfo describes a KES cluster consisting of
// one or multiple nodes controlled by one leader node.
type ClusterInfo struct {
	Nodes  map[uint64]string
	Leader uint64
}
