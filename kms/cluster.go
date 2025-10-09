// Copyright 2025 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kms

import (
	"context"
	"maps"
	"slices"
	"strings"
)

// Join joins the servers specified in conf.Endpoints
// into a single cluster or returns an error if it fails.
//
// Join can only construct one cluster from the given
// endpoints if there is not more than one multi-node
// cluster. It does not split existing clusters in order
// to join multiple clusters into one.
//
// It returns no error if all servers are already part
// of the same cluster.
func Join(ctx context.Context, conf *Config) error {
	if len(conf.Endpoints) <= 1 {
		return nil
	}
	const Scheme = "https://"

	client, err := NewClient(conf)
	if err != nil {
		return err
	}

	// Find one node that belongs to a multi-node cluster.
	// All remaining nodes that don't belong to this cluster
	// have to join it.
	//
	// Therefore, we simply assume that the remaining nodes
	// are "standalone". We don't handle a situation where
	// the list of endpoints refers to multiple multi-node
	// clusters here. In such a case, we cannot construct
	// a single cluster. Instead, we fail later on when
	// joining the nodes.
	clusterNodes := make(map[string]struct{})
	for _, endpoint := range conf.Endpoints {
		endpoint = strings.TrimPrefix(endpoint, Scheme)
		client.lb.Hosts = []string{endpoint}

		status, err := client.ClusterStatus(ctx, &ClusterStatusRequest{})
		if err != nil {
			return err
		}
		if len(status.NodesUp)+len(status.NodesDown) == 1 {
			continue
		}

		for _, node := range status.NodesUp {
			clusterNodes[node.Host] = struct{}{}
		}
		for _, node := range status.NodesDown {
			clusterNodes[node] = struct{}{}
		}
		break
	}

	// If all nodes are "standalone", we pick some node as the one
	// all others are joining to.
	if len(clusterNodes) == 0 {
		clusterNodes[strings.TrimPrefix(conf.Endpoints[0], Scheme)] = struct{}{}
	}
	client.lb.Hosts = slices.Collect(maps.Keys(clusterNodes))

	for _, endpoint := range conf.Endpoints {
		endpoint = strings.TrimPrefix(endpoint, Scheme)
		if _, ok := clusterNodes[endpoint]; ok {
			continue
		}
		if err := client.AddNode(ctx, &AddClusterNodeRequest{Host: endpoint}); err != nil {
			return err
		}
	}
	return nil
}
