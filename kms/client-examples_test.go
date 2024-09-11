// Copyright 2024 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kms_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"time"

	"aead.dev/mtls"
	"github.com/minio/kms-go/kms"
)

func ExampleNewClient() {
	key, err := mtls.ParsePrivateKey("k1:d7cY_5k8HbBGkZpoy2hGmvkxg83QDBXsA_nFXDfTk2E")
	if err != nil {
		log.Fatalf("Failed to parse KMS API key: %v", err)
	}

	client, err := kms.NewClient(&kms.Config{
		Endpoints: []string{
			"10.1.2.1:7373",
			"10.1.2.2:7373",
			"10.1.2.3:7373",
		},
		APIKey: key,
		TLS: &tls.Config{
			// This CertPool must contain the CA certificate that issued the
			// certificates of the KMS servers. Defaults to the system trust
			// store.
			// Using no or the wrong CA certificate is a common pitfall that
			// causes TLS/X.509 certificate verification errors.
			// A good test is a simple:
			//
			//  $ curl -v 'https://<endpoint:port>/version'
			RootCAs: nil,
		},
	})
	if err != nil {
		log.Fatalf("Failed to create KMS client: %v", err)
	}

	_ = client // TODO: use client for some operations

	// Output:
}

// ExampleClient_AddNode shows how to add a KMS server to an existing
// KMS cluster dynamically expanding it. The added KMS server must not
// be part of an exisiting cluster.
func ExampleClient_AddNode() {
	key, err := mtls.ParsePrivateKey("k1:d7cY_5k8HbBGkZpoy2hGmvkxg83QDBXsA_nFXDfTk2E")
	if err != nil {
		log.Fatalf("Failed to parse KMS API key: %v", err)
	}

	client, err := kms.NewClient(&kms.Config{
		Endpoints: []string{
			"127.0.0.1:7373",
		},
		APIKey: key,
		TLS: &tls.Config{
			RootCAs:            nil,   // Use nil for system root CAs or customize
			InsecureSkipVerify: false, // Don't skip TLS cert verification in prod
		},
	})
	if err != nil {
		log.Fatalf("Failed to create KMS client: %v", err)
	}

	request := &kms.AddClusterNodeRequest{
		Host: "10.1.2.3:7373",
	}
	if err = client.AddNode(context.TODO(), request); err != nil {
		log.Fatalf("Failed to add server '%s' to cluster: %v", request.Host, err)
	}
}

// ExampleClient_RemoveNode shows how to remove a KMS server from the
// cluster it is currently part of.
func ExampleClient_RemoveNode() {
	key, err := mtls.ParsePrivateKey("k1:d7cY_5k8HbBGkZpoy2hGmvkxg83QDBXsA_nFXDfTk2E")
	if err != nil {
		log.Fatalf("Failed to parse KMS API key: %v", err)
	}

	client, err := kms.NewClient(&kms.Config{
		Endpoints: []string{
			"127.0.0.1:7373",
		},
		APIKey: key,
		TLS: &tls.Config{
			RootCAs:            nil,   // Use nil for system root CAs or customize
			InsecureSkipVerify: false, // Don't skip TLS cert verification in prod
		},
	})
	if err != nil {
		log.Fatalf("Failed to create KMS client: %v", err)
	}

	request := &kms.RemoveClusterNodeRequest{
		Host: "10.1.2.3:7373",
	}
	if err = client.RemoveNode(context.TODO(), request); err != nil {
		log.Fatalf("Failed to remove server '%s' from cluster: %v", request.Host, err)
	}
}

// ExampleClient_ClusterStatus shows how to fetch cluster status information
// from a KMS cluster.
func ExampleClient_ClusterStatus() {
	key, err := mtls.ParsePrivateKey("k1:d7cY_5k8HbBGkZpoy2hGmvkxg83QDBXsA_nFXDfTk2E")
	if err != nil {
		log.Fatalf("Failed to parse KMS API key: %v", err)
	}

	client, err := kms.NewClient(&kms.Config{
		Endpoints: []string{
			"127.0.0.1:7373",
		},
		APIKey: key,
		TLS: &tls.Config{
			RootCAs:            nil,   // Use nil for system root CAs or customize
			InsecureSkipVerify: false, // Don't skip TLS cert verification in prod
		},
	})
	if err != nil {
		log.Fatalf("Failed to create KMS client: %v", err)
	}

	status, err := client.ClusterStatus(context.TODO(), &kms.ClusterStatusRequest{})
	if err != nil {
		log.Fatalf("Failed to fetch cluster status information: %v", err)
	}
	log.Printf("Servers: online [%d] - offline [%d]", len(status.NodesUp), len(status.NodesDown))
}

// ExampleClient_CreateEnclave shows how to create a new enclave.
func ExampleClient_CreateEnclave() {
	key, err := mtls.ParsePrivateKey("k1:d7cY_5k8HbBGkZpoy2hGmvkxg83QDBXsA_nFXDfTk2E")
	if err != nil {
		log.Fatalf("Failed to parse KMS API key: %v", err)
	}

	client, err := kms.NewClient(&kms.Config{
		Endpoints: []string{
			"127.0.0.1:7373",
		},
		APIKey: key,
		TLS: &tls.Config{
			RootCAs:            nil,   // Use nil for system root CAs or customize
			InsecureSkipVerify: false, // Don't skip TLS cert verification in prod
		},
	})
	if err != nil {
		log.Fatalf("Failed to create KMS client: %v", err)
	}

	request := &kms.CreateEnclaveRequest{
		Name: "minio-tenant-foo",
	}
	if err = client.CreateEnclave(context.TODO(), request); err != nil {
		log.Fatalf("Failed to create enclave '%s': %v", request.Name, err)
	}
}

// ExampleClient_DeleteEnclave shows how to delete an existing enclave.
func ExampleClient_DeleteEnclave() {
	key, err := mtls.ParsePrivateKey("k1:d7cY_5k8HbBGkZpoy2hGmvkxg83QDBXsA_nFXDfTk2E")
	if err != nil {
		log.Fatalf("Failed to parse KMS API key: %v", err)
	}

	client, err := kms.NewClient(&kms.Config{
		Endpoints: []string{
			"127.0.0.1:7373",
		},
		APIKey: key,
		TLS: &tls.Config{
			RootCAs:            nil,   // Use nil for system root CAs or customize
			InsecureSkipVerify: false, // Don't skip TLS cert verification in prod
		},
	})
	if err != nil {
		log.Fatalf("Failed to create KMS client: %v", err)
	}

	request := &kms.DeleteEnclaveRequest{
		Name: "minio-tenant-foo",
	}
	if err = client.DeleteEnclave(context.TODO(), request); err != nil {
		log.Fatalf("Failed to delete enclave '%s': %v", request.Name, err)
	}
}

// ExampleClient_EnclaveStatus shows how to fetch status information about two enclaves.
// Fetching information about multiple enclaves requires just a single network request.
func ExampleClient_EnclaveStatus() {
	key, err := mtls.ParsePrivateKey("k1:d7cY_5k8HbBGkZpoy2hGmvkxg83QDBXsA_nFXDfTk2E")
	if err != nil {
		log.Fatalf("Failed to parse KMS API key: %v", err)
	}

	client, err := kms.NewClient(&kms.Config{
		Endpoints: []string{
			"127.0.0.1:7373",
		},
		APIKey: key,
		TLS: &tls.Config{
			RootCAs:            nil,   // Use nil for system root CAs or customize
			InsecureSkipVerify: false, // Don't skip TLS cert verification in prod
		},
	})
	if err != nil {
		log.Fatalf("Failed to create KMS client: %v", err)
	}

	requests := []*kms.EnclaveStatusRequest{
		{Name: "minio-tenant-foo"},
		{Name: "minio-tenant-bar"},
	}
	responses, err := client.EnclaveStatus(context.TODO(), requests...)
	if err != nil {
		log.Fatalf("Failed to fetch enclave status: %v", err)
	}

	for _, response := range responses {
		fmt.Println(response.Name)
	}
}

// ExampleClient_EnclaveStatus shows how to fetch status information about two enclaves.
// Fetching information about multiple enclaves requires just a single network request.
func ExampleClient_ListEnclaves() {
	key, err := mtls.ParsePrivateKey("k1:d7cY_5k8HbBGkZpoy2hGmvkxg83QDBXsA_nFXDfTk2E")
	if err != nil {
		log.Fatalf("Failed to parse KMS API key: %v", err)
	}

	client, err := kms.NewClient(&kms.Config{
		Endpoints: []string{
			"127.0.0.1:7373",
		},
		APIKey: key,
		TLS: &tls.Config{
			RootCAs:            nil,   // Use nil for system root CAs or customize
			InsecureSkipVerify: false, // Don't skip TLS cert verification in prod
		},
	})
	if err != nil {
		log.Fatalf("Failed to create KMS client: %v", err)
	}

	iter := kms.Iter[kms.EnclaveStatusResponse]{
		NextFn: client.ListEnclaves,
	}
	for v, err := iter.Next(context.TODO()); err != io.EOF; v, err = iter.Next(context.TODO()) {
		if err != nil {
			log.Fatalf("Failed to list enclaves: %v", err)
		}
		fmt.Println(v.Name)
	}
}

// ExampleClient_Logs shows how to fetch server log records.
func ExampleClient_Logs() {
	key, err := mtls.ParsePrivateKey("k1:d7cY_5k8HbBGkZpoy2hGmvkxg83QDBXsA_nFXDfTk2E")
	if err != nil {
		log.Fatalf("Failed to parse KMS API key: %v", err)
	}

	client, err := kms.NewClient(&kms.Config{
		Endpoints: []string{
			"127.0.0.1:7373",
		},
		APIKey: key,
		TLS: &tls.Config{
			RootCAs:            nil,   // Use nil for system root CAs or customize
			InsecureSkipVerify: false, // Don't skip TLS cert verification in prod
		},
	})
	if err != nil {
		log.Fatalf("Failed to create KMS client: %v", err)
	}

	logs, err := client.Logs(context.TODO(), &kms.LogRequest{
		Host:  "127.0.0.1:7373",                 // The server to fetch logs from
		Level: slog.LevelWarn,                   // Fetch only warnings or error logs
		Since: time.Now().Add(-5 * time.Minute), // Fetch logs of the last 5 min
	})
	if err != nil {
		log.Fatalf("Failed to fetch server logs: %v", err)
	}
	defer logs.Close()

	for r, ok := logs.Next(); ok; r, ok = logs.Next() {
		_ = r // TODO: print logs
	}
	if err = logs.Close(); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}
