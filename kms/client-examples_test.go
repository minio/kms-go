// Copyright 2024 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kms_test

import (
	"crypto/tls"
	"log"

	"github.com/minio/kms-go/kms"
)

func ExampleNewClient() {
	key, err := kms.ParseAPIKey("k1:d7cY_5k8HbBGkZpoy2hGmvkxg83QDBXsA_nFXDfTk2E")
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
