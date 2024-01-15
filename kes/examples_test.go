// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"log"

	"github.com/minio/kms-go/kes"
)

func ExampleNewClient() {
	const (
		Endpoint = "https://play.min.io:7373"
		APIKey   = "kes:v1:AD9E7FSYWrMD+VjhI6q545cYT9YOyFxZb7UnjEepYDRc"
	)

	key, err := kes.ParseAPIKey(APIKey)
	if err != nil {
		log.Fatalf("Invalid API key '%s': %v", APIKey, err)
	}
	client, err := kes.NewClient(Endpoint, key)
	if err != nil {
		log.Fatalf("Failed to create client for '%s': %v", Endpoint, err)
	}
	_ = client

	fmt.Println("Identity:", key.Identity())
	// Output:
	// Identity: 3ecfcdf38fcbe141ae26a1030f81e96b753365a46760ae6b578698a97c59fd22
}

func ExampleNewClientWithConfig() {
	const (
		Endpoint = "https://play.min.io:7373"
	)
	const (
		PrivateKey  = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEID9E7FSYWrMD+VjhI6q545cYT9YOyFxZb7UnjEepYDRc\n-----END PRIVATE KEY-----"
		Certificate = "-----BEGIN CERTIFICATE-----\nMIIBKDCB26ADAgECAhB6vebGMUfKnmBKyqoApRSOMAUGAytlcDAbMRkwFwYDVQQDDBByb290QHBsYXkubWluLmlvMB4XDTIwMDQzMDE1MjIyNVoXDTI1MDQyOTE1MjIyNVowGzEZMBcGA1UEAwwQcm9vdEBwbGF5Lm1pbi5pbzAqMAUGAytlcAMhALzn735WfmSH/ghKs+4iPWziZMmWdiWr/sqvqeW+WwSxozUwMzAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAFBgMrZXADQQDZOrGKb2ATkDlu2pTcP3LyhSBDpYh7V4TvjRkBTRgjkacCzwFLm+mh+7US8V4dBpIDsJ4uuWoF0y6vbLVGIlkG\n-----END CERTIFICATE-----"
	)

	cert, err := tls.X509KeyPair([]byte(Certificate), []byte(PrivateKey))
	if err != nil {
		log.Fatalf("Failed to certificate/private key: %v", err)
	}
	cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])

	client := kes.NewClientWithConfig(Endpoint, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	})
	_ = client

	h := sha256.Sum256(cert.Leaf.RawSubjectPublicKeyInfo)
	fmt.Println("Identity:", hex.EncodeToString(h[:]))
	// Output:
	// Identity: 3ecfcdf38fcbe141ae26a1030f81e96b753365a46760ae6b578698a97c59fd22
}

func ExampleListIter() {
	const (
		Endpoint = "https://play.min.io:7373"
		APIKey   = "kes:v1:AD9E7FSYWrMD+VjhI6q545cYT9YOyFxZb7UnjEepYDRc"
	)

	key, err := kes.ParseAPIKey(APIKey)
	if err != nil {
		log.Fatalf("Invalid API key '%s': %v", APIKey, err)
	}
	client, err := kes.NewClient(Endpoint, key)
	if err != nil {
		log.Fatalf("Failed to create client for '%s': %v", Endpoint, err)
	}

	ctx := context.TODO()
	iter := kes.ListIter[string]{
		NextFunc: client.ListKeys,
	}
	for name, err := iter.Next(ctx); err != io.EOF; name, err = iter.Next(ctx) {
		if err != nil {
			log.Fatalf("Failed to list keys: %v", err)
		}
		fmt.Println(name)
	}
}

func ExampleListIter_SeekTo() {
	const (
		Endpoint = "https://play.min.io:7373"
		APIKey   = "kes:v1:AD9E7FSYWrMD+VjhI6q545cYT9YOyFxZb7UnjEepYDRc"
	)

	key, err := kes.ParseAPIKey(APIKey)
	if err != nil {
		log.Fatalf("Invalid API key '%s': %v", APIKey, err)
	}
	client, err := kes.NewClient(Endpoint, key)
	if err != nil {
		log.Fatalf("Failed to create client for '%s': %v", Endpoint, err)
	}

	ctx := context.TODO()
	iter := kes.ListIter[string]{
		NextFunc: client.ListKeys,
	}
	for name, err := iter.SeekTo(ctx, "my-key"); err != io.EOF; name, err = iter.Next(ctx) {
		if err != nil {
			log.Fatalf("Failed to list keys: %v", err)
		}
		fmt.Println(name)
	}
}
