// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kms_test

import (
	"fmt"
	"log"

	"github.com/minio/kms-go/kms"
)

func ExampleParseAPIKey() {
	key, err := kms.ParseAPIKey("k1:d7cY/5k8HbBGkZpoy2hGmvkxg83QDBXsA/nFXDfTk2E")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(key)
	// Output:
	// k1:d7cY/5k8HbBGkZpoy2hGmvkxg83QDBXsA/nFXDfTk2E
}

func ExampleAPIKey_Identity() {
	key, err := kms.ParseAPIKey("k1:d7cY/5k8HbBGkZpoy2hGmvkxg83QDBXsA/nFXDfTk2E")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(key.Identity())
	// Output:
	// h1:Rvxa7nj8zkL48CeDkN6LhpX+K7KK6uhIhpBOcTHNhWw
}
