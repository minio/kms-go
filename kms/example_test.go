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
	key, err := kms.ParseAPIKey("AGaV6VXHasF0FnaB60WdCOeTZ8eTIDikL4zlN16c8NAs")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(key)
	// Output:
	// AGaV6VXHasF0FnaB60WdCOeTZ8eTIDikL4zlN16c8NAs
}

func ExampleAPIKey_Identity() {
	key, err := kms.ParseAPIKey("AGaV6VXHasF0FnaB60WdCOeTZ8eTIDikL4zlN16c8NAs")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(key.Identity())
	// Output:
	// ea9826089311fe44d7590408ede9150f7c637b6cab0a91ee6fe1aa5d9fb366f6
}
