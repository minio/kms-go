// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package protobuf

import (
	"time"

	pbd "google.golang.org/protobuf/types/known/durationpb"
	pbt "google.golang.org/protobuf/types/known/timestamppb"
)

// Time returns a new protobuf timestamp from the given t.
func Time(t time.Time) *pbt.Timestamp { return pbt.New(t) }

// Duration returns a new protobuf duration from the given d.
func Duration(d time.Duration) *pbd.Duration { return pbd.New(d) }
