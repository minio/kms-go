// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package api

// API paths accessible to sysadmins, admins users and their
// service accounts. However, some APIs may behave differently
// depending on the identity. For example, user accounts can
// only create new service accounts while admins can also create
// new user accounts.
const (
	PathVersion     = "/version"         // Unprivileged by default
	PathHealthLive  = "/v1/health/live"  // Unprivileged by default - liveness check
	PathHealthReady = "/v1/health/ready" // Unprivileged by default - readiness check

	PathHealthStatus = "/v1/health/status"
	PathHealthAPIs   = "/v1/health/api"

	PathDB  = "/v1/db"
	PathKMS = "/v1/kms/"

	PathRPCReplicate = "/v1/rpc/replicate"
	PathRPCForward   = "/v1/rpc/forward"
	PathRPCVote      = "/v1/rpc/vote"
	PathRPCStatus    = "/v1/rpc/status"
)

// API query parameters supported by KMS servers.
const (
	QueryReadyWrite = "write"
)
