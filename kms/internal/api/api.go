// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package api

// Privileged API paths only accessible to sysadmin accounts.
// Intended for provisioning and operating a cluster.
const (
	PathEnclaveCreate   = "/v1/enclave/create/"
	PathEnclaveDescribe = "/v1/enclave/describe/"
	PathEnclaveDelete   = "/v1/enclave/delete/"
	PathEnclaveList     = "/v1/enclave/list/"

	PathClusterMetrics = "/v1/cluster/metrics"
	PathClusterStatus  = "/v1/cluster/status"
	PathClusterAdd     = "/v1/cluster/add/"
	PathClusterRemove  = "/v1/cluster/remove/"
	PathClusterEdit    = "/v1/cluster/edit"
	PathClusterBackup  = "/v1/cluster/backup"
)

// API paths accessible to sysadmins, admins users and their
// service accounts. However, some APIs may behave differently
// depending on the identity. For example, user accounts can
// only create new service accounts while admins can also create
// new user accounts.
const (
	PathVersion      = "/version"         // Unprivileged by default
	PathHealthLive   = "/v1/health/live"  // Unprivileged by default - liveness check
	PathHealthReady  = "/v1/health/ready" // Unprivileged by default - readiness check

	PathHealthStatus = "/v1/health/status"
	PathHealthAPIs   = "/v1/health/api"

	PathLogError = "/v1/log/error"
	PathLogAudit = "/v1/log/audit"

	PathSecretKeyCreate   = "/v1/key/create/"
	PathSecretKeyImport   = "/v1/key/import/"
	PathSecretKeyDescribe = "/v1/key/describe/"
	PathSecretKeyDelete   = "/v1/key/delete/"
	PathSecretKeyList     = "/v1/key/list/"
	PathSecretKeyGenerate = "/v1/key/generate/"
	PathSecretKeyEncrypt  = "/v1/key/encrypt/"
	PathSecretKeyDecrypt  = "/v1/key/decrypt/"

	PathSecretCreate   = "/v1/secret/create/"
	PathSecretDescribe = "/v1/secret/describe/"
	PathSecretRead     = "/v1/secret/read/"
	PathSecretDelete   = "/v1/secret/delete/"
	PathSecretList     = "/v1/secret/list"

	PathPolicyCreate   = "/v1/policy/create/"
	PathPolicyAssign   = "/v1/policy/assign/"
	PathPolicyDescribe = "/v1/policy/describe/"
	PathPolicyRead     = "/v1/policy/read/"
	PathPolicyDelete   = "/v1/policy/delete/"
	PathPolicyList     = "/v1/policy/list/"

	PathIdentityCreate       = "/v1/identity/create/"
	PathIdentityDescribe     = "/v1/identity/describe/"
	PathIdentityList         = "/v1/identity/list/"
	PathIdentityDelete       = "/v1/identity/delete/"
	PathIdentitySelfDescribe = "/v1/identity/self/describe"
)

// API query parameters supported by KMS servers.
const (
	QueryReadyWrite = "write"

	QueryListContinue = "continue"
	QueryListLimit    = "limit"
)
