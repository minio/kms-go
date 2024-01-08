// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package api

const (
	PathStatus = "/v1/status"

	PathEnclaveCreate   = "/v1/enclave/create/"
	PathEnclaveDescribe = "/v1/enclave/describe/"
	PathEnclaveDelete   = "/v1/enclave/delete/"
	PathEnclaveList     = "/v1/enclave/list/"

	PathSecretKeyCreate   = "/v1/key/create/"
	PathSecretKeyDescribe = "/v1/key/describe/"
	PathSecretKeyDelete   = "/v1/key/delete/"
	PathSecretKeyList     = "/v1/key/list/"
	PathSecretKeyGenerate = "/v1/key/generate/"
	PathSecretKeyEncrypt  = "/v1/key/encrypt/"
	PathSecretKeyDecrypt  = "/v1/key/decrypt/"

	PathPolicyCreate   = "/v1/policy/create/"
	PathPolicyAssign   = "/v1/policy/assign/"
	PathPolicyDescribe = "/v1/policy/describe/"
	PathPolicyRead     = "/v1/policy/read/"
	PathPolicyDelete   = "/v1/policy/delete/"
	PathPolicyList     = "/v1/policy/list/"

	PathIdentityCreate   = "/v1/identity/create/"
	PathIdentityIssue    = "/v1/identity/issue"
	PathIdentityDescribe = "/v1/identity/describe/"
	PathIdentityDelete   = "/v1/identity/delete/"
	PathIdentityList     = "/v1/identity/list/"

	PathClusterStatus  = "/v1/cluster/status"
	PathClusterAdd     = "/v1/cluster/add/"
	PathClusterRemove  = "/v1/cluster/remove/"
	PathClusterBackup  = "/v1/cluster/backup"
	PathClusterRestore = "/v1/cluster/restore"
	PathClusterEdit    = "/v1/cluster/edit"
)

// API query parameters supported by KMS servers.
const (
	QueryListContinue = "continue"
	QueryListLimit    = "limit"
)
