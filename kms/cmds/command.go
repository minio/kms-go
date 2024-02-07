// Copyright 2024 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package cmds

import (
	"errors"
	"strconv"
	"strings"
)

const (
	ClusterAddNode    Command = 1
	ClusterRemoveNode Command = 2
	ClusterStatus     Command = 3
	ClusterEdit       Command = 4

	EnclaveCreate Command = 101
	EnclaveDelete Command = 102
	EnclaveStatus Command = 103
	EnclaveList   Command = 104

	KeyCreate       Command = 201
	KeyDelete       Command = 202
	KeyImport       Command = 203
	KeyStatus       Command = 204
	KeyEncrypt      Command = 205
	KeyDecrypt      Command = 206
	KeyGenerate     Command = 207
	KeyList         Command = 208
	KeyListVersions Command = 209

	PolicyCreate Command = 301
	PolicyDelete Command = 302
	PolicyAssign Command = 303
	PolicyGet    Command = 304
	PolicyStatus Command = 305
	PolicyList   Command = 306

	IdentityCreate Command = 401
	IdentityDelete Command = 402
	IdentityGet    Command = 403
	IdentityList   Command = 404
)

func Parse(s string) (Command, error) {
	c, ok := textCmds[strings.ToUpper(s)]
	if !ok {
		return 0, errors.New("kms: invalid cmd '" + s + "'")
	}
	return c, nil
}

type Command uint16

// IsWrite reports whether c changes state on the server.
//
// A server may choose to not accept multiple commands within
// a single request that do and do not change the server's
// state, and instead, requires that clients either send
// "read-only" or "write-only" commands.
func (c Command) IsWrite() bool {
	_, ok := isWrite[c]
	return ok
}

func (c Command) String() string {
	s, ok := cmdTexts[c]
	if !ok {
		return "!INVALID:" + strconv.Itoa(int(c))
	}
	return s
}

func (c Command) MarshalText() ([]byte, error) {
	s, ok := cmdTexts[c]
	if !ok {
		return nil, errors.New("kms: invalid cmd '" + strconv.Itoa(int(c)) + "'")
	}
	return []byte(s), nil
}

func (c Command) AppendText(b []byte) ([]byte, error) {
	s, ok := cmdTexts[c]
	if !ok {
		return nil, errors.New("kms: invalid cmd '" + strconv.Itoa(int(c)) + "'")
	}
	return append(b, s...), nil
}

func (c *Command) UnmarshalText(text []byte) error {
	v, err := Parse(string(text))
	if err != nil {
		return err
	}

	*c = v
	return nil
}

var isWrite = map[Command]struct{}{ // Commands that change state on a KMS server
	ClusterAddNode:    {},
	ClusterRemoveNode: {},
	ClusterEdit:       {},

	EnclaveCreate: {},
	EnclaveDelete: {},

	KeyCreate: {},
	KeyDelete: {},
	KeyImport: {},

	PolicyCreate: {},
	PolicyDelete: {},
	PolicyAssign: {},

	IdentityCreate: {},
	IdentityDelete: {},
}

var cmdTexts = map[Command]string{
	ClusterAddNode:    "CLUSTER:ADDNODE",
	ClusterRemoveNode: "CLUSTER:REMOVENODE",
	ClusterStatus:     "CLUSTER:STATUS",
	ClusterEdit:       "CLUSTER:EDIT",

	EnclaveCreate: "ENCLAVE:CREATE",
	EnclaveDelete: "ENCLAVE:DELETE",
	EnclaveStatus: "ENCLAVE:STATUS",
	EnclaveList:   "ENCLAVE:LIST",

	KeyCreate:       "KEY:CREATE",
	KeyDelete:       "KEY:DELETE",
	KeyStatus:       "KEY:STATUS",
	KeyEncrypt:      "KEY:ENCRYPT",
	KeyDecrypt:      "KEY:DECRYPT",
	KeyGenerate:     "KEY:GENERATE",
	KeyList:         "KEY:LIST",
	KeyListVersions: "KEY:LISTVERSIONS",

	PolicyCreate: "POLICY:CREATE",
	PolicyDelete: "POLICY:DELETE",
	PolicyAssign: "POLICY:ASSIGN",
	PolicyGet:    "POLICY:GET",
	PolicyStatus: "POLICY:STATUS",
	PolicyList:   "POLICY:LIST",

	IdentityCreate: "IDENTITY:CREATE",
	IdentityDelete: "IDENTITY:DELETE",
	IdentityGet:    "IDENTITY:STATUS",
	IdentityList:   "IDENTITY:LIST",
}

var textCmds = map[string]Command{
	"CLUSTER:ADDNODE":    ClusterAddNode,
	"CLUSTER:REMOVENODE": ClusterRemoveNode,
	"CLUSTER:STATUS":     ClusterStatus,
	"CLUSTER:EDIT":       ClusterEdit,

	"ENCLAVE:CREATE": EnclaveCreate,
	"ENCLAVE:DELETE": EnclaveDelete,
	"ENCLAVE:STATUS": EnclaveStatus,
	"ENCLAVE:LIST":   EnclaveList,

	"KEY:CREATE":       KeyCreate,
	"KEY:DELETE":       KeyDelete,
	"KEY:STATUS":       KeyStatus,
	"KEY:ENCRYPT":      KeyEncrypt,
	"KEY:DECRYPT":      KeyDecrypt,
	"KEY:GENERATE":     KeyGenerate,
	"KEY:LIST":         KeyList,
	"KEY:LISTVERSIONS": KeyListVersions,

	"POLICY:CREATE": PolicyCreate,
	"POLICY:DELETE": PolicyDelete,
	"POLICY:ASSIGN": PolicyAssign,
	"POLICY:GET":    PolicyGet,
	"POLICY:STATUS": PolicyStatus,
	"POLICY:LIST":   PolicyList,

	"IDENTITY:CREATE": IdentityCreate,
	"IDENTITY:DELETE": IdentityDelete,
	"IDENTITY:STATUS": IdentityGet,
	"IDENTITY:LIST":   IdentityList,
}
