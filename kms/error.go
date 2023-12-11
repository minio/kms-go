// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kms

import (
	"bytes"
	"io"
	"net/http"
	"strings"

	"aead.dev/mem"
	"github.com/minio/kms-go/kms/internal/headers"
	pb "github.com/minio/kms-go/kms/protobuf"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// MinIO KMS API errors.
var (
	// ErrPermission is returned when the client has insufficient permissions
	// for performing the tried operation. For example, policy associated to the
	// client's identity may not allow or even deny the request or the client
	// may try to perform an admin operation without admin permissions.
	ErrPermission = Error{http.StatusForbidden, "access denied: insufficient permissions"}

	// ErrEnclaveExists is returned when trying to create an enclave
	// that already exists.
	ErrEnclaveExists = Error{http.StatusConflict, "enclave already exists"}

	// ErrEnclaveNotFound is returned when trying to operate within
	// an enclave that does not exist. For example, when trying to
	// create a key in a non-existing enclave.
	ErrEnclaveNotFound = Error{http.StatusNotFound, "enclave does not exist"}

	// ErrKeyExists is returned when trying to create a key in an
	// enclave that already contains a key with the same name.
	ErrKeyExists = Error{http.StatusConflict, "key already exists"}

	// ErrKeyNotFound is returned when trying to use a key that
	// that does not exist.
	ErrKeyNotFound = Error{http.StatusNotFound, "key does not exist"}

	// ErrPolicyNotFound is returned when trying to fetch or delete a policy
	// that does not exist.
	ErrPolicyNotFound = Error{http.StatusNotFound, "policy does not exist"}
)

// Error is a KMS API error.
type Error struct {
	Code int    // The HTTP response status code
	Err  string // The error message
}

// Status returns the Error's HTTP response status code.
func (e Error) Status() int { return e.Code }

// Error returns the Error's error string.
func (e Error) Error() string { return e.Err }

// readError returns the Error it reads from the response body.
func readError(resp *http.Response) Error {
	const MaxSize = 5 * mem.KB

	size := mem.Size(resp.ContentLength)
	if size <= 0 || size > MaxSize {
		size = MaxSize
	}
	body := mem.LimitReader(resp.Body, size)

	if ct := resp.Header.Get(headers.ContentType); ct == headers.ContentTypeBinary || ct == headers.ContentTypeJSON {
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(body); err != nil {
			return Error{Code: resp.StatusCode, Err: err.Error()}
		}

		var response pb.ErrResponse
		if ct == headers.ContentTypeBinary {
			if err := proto.Unmarshal(buf.Bytes(), &response); err != nil {
				return Error{Code: resp.StatusCode, Err: err.Error()}
			}
		} else {
			if err := protojson.Unmarshal(buf.Bytes(), &response); err != nil {
				return Error{Code: resp.StatusCode, Err: err.Error()}
			}
		}
		return Error{Code: resp.StatusCode, Err: response.Message}
	}

	var sb strings.Builder
	if _, err := io.Copy(&sb, body); err != nil {
		return Error{Code: resp.StatusCode, Err: err.Error()}
	}
	return Error{Code: resp.StatusCode, Err: sb.String()}
}
