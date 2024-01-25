// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kms

import (
	"bytes"
	"fmt"
	"io"
	"net"
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

	// ErrIdentityNotFound is returned when trying to access or delete a identity
	// that does not exist.
	ErrIdentityNotFound = Error{http.StatusNotFound, "identity does not exist"}

	// ErrDecrypt is returned when trying to decrypt an invalid or modified
	// ciphertext or when the wrong key is used for decryption.
	ErrDecrypt = Error{http.StatusBadRequest, "invalid ciphertext"}
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

// HostError captures an error returned by a host.
// It implements the net.Error interface.
type HostError struct {
	Host string // The host for which an operation failed
	Err  error  // The underlying error
}

var _ net.Error = (*HostError)(nil) // compiler check

// Error returns the underlying error message prefixed by the host.
func (e *HostError) Error() string { return fmt.Sprintf("%q: %s", e.Host, e.Err.Error()) }

// Unwrap returns the underlying error.
func (e *HostError) Unwrap() error { return e.Err }

// Timeout reports whether the error s caused by a timeout.
func (e *HostError) Timeout() bool {
	t, ok := e.Err.(interface {
		Timeout() bool
	})
	return ok && t.Timeout()
}

// Temporary reports whether the error is temporary.
//
// Deprecated: Temporary errors are not well-defined.
// It is only there to satisfy the net.Error interface.
func (e *HostError) Temporary() bool {
	t, ok := e.Err.(interface {
		Temporary() bool
	})
	return ok && t.Temporary()
}
