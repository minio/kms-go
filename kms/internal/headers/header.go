// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

// Package headers defines common HTTP headers.
package headers

// Commonly used HTTP headers.
const (
	Accept           = "Accept"            // RFC 2616
	Authorization    = "Authorization"     // RFC 2616
	ETag             = "ETag"              // RFC 2616
	ContentType      = "Content-Type"      // RFC 2616
	ContentLength    = "Content-Length"    // RFC 2616
	ContentEncoding  = "Content-Encoding"  // RFC 2616 and 7231
	TransferEncoding = "Transfer-Encoding" // RFC 2616
)

// Commonly used HTTP headers for forwarding originating
// IP addresses of clients connecting through an reverse
// proxy or load balancer.
const (
	Forwarded     = "Forwarded"       // RFC 7239
	XForwardedFor = "X-Forwarded-For" // Non-standard
	XFrameOptions = "X-Frame-Options" // Non-standard
)

// Commonly used HTTP content type values.
const (
	ContentTypeAny       = "*/*"
	ContentTypeAppAny    = "application/*" // any application type, like json, octet-stream, ...
	ContentTypeBinary    = "application/octet-stream"
	ContentTypeJSON      = "application/json"
	ContentTypeJSONLines = "application/x-ndjson"
	ContentTypeText      = "text/plain"
	ContentTypeHTML      = "text/html"
)

// Commonly used HTTP content encoding values.
const (
	ContentEncodingGZIP = "gzip"
)
