// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kms

import (
	"context"
	"io"
)

// Iter is an iterator over elements of type T. It turns
// a paginated listing provided by the NextFn into a
// continuous stream of items.
type Iter[T any] struct {
	// NextFn is a function that returns the next page from
	// a paginated list.
	NextFn func(context.Context, *ListRequest) (*Page[T], error)

	items      []T
	enclave    string
	prefix     string
	continueAt string
	limit      int
	err        error
}

// SeekTo seeks to a specific position within the stream and returns the item
// at this position.
func (i *Iter[T]) SeekTo(ctx context.Context, req *ListRequest) (item T, err error) {
	if i.err != nil && i.err != io.EOF {
		return item, i.err
	}

	i.enclave = req.Enclave
	i.prefix = req.Prefix
	i.continueAt = req.ContinueAt
	i.limit = req.Limit

	i.items, i.err = nil, nil
	return i.Next(ctx)
}

// Next returns the next item from the stream or io.EOF at the end.
// The context is used when Next has to fetch the next page of the
// paginated listing.
func (i *Iter[T]) Next(ctx context.Context) (item T, err error) {
	if len(i.items) == 0 {
		if i.err != nil {
			return item, i.err
		}

		resp, err := i.NextFn(ctx, &ListRequest{
			Enclave:    i.enclave,
			Prefix:     i.prefix,
			ContinueAt: i.continueAt,
			Limit:      i.limit,
		})
		if err != nil {
			i.err = err
			i.items = nil
			return item, i.err
		}

		i.items, i.continueAt = resp.Items, resp.ContinueAt
		if len(i.items) == 0 {
			i.err = io.EOF
			return item, i.err
		}
		if i.continueAt == "" {
			i.err = io.EOF
		}
	}

	item = i.items[0]
	i.items = i.items[1:]
	return item, nil
}
