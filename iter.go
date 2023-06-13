// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sort"
)

// ListIter is a struct that represents an iterator over a paginated list
// of items. It is generic over some item type T.
type ListIter[T any] struct {
	// NextFunc is a function that retrieves the next batch of items
	// from the paginated list. It takes a context, a token to continue
	// from, and the maximum number of items to fetch. It returns the
	// fetched items, a token to continue from for the next batch, and
	// any error encountered.
	NextFunc func(context.Context, string, int) ([]T, string, error)

	items      []T
	continueAt string
	err        error
}

// SeekTo seeks to a specific position in the paginated list. It updates the
// iterator's state to start fetching items from the specified prefix and returns
// the subsequent item.
//
// If the iterator has encountered an error previously, it returns the error
// without modifying the state. It returns io.EOF when seeking beyond the end
// of the list.
func (i *ListIter[T]) SeekTo(ctx context.Context, prefix string) (item T, err error) {
	if i.err != nil && i.err != io.EOF {
		return item, i.err
	}
	i.continueAt = prefix

	// Clear the items slice and err to start fetching new items.
	i.items = []T{}
	i.err = nil

	// Fetch the next item after seeking to the specified prefix.
	item, err = i.Next(ctx)
	return
}

// Next retrieves the next item from the paginated list. It uses
// the provided context when fetching the next page. If the
// ListIter has encountered an error previously or reached the end
// of the list, it returns the encountered error or io.EOF.
func (i *ListIter[T]) Next(ctx context.Context) (item T, err error) {
	if len(i.items) == 0 {
		if i.err != nil {
			return item, i.err
		}

		i.items, i.continueAt, i.err = i.NextFunc(ctx, i.continueAt, -1)
		if i.err != nil {
			i.items = nil
			return item, i.err
		}

		if len(i.items) == 0 {
			i.err = io.EOF
			return item, i.err
		}

		// If the continueAt field is empty, it means we have reached the end of the list.
		if i.continueAt == "" {
			i.err = io.EOF
		}
	}

	// Retrieve and return the next item from the fetched batch.
	item = i.items[0]
	i.items = i.items[1:]

	return item, nil
}

func parseLegacyListing(body io.Reader, n int) ([]string, string, error) {
	type Response struct {
		Name  string `json:"name"`
		Error string `json:"error"`
	}

	scanner := bufio.NewScanner(body)
	var (
		names []string
		count int
	)
	for scanner.Scan() {
		var r Response
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			return nil, "", err
		}
		if r.Error != "" {
			return nil, "", errors.New(r.Error)
		}

		names = append(names, r.Name)
		count++
		if count == n {
			break
		}
	}
	sort.Strings(names)
	return names, "", nil
}

func parseLegacyIdentityListing(body io.Reader, n int) ([]Identity, string, error) {
	type Response struct {
		Identity Identity `json:"identity"`
		Error    string   `json:"error"`
	}

	scanner := bufio.NewScanner(body)
	var (
		names []Identity
		count int
	)
	for scanner.Scan() {
		var r Response
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			return nil, "", err
		}
		if r.Error != "" {
			return nil, "", errors.New(r.Error)
		}

		names = append(names, r.Identity)
		count++
		if count == n {
			break
		}
	}
	return names, "", nil
}
