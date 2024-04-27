// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

// Package pool provides a global buffer pool that,
// if used correctly, can significantly reduce memory
// allocations and GC preasure.
package pool

import (
	"sync"

	"aead.dev/mem"
)

// Get returns a pointer to a byte slice. Callers
// should return the buffer using Put once, and only
// if, the buffer is no longer used.
//
// Get may allocate a new slice when when no suitable
// one is available and the capacity of the return
// buffer may be greater than size. Callers that require
// a buffer with exactly size bytes may use:
//
//	p := pool.Get(size)
//	defer pool.Put(p)
//	buf := (*p)[:size]
//
// In general, this buffer pool is not designed to
// reduce large allocations. Instead, it should be
// used for buffers up to one megabyte. This, however,
// may change in the future.
func Get(size int) *[]byte {
	if i := bucket(size); i >= 0 && size >= 0 {
		return buckets[i].Get().(*[]byte)
	}

	b := make([]byte, size)
	return &b
}

// Put puts b pack into the pool. Callers must ensure
// that b is no longer used by anyone. Reading or
// writing to a returned buffer can cause data races
// and subtil bugs that may be hard to reproduce.
// Put does not guarantee that b is actually reused.
func Put(b *[]byte) {
	if b == nil {
		return
	}

	c := cap(*b)
	if c == 0 {
		return
	}
	if i := bucket(c); i >= 0 {
		buckets[i].Put(b)
	}
}

var buckets = [5]sync.Pool{
	{
		New: func() any {
			b := make([]byte, 128)
			return &b
		},
	},
	{
		New: func() any {
			b := make([]byte, 1*mem.KB)
			return &b
		},
	},
	{
		New: func() any {
			b := make([]byte, 8*mem.KiB)
			return &b
		},
	},
	{
		New: func() any {
			b := make([]byte, 64*mem.KiB)
			return &b
		},
	},
	{
		New: func() any {
			b := make([]byte, 1*mem.MiB)
			return &b
		},
	},
}

func bucket(size int) int {
	switch {
	case size <= 128:
		return 0
	case size <= int(1*mem.KiB):
		return 1
	case size <= int(8*mem.KiB):
		return 2
	case size <= int(64*mem.KiB):
		return 3
	case size <= int(1*mem.MiB):
		return 4
	default:
		return -1
	}
}
