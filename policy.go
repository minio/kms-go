// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"net/http"
	"strings"
	"time"
)

// A Rule controls HTTP requests and is part of a policy.
type Rule struct{}

// A Policy represents a set of rules that determine whether an HTTP request
// is accepted or rejected. It consists of two sets of rules:
// allow rules and deny rules.
//
// If any rule from the deny set matches an incoming HTTP request, the request
// is rejected. Conversely, if any rule from the allow set matches, the request
// is accepted. If no rule matches, the request is also rejected.
// Therefore, an empty Policy, without any rules, rejects any request.
//
// A rule set is defined by a collection of API path patterns.
// An API path pattern consists of the KES server API path and an
// optional resource pattern. For example, "/v1/key/describe/my-key*"
// consists of the "/v1/key/describe" API path and the resource
// pattern "my-key*".
//
// When matching API path patterns:
//   - If the resource pattern does not end with an asterisk ('*') character,
//     the API path pattern only matches requests with an URL path equal to the pattern.
//   - If the resource pattern ends with an asterisk ('*') character,
//     the API path pattern matches if the API path pattern (without the asterisk) is a prefix of the URL path.
//
// An API path pattern cannot contain more than one asterisk character.
// API path patterns can be viewed as a subset of glob patterns.
//
// Here's an example defining a policy:
//
//	policy := Policy{
//	    Allow: map[string]kes.Rule{
//	        "/v1/status": {},
//	        "/v1/key/describe/my-key*": {},
//	        "/v1/key/generate/my-key*": {},
//	        "/v1/key/decrypt/my-key*": {},
//	    },
//	}
type Policy struct {
	Allow map[string]Rule // Set of allow rules
	Deny  map[string]Rule // Set of deny rules

	CreatedAt time.Time
	CreatedBy Identity
}

// Verify reports whether the given HTTP request is allowed.
// It returns no error if:
//
//	(1) No deny pattern matches the URL path *AND*
//	(2) At least one allow pattern matches the URL path.
//
// Otherwise, Verify returns ErrNotAllowed.
func (p *Policy) Verify(r *http.Request) error {
	for pattern := range p.Deny {
		if match(pattern, r.URL.Path) {
			return ErrNotAllowed
		}
	}
	for pattern := range p.Allow {
		if match(pattern, r.URL.Path) {
			return nil
		}
	}
	return ErrNotAllowed
}

// IsSubset reports whether the Policy p is a subset of o.
// If it is then any request allowed by p is also allowed
// by o and any request rejected by o is also rejected by p.
//
// Usually, p is a subset of o when it contains less or
// less generic allow rules and/or more or more generic
// deny rules.
//
// Two policies, A and B, are equivalent, but not necessarily
// equal, if:
//
//	A.IsSubset(B) && B.IsSubset(A)
func (p *Policy) IsSubset(o *Policy) bool {
	for allow := range p.Allow {

		// First, we check whether p's allow rule set
		// is a subset of o's allow rule set.
		var matched bool
		for pattern := range o.Allow {
			if matched = match(pattern, allow); matched {
				break
			}
		}
		if !matched {
			return false
		}

		// Next, we check whether one of p's allow rules
		// matches any of o's deny rules. If so, p would
		// allow something o denies unless p also contains
		// a deny rule equal or more generic than o's.
		for super := range o.Deny {
			if !match(allow, super) {
				continue
			}

			matched = false
			for deny := range p.Deny {
				if matched = match(deny, super); matched {
					break
				}
			}
			if !matched {
				return false
			}
		}
	}
	return true
}

// PolicyInfo describes a KES policy.
type PolicyInfo struct {
	Name      string    `json:"name"`                 // Name of the policy
	CreatedAt time.Time `json:"created_at,omitempty"` // Point in time when the policy was created
	CreatedBy Identity  `json:"created_by,omitempty"` // Identity that created the policy
}

func match(pattern, s string) bool {
	if pattern == "" {
		return false
	}

	if i := len(pattern) - 1; pattern[i] == '*' {
		return strings.HasPrefix(s, pattern[:i])
	}
	return s == pattern
}
