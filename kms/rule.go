// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kms

import (
	"cmp"
	"encoding/json"
	"slices"

	pb "github.com/minio/kms-go/kms/protobuf"
)

// Rule is a policy rule allowing for more fine-grain
// API access control.
type Rule struct{}

// A RuleSet is a set of patterns and their associated rules.
// It defines which rule should be applied when an argument
// matches a pattern.
//
// For example, the RuleSet {"my-key*": {}} applies the empty
// Rule, one without any restrictions, whenever a request or
// command argument matches the "my-key*" pattern.
//
// The RuleSet is the building block for KMS policies. Such a
// policy defines which RuleSet is applied for which KMS
// commands. For example, the RuleSet from above may be used
// for the CreateKey command. In this case, the policy would
// allow the creation of keys if and only if the key name
// would match the "my-key*" pattern.
//
// A RuleSet can be represented as protobuf message or JSON
// object. Usually, policies are defined in JSON to be human
// readable. For ease of use, a RuleSet can not just be
// represented as JSON object but also as JSON array or JSON
// string if the RuleSet contains just a single entry. For
// example the following to JSON documents are decoded into
// equal RuleSets:
//
//  1. RuleSet as JSON object:
//
//     {
//     "my-key*": {},
//     }
//
//  2. RuleSet as JSON array:
//
//     ["my-key*"]
//
//  3. RuleSet as JSON string:
//
//     "my-key*"
//
// The 2nd and 3rd forms are shorter and easier to read than the
// 1st one. However, the 1st one more accurately represenets the
// RuleSet's in memory representation and allows future extensions.
type RuleSet map[string]Rule

// MarshalPB converts the RuleSet into its protobuf representation.
func (r *RuleSet) MarshalPB(v *pb.RuleSet) error {
	rs := *r

	v.Rules = make(map[string]*pb.Rule, len(rs))
	for pattern := range rs {
		if pattern == "" {
			continue
		}
		v.Rules[pattern] = &pb.Rule{}
	}
	return nil
}

// UnmarshalPB initializes the RuleSet from its protobuf representation.
func (r *RuleSet) UnmarshalPB(v *pb.RuleSet) error {
	*r = make(RuleSet, len(v.Rules))

	rs := *r
	for pattern := range v.Rules {
		if pattern == "" {
			continue
		}
		rs[pattern] = Rule{}
	}
	return nil
}

// MarshalJSON returns the RuleSet's JSON representation.
//
// If the RuleSet contains only empty Rules, or no Rules,
// MarshalJSON returns a list of the RuleSet's patterns
// as JSON array.
//
// Otherwise, it returns a JSON object with each pattern
// being a key and the JSON representation of the
// corresponding Rule the associated value.
func (r RuleSet) MarshalJSON() ([]byte, error) {
	if len(r) == 0 {
		return []byte{'[', ']'}, nil
	}

	var (
		empty   = Rule{}
		hasRule bool
	)
	for _, rule := range r {
		if rule != empty {
			hasRule = true
			break
		}
	}
	if !hasRule {
		if len(r) == 1 {
			for pattern := range r {
				return json.Marshal(pattern)
			}
		}

		patterns := make([]string, 0, len(r))
		for pattern := range r {
			patterns = append(patterns, pattern)
		}
		slices.SortFunc(patterns, func(a, b string) int {
			if n := len(a) - len(b); n != 0 {
				return n
			}
			return cmp.Compare(a, b)
		})
		return json.Marshal(patterns)
	}
	return json.Marshal(map[string]Rule(r))
}

// UnmarshalJSON initializes the RuleSet from its JSON
// representation. UnmarshalJSON is able to decode RuleSet
// JSON objects produced by MarshalJSON. Therefore, b may
// be an array of patterns as strings or a JSON object
// containing the patterns as strings and the Rules as
// JSON objects.
func (r *RuleSet) UnmarshalJSON(b []byte) error {
	if n := len(b); n >= 2 && b[0] == '"' && b[n-1] == '"' {
		var pattern string
		if err := json.Unmarshal(b, &pattern); err != nil {
			return err
		}
		if pattern == "" {
			*r = RuleSet{}
		} else {
			*r = RuleSet{pattern: {}}
		}
		return nil
	}
	if n := len(b); n >= 2 && b[0] == '[' && b[n-1] == ']' {
		var patterns []string
		if err := json.Unmarshal(b, &patterns); err != nil {
			return err
		}

		m := make(RuleSet, len(patterns))
		for _, pattern := range patterns {
			if pattern != "" {
				m[pattern] = Rule{}
			}
		}
		*r = m
		return nil
	}

	m := map[string]Rule{}
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	for pattern := range m {
		if pattern == "" {
			delete(m, pattern)
		}
	}
	*r = RuleSet(m)
	return nil
}
