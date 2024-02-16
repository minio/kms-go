// Copyright 2024 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kms

import (
	"encoding/json"
	"maps"
	"testing"
)

func TestRuleSet_Marshal(t *testing.T) {
	t.Parallel()

	for i, test := range marshalRuleSetTests {
		text, err := json.Marshal(test.Set)
		if err != nil {
			t.Fatalf("Test %d: failed to marshal RuleSet: %v", i, err)
		}

		if s := string(text); s != test.JSON {
			t.Fatalf("Test %d: JSON mismatch: got '%s' - want '%s'", i, s, test.JSON)
		}
	}
}

func TestRuleSet_Unmarshal(t *testing.T) {
	t.Parallel()

	for i, test := range unmarshalRuleSetTests {
		for _, JSON := range test.JSON {
			var set RuleSet
			err := json.Unmarshal([]byte(JSON), &set)
			if err == nil && test.ShouldFail {
				t.Fatalf("Test %d: should have failed to parse RuleSet JSON '%s'", i, JSON)
			}
			if err != nil && !test.ShouldFail {
				t.Fatalf("Test %d: failed to parse RuleSet JSON '%s': %v", i, JSON, err)
			}
			if test.ShouldFail {
				continue
			}
			if !maps.Equal(set, test.Set) {
				t.Fatalf("Test %d: RuleSet mismatch: got '%v' - want '%v'", i, set, test.Set)
			}
		}
	}
}

var marshalRuleSetTests = []struct {
	Set  RuleSet
	JSON string
}{
	{
		Set:  RuleSet{},
		JSON: `[]`,
	},
	{
		Set:  RuleSet{"my-key": {}},
		JSON: `"my-key"`,
	},
	{
		Set:  RuleSet{"my-key": {}, "foo": {}, "bar*": {}},
		JSON: `["foo","bar*","my-key"]`,
	},
	{
		Set:  RuleSet{"my-key": {}, "foo": {}, "bar": {}},
		JSON: `["bar","foo","my-key"]`,
	},
}

var unmarshalRuleSetTests = []struct {
	JSON       []string // List of JSON representations equal to Set
	Set        RuleSet
	ShouldFail bool
}{
	{
		JSON: []string{`""`, `[]`, `{}`},
		Set:  RuleSet{},
	},
	{
		JSON: []string{`"my-key"`, `["my-key"]`, `{"my-key":{}}`},
		Set:  RuleSet{"my-key": {}},
	},
	{
		JSON: []string{`"my-*"`, `["my-*"]`, `{"my-*":{}}`},
		Set:  RuleSet{"my-*": {}},
	},
	{
		JSON: []string{`["my-key", ""]`, `{"my-key":{}, "": {}}`},
		Set:  RuleSet{"my-key": {}},
	},
	{
		JSON: []string{`["my-key", "foo", "bar*"]`, `{"my-key":{}, "foo": {}, "bar*": {}}`},
		Set:  RuleSet{"my-key": {}, "foo": {}, "bar*": {}},
	},
}
