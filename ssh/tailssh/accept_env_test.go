// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tailssh

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestMatchPattern(t *testing.T) {
	testCases := []struct {
		pattern string
		target  string
		match   bool
	}{
		// Positive cases
		{pattern: "*", target: "EXAMPLE_ENV", match: true},
		{pattern: "?", target: "A", match: true},
		{pattern: "?*", target: "EXAMPLE_2", match: true},
		{pattern: "??", target: "CC", match: true},
		{pattern: "?*?", target: "ABCDEFG", match: true},
		{pattern: "*?*", target: "ABCDEFG", match: true},
		{pattern: "***", target: "123456", match: true},
		{pattern: "**?TEST", target: "_TEST", match: true},
		{pattern: "TEST**?", target: "TEST_", match: true},
		{pattern: "TEST_*", target: "TEST_A", match: true},
		{pattern: "EXAMPLE_?_ENV", target: "EXAMPLE_A_ENV", match: true},
		{pattern: "EXAMPLE_*_ENV", target: "EXAMPLE_aBcd2231---_ENV", match: true},
		{pattern: "COMPLICA?ED_PATTERN*", target: "COMPLICATED_PATTERN_REST", match: true},
		{pattern: "COMPLICAT???ED_PATT??ERN", target: "COMPLICAT123ED_PATTggERN", match: true},
		{pattern: "DIRECT_MATCH", target: "DIRECT_MATCH", match: true},

		// Negative cases
		{pattern: "?", target: "123", match: false},
		{pattern: "??", target: "123", match: false},
		{pattern: "?*?", target: "A", match: false},
		{pattern: "*?*", target: "C", match: false},
		{pattern: "**?TEST", target: "ABC", match: false},
		{pattern: "TEST**?", target: "OTHER", match: false},
		{pattern: "TEST_*", target: "TEST", match: false},
		{pattern: "EXAMPLE_?_ENV", target: "EXAMPLE_ENV", match: false},
		{pattern: "EXAMPLE_*_ENV", target: "EXAMPLEENV", match: false},
		{pattern: "COMPLICA?ED_PATTERN*", target: "COMPLICATED_PATT", match: false},
		{pattern: "COMPLICAT???ED_PATT??ERN", target: "COMPLICATED_PATTERN", match: false},
		{pattern: "DIRECT_MATCH", target: "MISS", match: false},
	}

	for _, tc := range testCases {
		name := fmt.Sprintf("pattern_%s_target_%s", tc.pattern, tc.target)
		if tc.match {
			name += "_should_match"
		} else {
			name += "_should_not_match"
		}

		t.Run(name, func(t *testing.T) {
			match := matchPattern(tc.pattern, tc.target)
			if match != tc.match {
				t.Errorf("got %v, want %v", match, tc.match)
			}
		})
	}
}

func TestFilterEnv(t *testing.T) {
	testCases := []struct {
		name             string
		acceptEnv        []string
		environ          []string
		expectedFiltered []string
	}{
		{
			name:             "simple direct matches",
			acceptEnv:        []string{"FOO", "FOO2", "FOO_3"},
			environ:          []string{"FOO=BAR", "FOO2=BAZ", "FOO_3=123", "FOOOO4-2=AbCdEfG"},
			expectedFiltered: []string{"FOO=BAR", "FOO2=BAZ", "FOO_3=123"},
		},
		{
			name:             "bare wildcard",
			acceptEnv:        []string{"*"},
			environ:          []string{"FOO=BAR", "FOO2=BAZ", "FOO_3=123", "FOOOO4-2=AbCdEfG"},
			expectedFiltered: []string{"FOO=BAR", "FOO2=BAZ", "FOO_3=123", "FOOOO4-2=AbCdEfG"},
		},
		{
			name:             "complex matches",
			acceptEnv:        []string{"FO?", "FOOO*", "FO*5?7"},
			environ:          []string{"FOO=BAR", "FOO2=BAZ", "FOO_3=123", "FOOOO4-2=AbCdEfG", "FO1-kmndGamc79567=ABC", "FO57=BAR2"},
			expectedFiltered: []string{"FOO=BAR", "FOOOO4-2=AbCdEfG", "FO1-kmndGamc79567=ABC"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			filtered := filterEnv(tc.acceptEnv, tc.environ)
			if diff := cmp.Diff(tc.expectedFiltered, filtered); diff != "" {
				t.Errorf("unexpected filter result (-got,+want): \n%s", diff)
			}
		})
	}
}
