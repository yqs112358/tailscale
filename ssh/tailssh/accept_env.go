// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tailssh

import (
	"slices"
	"strings"
)

// filterEnv filters a passed in environ string slice (a slice with strings
// representing environment variables in the form "key=value") based on
// the supplied slice of acceptEnv values.
//
// acceptEnv is a slice of environment variable names that are allowlisted
// for the SSH rule in the policy file.
//
// acceptEnv values may contain * and ? wildcard characters which match against
// an arbitrary number of characters or a single character respectively.
func filterEnv(acceptEnv []string, environ []string) []string {
	var acceptedPairs []string

	for _, envPair := range environ {
		envVar := strings.Split(envPair, "=")[0]

		// Short circuit if we have a direct match between the environment
		// variable and an AcceptEnv value.
		if slices.Contains(acceptEnv, envVar) {
			acceptedPairs = append(acceptedPairs, envPair)
			continue
		}

		// Otherwise check if we have a wildcard pattern that matches.
		if matchAcceptEnv(acceptEnv, envVar) {
			acceptedPairs = append(acceptedPairs, envPair)
			continue
		}
	}

	return acceptedPairs
}

// matchAcceptEnv is a convenience function that wraps calling matchPattern
// with every value in acceptEnv for a given env that is being matched against.
func matchAcceptEnv(acceptEnv []string, env string) bool {
	for _, pattern := range acceptEnv {
		if matchPattern(pattern, env) {
			return true
		}
	}

	return false
}

// matchPattern returns true if the pattern matches against the target string.
// Patterns may include * and ? wildcard characters which match against an
// arbitrary number of characters or a single character respectively.
func matchPattern(pattern string, target string) bool {
	patternIdx := 0
	targetIdx := 0
	matchingAsterisk := false

	for targetIdx < len(target) {
		// If we are at the end of the pattern but not the end of the target,
		// the only case where we have a match is if we are currently
		// matching against an asterisk.
		if patternIdx == len(pattern) {
			return matchingAsterisk
		}

		if pattern[patternIdx] == '?' || pattern[patternIdx] == target[targetIdx] {
			patternIdx++
			targetIdx++
			continue
		}

		if pattern[patternIdx] == '*' {
			patternIdx++
			// Optimization to skip through any repeated asterisks as they
			// have the same net effect on our search.
			for patternIdx < len(pattern) {
				if pattern[patternIdx] != '*' {
					break
				}

				patternIdx++
			}
			matchingAsterisk = true
			continue
		}

		if matchingAsterisk {
			// We want to find increase the index in the target string
			// until we find the next character in the pattern in the match
			// case, or until we hit the end of the target in the non-match case.
			targetIdx++
			if targetIdx < len(target) && target[targetIdx] == pattern[patternIdx] {
				patternIdx++
				targetIdx++
				matchingAsterisk = false
			}
		} else {
			// Failed to find match.
			return false
		}
	}

	// We've reached both the end of the pattern and the end of the target,
	// implying that we have successfully matched.
	if patternIdx == len(pattern) {
		return true
	}

	return false
}
