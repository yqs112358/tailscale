// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package usermetric provides a container and handler
// for user-facing metrics.
package usermetric

import (
	"expvar"
	"net/http"

	"tailscale.com/metrics"
	"tailscale.com/tsweb/varz"
)

var vars expvar.Map

// NewMultiLabelMap creates and register a new
// MultiLabelMap[T] variable with the given name and returns it.
// The variable is registered with the userfacing metrics package.
//
// Note that usermetric are not protected against duplicate
// metrics name. It is the caller's responsibility to ensure that
// the name is unique.
func NewMultiLabelMap[T comparable](name string, promType, helpText string) *metrics.MultiLabelMap[T] {
	m := &metrics.MultiLabelMap[T]{
		Type: promType,
		Help: helpText,
	}
	var zero T
	_ = metrics.LabelString(zero) // panic early if T is invalid
	vars.Set(name, m)
	return m
}

// NewMap creates and register a new
// Map variable with the given name and returns it.
//
// Note that usermetric are not protected against duplicate
// metrics name. It is the caller's responsibility to ensure that
// the name is unique.
func NewMap(name string, promType, helpText string) *metrics.MultiLabelMap[struct{}] {
	m := &metrics.MultiLabelMap[struct{}]{
		Type: promType,
		Help: helpText,
	}
	vars.Set(name, m)
	return m
}

// Handler returns a varz.Handler that serves the userfacing expvar contained
// in this package.
func Handler(w http.ResponseWriter, r *http.Request) {
	varz.ExpvarDoHandler(vars.Do)(w, r)
}
