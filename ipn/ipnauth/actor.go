// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnauth

import (
	"fmt"

	"tailscale.com/ipn"
	"tailscale.com/util/rands"
)

// Actor is any actor using the [ipnlocal.LocalBackend].
//
// It typically represents a specific OS user, indicating that an operation
// is performed on behalf of this user, should be evaluated against their
// access rights, and performed in their security context when applicable.
type Actor interface {
	// UserID returns an OS-specific UID of the user represented by the receiver,
	// or "" if the actor does not represent a specific user on a multi-user system.
	// As of 2024-08-27, it is only used on Windows.
	UserID() ipn.WindowsUserID
	// Username returns the user name associated with the receiver,
	// or "" if the actor does not represent a specific user.
	Username() (string, error)

	// IsLocalSystem reports whether the actor is the Windows' Local System account.
	//
	// Deprecated: this method exists for compatibility with the current (as of 2024-08-27)
	// permission model and will be removed as we progress on tailscale/corp#18342.
	IsLocalSystem() bool

	// IsLocalAdmin reports whether the actor has administrative access to the
	// local machine, for whatever that means with respect to the current OS.
	//
	// The operatorUID is only used on Unix-like platforms and specifies the ID
	// of a local user (in the os/user.User.Uid string form) who is allowed to
	// operate tailscaled without being root or using sudo.
	//
	// Deprecated: this method exists for compatibility with the current (as of 2024-08-27)
	// permission model and will be removed as we progress on tailscale/corp#18342.
	IsLocalAdmin(operatorUID string) bool
}

// ActorCloser is an optional interface that might be implemented by an [Actor]
// that must be closed when done to release the resources.
type ActorCloser interface {
	// Close releases resources associated with the receiver.
	Close() error
}

// SessionID is an opaque, comparable value used to identify a logical [Session].
type SessionID struct {
	v any
}

type uniqueID struct {
	p *byte
	s string
}

// NewSessionID returns a new process-unique [SessionID].
func NewSessionID() SessionID {
	// We use both a byte pointer and a random hex string out of paranoia that
	// eventually we may use a SessionID in a context where 64 bits of entropy
	// of the hex string is not enough. The string is nice for debugging and logging,
	// but the pointer guarantees uniqueness of the ID within the address space
	// of a given process.
	return SessionID{uniqueID{new(byte), rands.HexString(16)}}
}

// SessionIDFrom returns a new [SessionID] derived from the specified value.
// SessionIDs derived from equal values are equal.
func SessionIDFrom[T comparable](v T) SessionID {
	return SessionID{v}
}

// String implements [fmt.Stringer].
func (id SessionID) String() string {
	if id.v == nil {
		return "(none)"
	}
	return fmt.Sprint(id.v)
}

func (id uniqueID) String() string {
	return id.s
}

// Session is an optional interface that an [Actor] might implement to link a
// series of related interactions with the LocalAPI by a [SessionID].
// It doesn't necessarily correspond to the same [net.Conn] or any physical session.
// For example, all interactions with the same client process, if one is known,
// could be considered part of the same session.
type Session interface {
	// SessionID returns a unique comparable ID associated with the session.
	SessionID() SessionID
}
