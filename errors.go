// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import "errors"

var (
	// ErrDecryption represents a failure to decrypt the input.
	ErrDecryption = errors.New("pkcs12: decryption error, incorrect padding")

	// ErrIncorrectPassword is returned when an incorrect password is detected.
	// Usually, P12/PFX data is signed to be able to verify the password.
	ErrIncorrectPassword = errors.New("pkcs12: decryption password incorrect")

	// ErrIntegrity is returned when the MAC integrity check of a PFX fails,
	// either because the integrity password is wrong or because the data has
	// been corrupted or tampered with.  It is distinct from
	// ErrIncorrectPassword so callers can tell an integrity failure apart
	// from a failed attempt to decrypt an individual safe bag.
	ErrIntegrity = errors.New("pkcs12: integrity check failed")

	// ErrNoPassword is returned when no password was provided for an
	// encryption layer that must be unlocked before decoding can proceed,
	// such as the outer integrity check of a PFX.
	ErrNoPassword = errors.New("pkcs12: no password provided")
)

// NotImplementedError indicates that the input is not currently supported.
type NotImplementedError string

func (e NotImplementedError) Error() string {
	return "pkcs12: " + string(e)
}
