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

	// ErrPolicyRejected is returned by the policy-aware decoding entry points
	// (e.g. [DecodeChainWithPolicy]) when the PFX uses an algorithm or parameter
	// that the supplied [Policy] does not permit, such as an OID that is not
	// allowed, a KDF iteration count at or beyond the configured limit, a salt
	// of an unsupported length, or a container larger than the configured size.
	ErrPolicyRejected = errors.New("pkcs12: algorithm or parameter rejected by policy")

	// ErrMalformedParameters is returned when an algorithm identifier carries
	// syntactically invalid parameters (e.g. an iteration count of zero or a
	// field with an unexpected ASN.1 type).
	ErrMalformedParameters = errors.New("pkcs12: malformed algorithm parameters")

	// ErrNegativeValue is returned when an algorithm parameter that must be
	// positive is encoded as a negative integer.
	ErrNegativeValue = errors.New("pkcs12: negative integer parameter")

	// ErrIntegerOverflow is returned when an algorithm parameter contains an
	// integer too large to be represented by the platform's int type.
	ErrIntegerOverflow = errors.New("pkcs12: integer parameter overflow")
)

// NotImplementedError indicates that the input is not currently supported.
type NotImplementedError string

func (e NotImplementedError) Error() string {
	return "pkcs12: " + string(e)
}
