// Copyright 2026 Opsmate, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

// kdfHook, when non-nil, is invoked exactly once per key derivation, just
// before its iteration loop.  It exists so tests can observe whether a key
// derivation was attempted at all (and with how many iterations), proving
// that policy rejection happens before any expensive KDF work.
var kdfHook func(kind string, iterations int)

func observeKDF(kind string, iterations int) {
	if kdfHook != nil {
		kdfHook(kind, iterations)
	}
}
