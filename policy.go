// Copyright 2026 Opsmate, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

var (
	// ErrPolicyRejected is returned by the policy-aware decoding entry points
	// (DecodeWithPolicy, DecodeChainWithPolicy, and DecodeTrustStoreWithPolicy)
	// when the PFX uses a parameter that the Policy does not allow.
	ErrPolicyRejected = errors.New("pkcs12: rejected by policy")

	// ErrIntegerOverflow is returned by the policy-aware decoding entry points
	// when an ASN.1 INTEGER parameter (such as an iteration count) cannot be
	// represented on the current platform.
	ErrIntegerOverflow = errors.New("pkcs12: integer parameter overflow")

	// ErrNegativeValue is returned by the policy-aware decoding entry points
	// when an ASN.1 INTEGER parameter that must be non-negative is negative.
	ErrNegativeValue = errors.New("pkcs12: negative value")

	// ErrMalformedParameter is returned by the policy-aware decoding entry
	// points when an algorithm parameter is malformed (for example, a required
	// field is missing or has the wrong ASN.1 type).
	ErrMalformedParameter = errors.New("pkcs12: malformed algorithm parameter")

	// ErrUnknownAlgorithm is returned by the policy-aware decoding entry points
	// when the PFX uses an algorithm that this library does not know how to
	// decode.  Algorithms rejected by Policy are reported with
	// ErrPolicyRejected instead.
	ErrUnknownAlgorithm = errors.New("pkcs12: unknown algorithm")
)

// maxInt is the largest value representable by an int on the current platform.
const maxInt = int(^uint(0) >> 1)

// Policy restricts the algorithms and parameters that may appear in a PFX
// being decoded.  The zero value permits every algorithm supported by this
// library without limiting KDF work, salt lengths, or container sizes, but
// unknown algorithms remain unsupported.
//
// A Policy is applied before any keys are derived (see
// DecodeChainWithPolicy): every parameter that can be checked without
// decrypting anything is validated first, so a non-conforming PFX is rejected
// before any expensive KDF computation takes place.  KDF work is accumulated
// across the MAC, all encrypted safe contents, and all shrouded key bags
// instead of being reset for each layer.
type Policy struct {
	// MacAlgorithms contains the OIDs of the allowed MAC algorithms:
	// oidSHA1, oidSHA256, oidSHA512, and oidPBMAC1.  For PBMAC1, the nested
	// PBKDF2 PRF and HMAC algorithm OIDs must be known to this library even if
	// they are not listed here.  If empty, every known MAC algorithm is allowed.
	MacAlgorithms []asn1.ObjectIdentifier

	// EncryptionAlgorithms contains the OIDs of the allowed content encryption
	// algorithms: the legacy PBE OIDs (oidPBEWithSHAAnd3KeyTripleDESCBC,
	// oidPBEWithSHAAnd128BitRC2CBC, oidPBEWithSHAAnd40BitRC2CBC), oidPBES2,
	// and, within PBES2, the PBES2 encryption schemes (oidAES128CBC,
	// oidAES192CBC, oidAES256CBC).  If empty, every known encryption algorithm
	// is allowed.
	EncryptionAlgorithms []asn1.ObjectIdentifier

	// MaxKDFIterations limits the iteration count of a single KDF invocation.
	// A legacy PBE invocation derives both a key and an IV, so it is charged
	// twice the iteration count against MaxTotalKDFWork, but the iteration
	// count itself is compared against this field.  Zero means unlimited.
	MaxKDFIterations int64

	// MaxTotalKDFWork limits the sum of KDF iteration counts accumulated over
	// the MAC, every encrypted safe content, and every shrouded key bag.  A
	// legacy PBE invocation is charged twice the iteration count (key and IV),
	// while PBKDF2 (PBES2 and PBMAC1) is charged once.  Zero means unlimited.
	MaxTotalKDFWork int64

	// MinSaltLength and MaxSaltLength limit the length (in bytes) of KDF salts:
	// the legacy MAC salt, the PBMAC1/PBKDF2 salt, and the legacy PBE salt.
	// A zero MaxSaltLength means no upper limit; a zero MinSaltLength permits
	// empty salts.
	MinSaltLength int
	MaxSaltLength int

	// MaxSafeContents limits the number of ContentInfo values in the
	// authenticated safe.  Zero means unlimited.
	MaxSafeContents int

	// MaxSafeBags limits the number of SafeBag values across all safe contents
	// that can be inspected without decrypting.  Bags inside encrypted safe
	// contents cannot be counted until decryption succeeds and are not
	// included.  Zero means unlimited.
	MaxSafeBags int
}

// CheckPolicy validates every checkable parameter of pfxData against the
// policy without deriving any keys or decrypting anything.  expectedItemsMin
// and expectedItemsMax constrain the number of ContentInfo values in the
// authenticated safe (expectedItemsMax of 0 means unbounded at the upper end).
//
// Errors wrap one of ErrPolicyRejected, ErrIntegerOverflow, ErrNegativeValue,
// ErrMalformedParameter, or ErrUnknownAlgorithm.  Error messages never contain
// the password or any decrypted data.
func (policy *Policy) CheckPolicy(pfxData []byte, expectedItemsMin, expectedItemsMax int) error {
	if err := policy.validate(); err != nil {
		return err
	}
	return preflightPolicy(&decodeConfig{policy: policy}, pfxData, expectedItemsMin, expectedItemsMax)
}

func (policy *Policy) validate() error {
	if policy.MaxKDFIterations < 0 || policy.MaxTotalKDFWork < 0 ||
		policy.MinSaltLength < 0 || policy.MaxSaltLength < 0 ||
		policy.MaxSafeContents < 0 || policy.MaxSafeBags < 0 {
		return errors.New("pkcs12: invalid policy: negative limit")
	}
	if policy.MaxSaltLength != 0 && policy.MinSaltLength > policy.MaxSaltLength {
		return fmt.Errorf("pkcs12: invalid policy: MinSaltLength (%d) is greater than MaxSaltLength (%d)", policy.MinSaltLength, policy.MaxSaltLength)
	}
	return nil
}

// decodeConfig threads the policy budget through the actual decoding path.
// The budget is created once per top-level decode and is never reset, so KDF
// work in nested shrouded key bags accumulates with everything else.
type decodeConfig struct {
	policy *Policy
	used   int64
}

// charge validates one prospective KDF invocation against the per-invocation
// and cumulative limits, and reserves its work.  work must already include the
// legacy key-plus-IV multiplier (see pbeLegacyWork).
func (cfg *decodeConfig) charge(iterations int, work int64, what string) error {
	if cfg == nil || cfg.policy == nil {
		return nil
	}
	if err := cfg.policy.checkIterations(int64(iterations), what); err != nil {
		return err
	}
	if cfg.policy.MaxTotalKDFWork != 0 {
		limit := cfg.policy.MaxTotalKDFWork
		if work > limit-cfg.used {
			return fmt.Errorf("%w: %s KDF would raise cumulative work from %d to %d, exceeding the limit of %d iterations",
				ErrPolicyRejected, what, cfg.used, cfg.used+work, limit)
		}
	}
	cfg.used += work
	return nil
}

func (policy *Policy) checkIterations(iterations int64, what string) error {
	if iterations < 1 {
		return fmt.Errorf("%w: %s KDF iteration count must be at least 1 (got %d)", ErrMalformedParameter, what, iterations)
	}
	if policy.MaxKDFIterations != 0 && iterations > policy.MaxKDFIterations {
		return fmt.Errorf("%w: %s KDF iteration count %d exceeds the limit of %d",
			ErrPolicyRejected, what, iterations, policy.MaxKDFIterations)
	}
	return nil
}

func (policy *Policy) checkSalt(salt []byte, what string) error {
	n := len(salt)
	if n < policy.MinSaltLength {
		return fmt.Errorf("%w: %s salt length %d is shorter than the minimum of %d",
			ErrPolicyRejected, what, n, policy.MinSaltLength)
	}
	if policy.MaxSaltLength != 0 && n > policy.MaxSaltLength {
		return fmt.Errorf("%w: %s salt length %d exceeds the maximum of %d",
			ErrPolicyRejected, what, n, policy.MaxSaltLength)
	}
	return nil
}

func (policy *Policy) allowsMac(oid asn1.ObjectIdentifier) bool {
	return oidAllowed(policy.MacAlgorithms, oid)
}

func (policy *Policy) allowsEncryption(oid asn1.ObjectIdentifier) bool {
	return oidAllowed(policy.EncryptionAlgorithms, oid)
}

func oidAllowed(allowlist []asn1.ObjectIdentifier, oid asn1.ObjectIdentifier) bool {
	if len(allowlist) == 0 {
		return true
	}
	for _, allowed := range allowlist {
		if allowed.Equal(oid) {
			return true
		}
	}
	return false
}

// pbeLegacyWork is the cumulative KDF work of one legacy PBE operation: one
// derivation for the key and another for the IV, each running the iteration
// count number of times.
func pbeLegacyWork(iterations int64) int64 { return 2 * iterations }

func wrapASN1Error(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.Contains(msg, "integer too large") || strings.Contains(msg, "cannot represent") {
		return fmt.Errorf("%w: %v", ErrIntegerOverflow, err)
	}
	return fmt.Errorf("%w: %v", ErrMalformedParameter, err)
}

// preflight mirrors of the ASN.1 structures.  Integer parameters are *big.Int
// (instead of int) so that overflows and negative values can be detected and
// distinctly reported rather than clamped by encoding/asn1.
type preflightPfx struct {
	Version  int
	AuthSafe contentInfo
	MacData  preflightMacData `asn1:"optional"`
}

type preflightMacData struct {
	Mac        digestInfo
	MacSalt    []byte
	Iterations *big.Int `asn1:"optional"`
}

type preflightPbeParams struct {
	Salt       []byte
	Iterations *big.Int
}

type preflightPbkdf2Params struct {
	Salt       asn1.RawValue
	Iterations *big.Int
	KeyLength  *big.Int                 `asn1:"optional"`
	Prf        pkix.AlgorithmIdentifier `asn1:"optional"`
}

type preflightPbes2Params struct {
	Kdf              pkix.AlgorithmIdentifier
	EncryptionScheme pkix.AlgorithmIdentifier
}

type preflightPbmac1Params struct {
	Kdf    pkix.AlgorithmIdentifier
	MacAlg pkix.AlgorithmIdentifier
}

type preflightEncryptedData struct {
	Version              *big.Int
	EncryptedContentInfo encryptedContentInfo
}
