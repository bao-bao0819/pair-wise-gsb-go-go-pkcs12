// Copyright 2026 Opsmate, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math"
)

// Policy constrains the algorithms and key-derivation work that the
// policy-aware decoding entry points ([DecodeChainWithPolicy],
// [DecodeWithPolicy], [DecodeTrustStoreWithPolicy] and [ToPEMWithPolicy])
// will accept.
//
// Every parameter that can be determined from the PFX structure is validated
// before any key-derivation function (KDF) is invoked.  The cumulative KDF
// work of the MAC, every encrypted SafeContents and every shrouded key is
// charged against a single budget that is carried through the whole decode;
// entering a nested layer never resets it.
//
// Passing a nil pointer, or the zero value, is equivalent to a permissive
// policy: every algorithm the library implements is accepted and no work,
// salt-length or container-size limits are enforced.  Start from
// [DefaultPolicy] and modify the limits you need to change.
type Policy struct {
	// AllowedMACAlgorithms is the list of MAC algorithm OIDs permitted in
	// the PFX MacData.  Recognized values are oidSHA1, oidSHA256, oidSHA512
	// and oidPBMAC1; for PBMAC1 the inner PBKDF2 PRF OIDs
	// (oidHmacWithSHA1/256/512) and inner MAC OID must also be permitted.
	// A nil slice permits every MAC algorithm the library supports.
	AllowedMACAlgorithms []asn1.ObjectIdentifier

	// AllowedEncryptionAlgorithms is the list of OIDs permitted for
	// encrypting SafeContents and shrouded keys.  Recognized values are the
	// legacy PBE OIDs (oidPBEWithSHAAnd3KeyTripleDESCBC,
	// oidPBEWithSHAAnd128BitRC2CBC, oidPBEWithSHAAnd40BitRC2CBC), oidPBES2,
	// the PBES2 content-encryption OIDs (oidAES128CBC, oidAES192CBC,
	// oidAES256CBC) and the PBKDF2 PRF OIDs (oidHmacWithSHA1/256/512).
	// A nil slice permits every encryption algorithm the library supports.
	AllowedEncryptionAlgorithms []asn1.ObjectIdentifier

	// MaxKDFIterations limits the iteration count of a single key
	// derivation.  For the legacy PBE, each encrypted object performs two
	// derivations (key and IV) with the same iteration count.  Zero means
	// no per-derivation limit.
	MaxKDFIterations int64

	// MaxTotalKDFIterations limits the sum of iteration counts charged by
	// the MAC, all encrypted SafeContents and all shrouded keys during the
	// entire decode.  The budget is not reset when entering nested
	// contents.  Zero means no cumulative limit.
	MaxTotalKDFIterations int64

	// MinSaltLength and MaxSaltLength bound the length, in bytes, of every
	// MAC and KDF salt.  Either bound of zero leaves that side unbounded.
	MinSaltLength int
	MaxSaltLength int

	// MaxPFXSize limits the total size, in bytes, of the DER-encoded PFX.
	// Zero means no size limit.
	MaxPFXSize int

	// MaxAuthenticatedSafe limits the number of ContentInfos in the
	// authenticated safe.  Zero means no limit.
	MaxAuthenticatedSafe int

	// MaxSafeBags limits the total number of SafeBags found across all
	// SafeContents.  Zero means no limit.
	MaxSafeBags int
}

// DefaultPolicy returns a policy with modern defaults.
//
// The weak legacy PBE algorithms (RC2, 3DES, HMAC-SHA-1 based MACs) are
// rejected: only PBES2/PBKDF2 with HMAC-SHA-2, SHA-2 MACs and PBMAC1 are
// permitted.  KDF iteration counts are capped both per derivation and in
// aggregate, salts must be 8-64 bytes, and the container structure is bounded
// so that a crafted PFX cannot trigger unbounded parsing or key-derivation
// work.  The returned value may be copied and adjusted before use.
func DefaultPolicy() *Policy {
	return &Policy{
		AllowedMACAlgorithms: []asn1.ObjectIdentifier{
			oidSHA256,
			oidSHA512,
			oidPBMAC1,
			oidHmacWithSHA256,
			oidHmacWithSHA512,
		},
		AllowedEncryptionAlgorithms: []asn1.ObjectIdentifier{
			oidPBES2,
			oidHmacWithSHA256,
			oidHmacWithSHA512,
			oidAES128CBC,
			oidAES192CBC,
			oidAES256CBC,
		},
		MaxKDFIterations:      600000,
		MaxTotalKDFIterations: 3000000,
		MinSaltLength:         8,
		MaxSaltLength:         64,
		MaxPFXSize:            10 * 1024 * 1024,
		MaxAuthenticatedSafe:  16,
		MaxSafeBags:           1024,
	}
}

func (p *Policy) allows(list []asn1.ObjectIdentifier, oid asn1.ObjectIdentifier) bool {
	if p == nil || len(list) == 0 {
		return true
	}
	for _, allowed := range list {
		if allowed.Equal(oid) {
			return true
		}
	}
	return false
}

func (p *Policy) allowsMAC(oid asn1.ObjectIdentifier) bool {
	return p.allows(p.AllowedMACAlgorithms, oid)
}

func (p *Policy) allowsEncryption(oid asn1.ObjectIdentifier) bool {
	return p.allows(p.AllowedEncryptionAlgorithms, oid)
}

func (p *Policy) checkSaltLength(salt []byte, where string) error {
	if p == nil {
		return nil
	}
	if p.MinSaltLength > 0 && len(salt) < p.MinSaltLength {
		return fmt.Errorf("%w: %s salt length %d is below minimum %d", ErrPolicyRejected, where, len(salt), p.MinSaltLength)
	}
	if p.MaxSaltLength > 0 && len(salt) > p.MaxSaltLength {
		return fmt.Errorf("%w: %s salt length %d exceeds maximum %d", ErrPolicyRejected, where, len(salt), p.MaxSaltLength)
	}
	return nil
}

// decodeState carries the policy and the cumulative KDF budget through a
// decode, including across decrypted SafeContents layers.  It is the single
// place the budget is tracked, so nested content can never reset it.
type decodeState struct {
	policy   *Policy
	kdfSpent int64
}

// charge accounts for a single KDF invocation that will perform iterations
// iterations, enforcing both the per-derivation and cumulative caps.
func (s *decodeState) charge(where string, iterations int64) error {
	if s == nil || s.policy == nil {
		return nil
	}
	if limit := s.policy.MaxKDFIterations; limit > 0 && iterations > limit {
		return fmt.Errorf("%w: %s KDF iteration count %d exceeds per-derivation limit %d", ErrPolicyRejected, where, iterations, limit)
	}
	if s.policy.MaxTotalKDFIterations > 0 {
		if iterations > math.MaxInt64-s.kdfSpent {
			return fmt.Errorf("%w: cumulative KDF iteration count overflow", ErrPolicyRejected)
		}
		total := s.kdfSpent + iterations
		if total > s.policy.MaxTotalKDFIterations {
			return fmt.Errorf("%w: cumulative KDF iteration count %d exceeds total limit %d", ErrPolicyRejected, total, s.policy.MaxTotalKDFIterations)
		}
		s.kdfSpent = total
	}
	return nil
}

// checkedPbeParams mirrors pbeParams but keeps the INTEGER fields as raw
// ASN.1 so that negative values and platform-overflowing values can be
// distinguished from ordinary malformed parameters.
type checkedPbeParams struct {
	Salt       asn1.RawValue
	Iterations asn1.RawValue
}

// decodePositiveInt64 decodes a DER INTEGER into an int64.  Negative values
// produce ErrNegativeValue, and values outside the platform int range produce
// ErrIntegerOverflow.  Zero is returned without an error; callers decide
// whether zero is legal for the parameter in question.
func decodePositiveInt64(raw asn1.RawValue) (int64, error) {
	if raw.Tag != asn1.TagInteger || len(raw.Bytes) == 0 {
		return 0, fmt.Errorf("%w: expected INTEGER", ErrMalformedParameters)
	}
	if raw.Bytes[0]&0x80 != 0 {
		return 0, fmt.Errorf("%w: integer is negative", ErrNegativeValue)
	}
	var v uint64
	for _, b := range raw.Bytes {
		if v > (math.MaxInt64-uint64(b))>>8 {
			return 0, fmt.Errorf("%w: integer %d exceeds the platform int range", ErrIntegerOverflow, v)
		}
		v = v<<8 | uint64(b)
	}
	return int64(v), nil
}

// parseASN1Elements splits the body of a SEQUENCE/SET into its top-level DER
// elements.
func parseASN1Elements(data []byte) ([]asn1.RawValue, error) {
	var elements []asn1.RawValue
	for len(data) > 0 {
		var element asn1.RawValue
		var err error
		data, err = asn1.Unmarshal(data, &element)
		if err != nil {
			return nil, err
		}
		elements = append(elements, element)
	}
	return elements, nil
}

func isLegacyPBE(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(oidPBEWithSHAAnd3KeyTripleDESCBC) ||
		oid.Equal(oidPBEWithSHAAnd128BitRC2CBC) ||
		oid.Equal(oidPBEWithSHAAnd40BitRC2CBC)
}

func isHmacPRF(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(oidHmacWithSHA1) ||
		oid.Equal(oidHmacWithSHA256) ||
		oid.Equal(oidHmacWithSHA512)
}

func isAES(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(oidAES128CBC) ||
		oid.Equal(oidAES192CBC) ||
		oid.Equal(oidAES256CBC)
}

func isLegacyMACDigest(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(oidSHA1) || oid.Equal(oidSHA256) || oid.Equal(oidSHA512)
}

var errPBMAC1KeyLengthMissing = errors.New("pkcs12: PBMAC1 requires explicit KeyLength parameter in PBKDF2 parameters")

// checkPBMAC1KeyLength applies the PBMAC1 key-length security bounds shared
// by the preflight and the verifier.
func checkPBMAC1KeyLength(keyLength int64) error {
	if keyLength <= 0 {
		return errPBMAC1KeyLengthMissing
	}
	if keyLength < 20 {
		return fmt.Errorf("pkcs12: PBMAC1 key length %d is too short to be secure (minimum 20 octets)", keyLength)
	}
	const maxKeyLength = 64
	if keyLength > maxKeyLength {
		return fmt.Errorf("pkcs12: PBMAC1 key length %d is too large (maximum %d octets)", keyLength, maxKeyLength)
	}
	return nil
}

// checkPBKDF2Parameters validates the raw PBKDF2-params and charges the
// single PBKDF2 derivation to the budget.  When forPBMAC1 is true the
// mandatory RFC 9579 key-length bounds are enforced.  The prfOID return value
// is the effective PRF (defaulting to HMAC-SHA-1).
func (s *decodeState) checkPBKDF2Parameters(rawParams []byte, where string, forPBMAC1 bool) (asn1.ObjectIdentifier, error) {
	var seq asn1.RawValue
	if rest, err := asn1.Unmarshal(rawParams, &seq); err != nil {
		return nil, fmt.Errorf("%w: %s PBKDF2 parameters: %v", ErrMalformedParameters, where, err)
	} else if len(rest) != 0 {
		return nil, fmt.Errorf("%w: %s PBKDF2 parameters have trailing data", ErrMalformedParameters, where)
	}
	if !seq.IsCompound || seq.Tag != asn1.TagSequence {
		return nil, fmt.Errorf("%w: %s PBKDF2 parameters must be a SEQUENCE", ErrMalformedParameters, where)
	}

	// Parse the four elements by hand so an absent optional INTEGER keyLength
	// cannot be confused with the following SEQUENCE PRF, and so that
	// negative/overflowing integers can be reported distinctly.
	var (
		saltRaw       asn1.RawValue
		iterationsRaw asn1.RawValue
		keyLengthRaw  asn1.RawValue
		prfRaw        asn1.RawValue
		haveKeyLength bool
		havePRF       bool
	)
	elements, err := parseASN1Elements(seq.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %s PBKDF2 parameters: %v", ErrMalformedParameters, where, err)
	}
	if len(elements) < 2 {
		return nil, fmt.Errorf("%w: %s PBKDF2 parameters have too few fields", ErrMalformedParameters, where)
	}
	saltRaw = elements[0]
	iterationsRaw = elements[1]
	switch len(elements) {
	case 2:
	case 3:
		if elements[2].Tag == asn1.TagInteger {
			keyLengthRaw = elements[2]
			haveKeyLength = true
		} else {
			prfRaw = elements[2]
			havePRF = true
		}
	case 4:
		keyLengthRaw = elements[2]
		haveKeyLength = true
		prfRaw = elements[3]
		havePRF = true
	default:
		return nil, fmt.Errorf("%w: %s PBKDF2 parameters have too many fields", ErrMalformedParameters, where)
	}
	if haveKeyLength && keyLengthRaw.Tag != asn1.TagInteger {
		return nil, fmt.Errorf("%w: %s PBKDF2 key length must be an INTEGER", ErrMalformedParameters, where)
	}
	if havePRF && (prfRaw.Tag != asn1.TagSequence) {
		return nil, fmt.Errorf("%w: %s PBKDF2 PRF must be a SEQUENCE", ErrMalformedParameters, where)
	}

	if haveKeyLength {
		keyLength, err := decodePositiveInt64(keyLengthRaw)
		if err != nil {
			return nil, fmt.Errorf("%w: %s PBKDF2 key length", err, where)
		}
		if forPBMAC1 {
			if err := checkPBMAC1KeyLength(keyLength); err != nil {
				return nil, err
			}
		} else if keyLength == 0 {
			return nil, fmt.Errorf("%w: %s PBKDF2 key length must not be zero", ErrMalformedParameters, where)
		}
	} else if forPBMAC1 {
		return nil, errPBMAC1KeyLengthMissing
	}

	iterations, err := decodePositiveInt64(iterationsRaw)
	if err != nil {
		return nil, fmt.Errorf("%w: %s PBKDF2 iteration count", err, where)
	}
	if iterations == 0 {
		return nil, fmt.Errorf("%w: %s PBKDF2 iteration count must be positive", ErrMalformedParameters, where)
	}

	if saltRaw.Tag != asn1.TagOctetString {
		return nil, NotImplementedError("only octet string salts are supported for pbes2/pbkdf2")
	}
	if err := s.policy.checkSaltLength(saltRaw.Bytes, where+" PBKDF2"); err != nil {
		return nil, err
	}

	prfOID := oidHmacWithSHA1
	if havePRF {
		var prf pkix.AlgorithmIdentifier
		if rest, err := asn1.Unmarshal(prfRaw.FullBytes, &prf); err != nil {
			return nil, fmt.Errorf("%w: %s PBKDF2 PRF: %v", ErrMalformedParameters, where, err)
		} else if len(rest) != 0 {
			return nil, fmt.Errorf("%w: %s PBKDF2 PRF has trailing data", ErrMalformedParameters, where)
		}
		prfOID = prf.Algorithm
	}
	if len(prfOID) == 0 || !isHmacPRF(prfOID) {
		return nil, NotImplementedError("pbes2 prf " + prfOID.String() + " is not supported")
	}
	if forPBMAC1 {
		if !s.policy.allowsMAC(prfOID) {
			return nil, fmt.Errorf("%w: %s PBKDF2 PRF %s is not allowed", ErrPolicyRejected, where, prfOID)
		}
	} else if !s.policy.allowsEncryption(prfOID) {
		return nil, fmt.Errorf("%w: %s PBKDF2 PRF %s is not allowed", ErrPolicyRejected, where, prfOID)
	}

	if err := s.charge(where+" PBKDF2", iterations); err != nil {
		return nil, err
	}
	return prfOID, nil
}

// checkEncryptionAlgorithm validates an algorithm identifier used to encrypt
// a SafeContents or a shrouded private key, charging its KDF work to the
// budget.  No decryption is performed.
func (s *decodeState) checkEncryptionAlgorithm(algorithm pkix.AlgorithmIdentifier, where string) error {
	p := s.policy
	switch {
	case isLegacyPBE(algorithm.Algorithm):
		if !p.allowsEncryption(algorithm.Algorithm) {
			return fmt.Errorf("%w: %s encryption algorithm %s is not allowed", ErrPolicyRejected, where, algorithm.Algorithm)
		}
		var params checkedPbeParams
		if rest, err := asn1.Unmarshal(algorithm.Parameters.FullBytes, &params); err != nil {
			return fmt.Errorf("%w: %s PBE parameters: %v", ErrMalformedParameters, where, err)
		} else if len(rest) != 0 {
			return fmt.Errorf("%w: %s PBE parameters have trailing data", ErrMalformedParameters, where)
		}
		if params.Salt.Tag != asn1.TagOctetString {
			return fmt.Errorf("%w: %s PBE salt must be an OCTET STRING", ErrMalformedParameters, where)
		}
		if err := p.checkSaltLength(params.Salt.Bytes, where+" PBE"); err != nil {
			return err
		}
		iterations, err := decodePositiveInt64(params.Iterations)
		if err != nil {
			return fmt.Errorf("%w: %s PBE iteration count", err, where)
		}
		if iterations == 0 {
			return fmt.Errorf("%w: %s PBE iteration count must be positive", ErrMalformedParameters, where)
		}
		// The legacy PBE derives both a key and an IV, each with the same
		// iteration count.
		return s.charge(where+" PBE", 2*iterations)

	case algorithm.Algorithm.Equal(oidPBES2):
		// Handled below.

	default:
		return NotImplementedError("pbe algorithm " + algorithm.Algorithm.String() + " is not supported")
	}

	if !p.allowsEncryption(oidPBES2) {
		return fmt.Errorf("%w: %s encryption algorithm %s is not allowed", ErrPolicyRejected, where, oidPBES2)
	}

	var params pbes2Params
	if rest, err := asn1.Unmarshal(algorithm.Parameters.FullBytes, &params); err != nil {
		return fmt.Errorf("%w: %s PBES2 parameters: %v", ErrMalformedParameters, where, err)
	} else if len(rest) != 0 {
		return fmt.Errorf("%w: %s PBES2 parameters have trailing data", ErrMalformedParameters, where)
	}
	if !params.Kdf.Algorithm.Equal(oidPBKDF2) {
		return NotImplementedError("pbes2 kdf algorithm " + params.Kdf.Algorithm.String() + " is not supported")
	}
	if _, err := s.checkPBKDF2Parameters(params.Kdf.Parameters.FullBytes, where+" PBES2", false); err != nil {
		return err
	}
	if !isAES(params.EncryptionScheme.Algorithm) {
		return NotImplementedError("pbes2 algorithm " + params.EncryptionScheme.Algorithm.String() + " is not supported")
	}
	if !p.allowsEncryption(params.EncryptionScheme.Algorithm) {
		return fmt.Errorf("%w: %s PBES2 encryption scheme %s is not allowed", ErrPolicyRejected, where, params.EncryptionScheme.Algorithm)
	}
	if len(params.EncryptionScheme.Parameters.Bytes) != aesBlockSize(params.EncryptionScheme.Algorithm) {
		return fmt.Errorf("pkcs12: invalid IV length in PBES2 encryption scheme (IV length %d does not match block size %d)",
			len(params.EncryptionScheme.Parameters.Bytes), aesBlockSize(params.EncryptionScheme.Algorithm))
	}
	return nil
}

func aesBlockSize(oid asn1.ObjectIdentifier) int {
	return 16
}

// checkMacData validates the MAC parameters and charges the MAC key
// derivation to the budget.  It neither computes nor verifies the MAC.
func (s *decodeState) checkMacData(data *macData) error {
	p := s.policy

	if data.Mac.Algorithm.Algorithm.Equal(oidPBMAC1) {
		if !p.allowsMAC(oidPBMAC1) {
			return fmt.Errorf("%w: MAC algorithm %s is not allowed", ErrPolicyRejected, oidPBMAC1)
		}
		var params pbmac1Params
		if rest, err := asn1.Unmarshal(data.Mac.Algorithm.Parameters.FullBytes, &params); err != nil {
			return fmt.Errorf("%w: PBMAC1 parameters: %v", ErrMalformedParameters, err)
		} else if len(rest) != 0 {
			return fmt.Errorf("%w: PBMAC1 parameters have trailing data", ErrMalformedParameters)
		}
		if !params.Kdf.Algorithm.Equal(oidPBKDF2) {
			return NotImplementedError("PBMAC1 KDF algorithm " + params.Kdf.Algorithm.String() + " is not supported")
		}
		prfOID, err := s.checkPBKDF2Parameters(params.Kdf.Parameters.FullBytes, "PBMAC1", true)
		if err != nil {
			return err
		}
		if !p.allowsMAC(prfOID) {
			return fmt.Errorf("%w: PBMAC1 PBKDF2 PRF %s is not allowed", ErrPolicyRejected, prfOID)
		}
		if len(params.MacAlg.Algorithm) == 0 ||
			!(params.MacAlg.Algorithm.Equal(oidHmacWithSHA1) ||
				params.MacAlg.Algorithm.Equal(oidHmacWithSHA256) ||
				params.MacAlg.Algorithm.Equal(oidHmacWithSHA512)) {
			return NotImplementedError("PBMAC1 MAC algorithm " + params.MacAlg.Algorithm.String() + " is not supported")
		}
		if !p.allowsMAC(params.MacAlg.Algorithm) {
			return fmt.Errorf("%w: PBMAC1 MAC algorithm %s is not allowed", ErrPolicyRejected, params.MacAlg.Algorithm)
		}
		return nil
	}

	if !isLegacyMACDigest(data.Mac.Algorithm.Algorithm) {
		return NotImplementedError("MAC digest algorithm not supported: " + data.Mac.Algorithm.Algorithm.String())
	}
	if !p.allowsMAC(data.Mac.Algorithm.Algorithm) {
		return fmt.Errorf("%w: MAC algorithm %s is not allowed", ErrPolicyRejected, data.Mac.Algorithm.Algorithm)
	}
	if err := p.checkSaltLength(data.MacSalt, "MAC"); err != nil {
		return err
	}
	iterations := int64(data.Iterations)
	if iterations < 0 {
		return fmt.Errorf("%w: MAC iteration count is negative", ErrNegativeValue)
	}
	return s.charge("MAC", iterations)
}

// preflightPFX walks everything that is visible before decryption and
// validates it against the policy, so that policy violations and malformed
// parameters are reported before any KDF runs.  The MAC is not verified here.
func (s *decodeState) preflightPFX(pfxData []byte, pfx *pfxPdu, authenticatedSafe []contentInfo) ([]contentInfo, error) {
	p := s.policy
	if p == nil {
		return authenticatedSafe, nil
	}

	if p.MaxPFXSize > 0 && len(pfxData) > p.MaxPFXSize {
		return nil, fmt.Errorf("%w: PFX size %d exceeds maximum %d", ErrPolicyRejected, len(pfxData), p.MaxPFXSize)
	}
	if p.MaxAuthenticatedSafe > 0 && len(authenticatedSafe) > p.MaxAuthenticatedSafe {
		return nil, fmt.Errorf("%w: authenticated safe contains %d items, maximum is %d", ErrPolicyRejected, len(authenticatedSafe), p.MaxAuthenticatedSafe)
	}

	if len(pfx.MacData.Mac.Algorithm.Algorithm) > 0 {
		if err := s.checkMacData(&pfx.MacData); err != nil {
			return nil, err
		}
	}

	for i := range authenticatedSafe {
		ci := &authenticatedSafe[i]
		switch {
		case ci.ContentType.Equal(oidDataContentType):
			// Nothing encrypted here.
		case ci.ContentType.Equal(oidEncryptedDataContentType):
			var ed encryptedData
			if err := unmarshal(ci.Content.Bytes, &ed); err != nil {
				return nil, err
			}
			if ed.Version != 0 {
				return nil, NotImplementedError("only version 0 of EncryptedData is supported")
			}
			if err := s.checkEncryptionAlgorithm(ed.EncryptedContentInfo.ContentEncryptionAlgorithm, fmt.Sprintf("authenticatedSafe[%d]", i)); err != nil {
				return nil, err
			}
		default:
			return nil, NotImplementedError("only data and encryptedData content types are supported in authenticated safe")
		}
	}

	return authenticatedSafe, nil
}
