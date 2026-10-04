// Copyright 2026 Opsmate, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
)

func preflightPolicy(cfg *decodeConfig, pfxData []byte, expectedItemsMin, expectedItemsMax int) error {
	policy := cfg.policy

	pfx := new(preflightPfx)
	if err := unmarshal(pfxData, pfx); err != nil {
		return wrapASN1Error(err)
	}

	// Only validate the password-protected shape that getSafeContents decodes;
	// unsupported versions and content types are reported by the normal path
	// with their usual NotImplementedError.
	if pfx.Version != 3 || !pfx.AuthSafe.ContentType.Equal(oidDataContentType) {
		return nil
	}

	var authSafeBytes []byte
	if err := unmarshal(pfx.AuthSafe.Content.Bytes, &authSafeBytes); err != nil {
		return wrapASN1Error(err)
	}

	if len(pfx.MacData.Mac.Algorithm.Algorithm) != 0 {
		if err := preflightMac(cfg, &pfx.MacData); err != nil {
			return err
		}
	}

	var authenticatedSafe []contentInfo
	if err := unmarshal(authSafeBytes, &authenticatedSafe); err != nil {
		return wrapASN1Error(err)
	}
	if len(authenticatedSafe) < expectedItemsMin ||
		(expectedItemsMax != 0 && len(authenticatedSafe) > expectedItemsMax) {
		// Mirror the NotImplementedError produced by the normal decode path.
		return nil
	}
	if policy.MaxSafeContents != 0 && len(authenticatedSafe) > policy.MaxSafeContents {
		return fmt.Errorf("%w: authenticated safe contains %d content infos, exceeding the limit of %d",
			ErrPolicyRejected, len(authenticatedSafe), policy.MaxSafeContents)
	}

	visibleBags := 0
	for _, ci := range authenticatedSafe {
		switch {
		case ci.ContentType.Equal(oidDataContentType):
			var data []byte
			if err := unmarshal(ci.Content.Bytes, &data); err != nil {
				return wrapASN1Error(err)
			}
			var safeContents []safeBag
			if err := unmarshal(data, &safeContents); err != nil {
				return wrapASN1Error(err)
			}
			visibleBags += len(safeContents)
			for i := range safeContents {
				if safeContents[i].Id.Equal(oidPKCS8ShroundedKeyBag) {
					if err := preflightShroudedKey(cfg, safeContents[i].Value.Bytes); err != nil {
						return err
					}
				}
			}
		case ci.ContentType.Equal(oidEncryptedDataContentType):
			if err := preflightEncryptedContentInfo(cfg, ci); err != nil {
				return err
			}
		default:
			// Unsupported content types are reported by the normal path.
			return nil
		}
	}

	if policy.MaxSafeBags != 0 && visibleBags > policy.MaxSafeBags {
		return fmt.Errorf("%w: %d safe bags are visible, exceeding the limit of %d",
			ErrPolicyRejected, visibleBags, policy.MaxSafeBags)
	}
	return nil
}

func preflightMac(cfg *decodeConfig, data *preflightMacData) error {
	algorithm := data.Mac.Algorithm

	if algorithm.Algorithm.Equal(oidPBMAC1) {
		if !cfg.policy.allowsMac(oidPBMAC1) {
			return fmt.Errorf("%w: MAC algorithm %s is not allowed by policy",
				ErrPolicyRejected, oidPBMAC1)
		}
		var params preflightPbmac1Params
		if err := unmarshal(algorithm.Parameters.FullBytes, &params); err != nil {
			return malformedParameterf("error decoding PBMAC1 parameters: %v", err)
		}
		if !params.Kdf.Algorithm.Equal(oidPBKDF2) {
			return unknownAlgorithmf("PBMAC1 KDF algorithm %s", params.Kdf.Algorithm)
		}
		iterations, _, err := preflightPbkdf2ParamsCheck(cfg, params.Kdf, "PBMAC1", true)
		if err != nil {
			return err
		}
		if !knownMacOid(params.MacAlg.Algorithm) {
			return unknownAlgorithmf("PBMAC1 MAC algorithm %s", params.MacAlg.Algorithm)
		}
		return cfg.charge(iterations, int64(iterations), "PBMAC1")
	}

	if !knownMacOid(algorithm.Algorithm) {
		return unknownAlgorithmf("MAC digest algorithm %s", algorithm.Algorithm)
	}
	if !cfg.policy.allowsMac(algorithm.Algorithm) {
		return fmt.Errorf("%w: MAC algorithm %s is not allowed by policy",
			ErrPolicyRejected, algorithm.Algorithm)
	}

	// The legacy PKCS#12 MAC defaults to 1 iteration when absent.
	iterations := 1
	if data.Iterations != nil {
		iter, err := nonNegativeInt(data.Iterations, "MAC iteration count")
		if err != nil {
			return err
		}
		iterations = iter
	}
	if err := cfg.policy.checkSalt(data.MacSalt, "MAC"); err != nil {
		return err
	}
	if err := cfg.policy.checkIterations(int64(iterations), "MAC"); err != nil {
		return err
	}
	return cfg.charge(iterations, int64(iterations), "MAC")
}

func preflightEncryptedContentInfo(cfg *decodeConfig, ci contentInfo) error {
	var data preflightEncryptedData
	if err := unmarshal(ci.Content.Bytes, &data); err != nil {
		return wrapASN1Error(err)
	}
	if data.Version != nil {
		version, err := nonNegativeInt(data.Version, "encryptedData version")
		if err != nil {
			return err
		}
		if version != 0 {
			// Reported by the normal path with its usual NotImplementedError.
			return nil
		}
	}
	return preflightEncryptionAlgorithm(cfg, data.EncryptedContentInfo.ContentEncryptionAlgorithm)
}

func preflightShroudedKey(cfg *decodeConfig, asn1Data []byte) error {
	var pkinfo encryptedPrivateKeyInfo
	if err := unmarshal(asn1Data, &pkinfo); err != nil {
		return malformedParameterf("error decoding PKCS#8 shrouded key bag: %v", err)
	}
	if err := preflightEncryptionAlgorithm(cfg, pkinfo.AlgorithmIdentifier); err != nil {
		return err
	}
	return nil
}

func preflightEncryptionAlgorithm(cfg *decodeConfig, algorithm pkix.AlgorithmIdentifier) error {
	switch {
	case algorithm.Algorithm.Equal(oidPBEWithSHAAnd3KeyTripleDESCBC),
		algorithm.Algorithm.Equal(oidPBEWithSHAAnd128BitRC2CBC),
		algorithm.Algorithm.Equal(oidPBEWithSHAAnd40BitRC2CBC):
		if !cfg.policy.allowsEncryption(algorithm.Algorithm) {
			return fmt.Errorf("%w: encryption algorithm %s is not allowed by policy",
				ErrPolicyRejected, algorithm.Algorithm)
		}
		var params preflightPbeParams
		if err := unmarshal(algorithm.Parameters.FullBytes, &params); err != nil {
			return wrapASN1Error(err)
		}
		if params.Iterations == nil {
			return malformedParameterf("PBE algorithm %s is missing an iteration count", algorithm.Algorithm)
		}
		iterations, err := nonNegativeInt(params.Iterations, "PBE iteration count")
		if err != nil {
			return err
		}
		if err := cfg.policy.checkSalt(params.Salt, "PBE"); err != nil {
			return err
		}
		if err := cfg.policy.checkIterations(int64(iterations), "PBE"); err != nil {
			return err
		}
		return cfg.charge(iterations, pbeLegacyWork(int64(iterations)), "PBE")

	case algorithm.Algorithm.Equal(oidPBES2):
		if !cfg.policy.allowsEncryption(oidPBES2) {
			return fmt.Errorf("%w: encryption algorithm %s is not allowed by policy",
				ErrPolicyRejected, oidPBES2)
		}
		var params preflightPbes2Params
		if err := unmarshal(algorithm.Parameters.FullBytes, &params); err != nil {
			return malformedParameterf("error decoding PBES2 parameters: %v", err)
		}
		if !params.Kdf.Algorithm.Equal(oidPBKDF2) {
			return unknownAlgorithmf("PBES2 KDF algorithm %s", params.Kdf.Algorithm)
		}
		iterations, _, err := preflightPbkdf2ParamsCheck(cfg, params.Kdf, "PBES2", false)
		if err != nil {
			return err
		}
		switch {
		case params.EncryptionScheme.Algorithm.Equal(oidAES128CBC),
			params.EncryptionScheme.Algorithm.Equal(oidAES192CBC),
			params.EncryptionScheme.Algorithm.Equal(oidAES256CBC):
		default:
			return unknownAlgorithmf("PBES2 encryption scheme %s", params.EncryptionScheme.Algorithm)
		}
		if !cfg.policy.allowsEncryption(params.EncryptionScheme.Algorithm) {
			return fmt.Errorf("%w: PBES2 encryption scheme %s is not allowed by policy",
				ErrPolicyRejected, params.EncryptionScheme.Algorithm)
		}
		var iv []byte
		if err := unmarshal(params.EncryptionScheme.Parameters.FullBytes, &iv); err != nil {
			return malformedParameterf("error decoding PBES2 IV: %v", err)
		}
		if len(iv) != 16 {
			return malformedParameterf("invalid IV length in PBES2 encryption scheme (IV length %d does not match block size 16)", len(iv))
		}
		return cfg.charge(iterations, int64(iterations), "PBES2")

	default:
		return unknownAlgorithmf("PBE algorithm %s", algorithm.Algorithm)
	}
}

// preflightPbkdf2ParamsCheck validates a PBKDF2 AlgorithmIdentifier used by
// either PBES2 or PBMAC1.  It returns the iteration count and, when present
// and valid, the key length.  PBMAC1 mandates an explicit KeyLength.
func preflightPbkdf2ParamsCheck(cfg *decodeConfig, kdf pkix.AlgorithmIdentifier, what string, requireKeyLength bool) (iterations int, keyLength int, err error) {
	var params preflightPbkdf2Params
	if e := unmarshal(kdf.Parameters.FullBytes, &params); e != nil {
		return 0, 0, malformedParameterf("error decoding PBKDF2 parameters for %s: %v", what, e)
	}
	if params.Salt.Tag != asn1.TagOctetString {
		return 0, 0, unknownAlgorithmf("only octet string salts are supported for %s/PBKDF2", what)
	}
	if params.Iterations == nil {
		return 0, 0, malformedParameterf("%s PBKDF2 parameters are missing an iteration count", what)
	}
	iter, e := nonNegativeInt(params.Iterations, what+" PBKDF2 iteration count")
	if e != nil {
		return 0, 0, e
	}
	if e := cfg.policy.checkSalt(params.Salt.Bytes, what+" PBKDF2"); e != nil {
		return 0, 0, e
	}
	if e := cfg.policy.checkIterations(int64(iter), what+" PBKDF2"); e != nil {
		return 0, 0, e
	}

	if params.KeyLength != nil {
		kl, e := nonNegativeInt(params.KeyLength, what+" PBKDF2 key length")
		if e != nil {
			return 0, 0, e
		}
		if kl < 1 {
			return 0, 0, malformedParameterf("%s PBKDF2 key length must be at least 1 (got %d)", what, kl)
		}
		if requireKeyLength && kl < 20 {
			return 0, 0, malformedParameterf("PBMAC1 key length %d is too short to be secure (minimum 20 octets)", kl)
		}
		if kl > 64 {
			return 0, 0, malformedParameterf("%s PBKDF2 key length %d is too large (maximum 64 octets)", what, kl)
		}
		keyLength = kl
	} else if requireKeyLength {
		return 0, 0, malformedParameterf("PBMAC1 requires an explicit KeyLength parameter in PBKDF2 parameters")
	}

	if len(params.Prf.Algorithm) != 0 && !knownPbkdf2Prf(params.Prf.Algorithm) {
		return 0, 0, unknownAlgorithmf("%s PBKDF2 PRF %s", what, params.Prf.Algorithm)
	}
	return iter, keyLength, nil
}

func knownMacOid(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(oidSHA1) || oid.Equal(oidSHA256) || oid.Equal(oidSHA512) ||
		oid.Equal(oidHmacWithSHA1) || oid.Equal(oidHmacWithSHA256) || oid.Equal(oidHmacWithSHA512)
}

func knownPbkdf2Prf(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(oidHmacWithSHA1) || oid.Equal(oidHmacWithSHA256) || oid.Equal(oidHmacWithSHA512)
}

// nonNegativeInt converts a parsed ASN.1 INTEGER to a platform int, reporting
// negative values and values that overflow int distinctly.
func nonNegativeInt(v *big.Int, what string) (int, error) {
	if v.Sign() < 0 {
		return 0, fmt.Errorf("%w: %s is negative (%d)", ErrNegativeValue, what, v)
	}
	if !v.IsInt64() || v.Int64() > int64(maxInt) {
		return 0, fmt.Errorf("%w: %s %d is too large", ErrIntegerOverflow, what, v)
	}
	return int(v.Int64()), nil
}

func malformedParameterf(format string, args ...interface{}) error {
	return fmt.Errorf("%w: "+format, append([]interface{}{ErrMalformedParameter}, args...)...)
}

func unknownAlgorithmf(format string, args ...interface{}) error {
	return fmt.Errorf("%w: "+format, append([]interface{}{ErrUnknownAlgorithm}, args...)...)
}
