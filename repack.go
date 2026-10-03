// Copyright 2026 Opsmate, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"encoding/asn1"
	"errors"
)

// Repack decrypts and re-encrypts the DER-encoded PKCS#12 file pfxData using
// the parameters and password of the receiver [Encoder].
//
// Unlike decoding the file into a private key and certificates (see
// [DecodeChain]) and re-encoding it, Repack preserves the complete structure
// of the container: the order of the authenticated safe contents and of the
// bags within them, all bag attributes (including friendlyName, localKeyId,
// duplicate attributes, and unknown attributes retained as their original
// DER), and the raw DER of certificate and private key material. Only the
// encryption and MAC are re-generated.
//
// Repack first verifies the original integrity value (the MAC) using
// oldPassword, then decrypts every supported piece of content. The old
// password must be correct; an incorrect one results in [ErrIncorrectPassword].
// A password-less file (one without a MAC or encryption) requires oldPassword
// to be empty, mirroring the semantics of [DecodeTrustStore].
//
// The newPassword is handled according to the receiver's encoding rules: when
// using the [Passwordless] encoder it MUST be empty (and the output contains no
// encryption and no MAC); for every other encoder it may be empty, in which
// case it is treated as a literal empty password (distinct from password-less
// encoding).
//
// Bags whose type Repack cannot safely re-encapsulate are reported with a
// [NotImplementedError]; they are never silently dropped.
//
// All new salts and initialization vectors come from the encoder's random
// source (see [Encoder.WithRand]); a short read or any other error from the
// random source causes Repack to fail rather than produce output based on
// uninitialized randomness.
func (enc *Encoder) Repack(pfxData []byte, oldPassword, newPassword string) (newPfxData []byte, err error) {
	if enc.macAlgorithm == nil && enc.certAlgorithm == nil && enc.keyAlgorithm == nil && newPassword != "" {
		return nil, errors.New("pkcs12: password must be empty")
	}

	oldEncodedPassword, err := bmpStringZeroTerminated(oldPassword)
	if err != nil {
		return nil, err
	}
	newEncodedPassword, err := bmpStringZeroTerminated(newPassword)
	if err != nil {
		return nil, err
	}

	var pfx pfxPdu
	if err = unmarshal(pfxData, &pfx); err != nil {
		return nil, errors.New("pkcs12: error reading P12 data: " + err.Error())
	}
	if pfx.Version != 3 {
		return nil, NotImplementedError("can only decode v3 PFX PDU's")
	}
	if !pfx.AuthSafe.ContentType.Equal(oidDataContentType) {
		return nil, NotImplementedError("only password-protected PFX is implemented")
	}

	// Unwrap the explicit [0] content of the outer 'data' content info.
	if err = unmarshal(pfx.AuthSafe.Content.Bytes, &pfx.AuthSafe.Content); err != nil {
		return nil, err
	}

	// Verify the original MAC before decrypting anything.
	if len(pfx.MacData.Mac.Algorithm.Algorithm) == 0 {
		if !(len(oldEncodedPassword) == 2 && oldEncodedPassword[0] == 0 && oldEncodedPassword[1] == 0) {
			return nil, errors.New("pkcs12: no MAC in data")
		}
	} else if err = verifyMac(&pfx.MacData, pfx.AuthSafe.Content.Bytes, oldEncodedPassword); err != nil {
		if err == ErrIncorrectPassword && len(oldEncodedPassword) == 2 && oldEncodedPassword[0] == 0 && oldEncodedPassword[1] == 0 {
			// Some implementations use an empty byte array (rather than the
			// double-NUL BMP encoding) for the empty password; retry once.
			oldEncodedPassword = nil
			err = verifyMac(&pfx.MacData, pfx.AuthSafe.Content.Bytes, oldEncodedPassword)
		}
		if err != nil {
			return nil, err
		}
	}

	var authenticatedSafe []contentInfo
	if err = unmarshal(pfx.AuthSafe.Content.Bytes, &authenticatedSafe); err != nil {
		return nil, err
	}

	for ciIndex := range authenticatedSafe {
		ci := &authenticatedSafe[ciIndex]
		var data []byte

		switch {
		case ci.ContentType.Equal(oidDataContentType):
			if err = unmarshal(ci.Content.Bytes, &data); err != nil {
				return nil, err
			}
		case ci.ContentType.Equal(oidEncryptedDataContentType):
			var encryptedData encryptedData
			if err = unmarshal(ci.Content.Bytes, &encryptedData); err != nil {
				return nil, err
			}
			if encryptedData.Version != 0 {
				return nil, NotImplementedError("only version 0 of EncryptedData is supported")
			}
			if data, err = pbDecrypt(encryptedData.EncryptedContentInfo, oldEncodedPassword); err != nil {
				return nil, err
			}
		default:
			return nil, NotImplementedError("only data and encryptedData content types are supported in authenticated safe")
		}

		var bags []safeBag
		if err = unmarshal(data, &bags); err != nil {
			return nil, err
		}

		for bagIndex := range bags {
			if bags[bagIndex], err = repackBag(&bags[bagIndex], enc, oldEncodedPassword, newEncodedPassword); err != nil {
				return nil, err
			}
		}

		// Preserve whether this SafeContents was originally encrypted: an
		// unencrypted SafeContents stays unencrypted, and vice versa.
		encryptAlgorithm := enc.certAlgorithm
		if ci.ContentType.Equal(oidDataContentType) {
			encryptAlgorithm = nil
		}
		var newCI contentInfo
		if newCI, err = makeSafeContents(enc.rand, bags, encryptAlgorithm, newEncodedPassword, enc.encryptionIterations, enc.saltLen); err != nil {
			return nil, err
		}
		*ci = newCI
	}

	var newPfx pfxPdu
	newPfx.Version = 3

	var authenticatedSafeBytes []byte
	if authenticatedSafeBytes, err = asn1.Marshal(authenticatedSafe); err != nil {
		return nil, err
	}

	if enc.macAlgorithm != nil {
		macSalt := make([]byte, enc.saltLen)
		if err = readRandom(enc.rand, macSalt); err != nil {
			return nil, err
		}
		newPfx.MacData.Mac.Algorithm.Algorithm = enc.macAlgorithm
		if enc.macAlgorithm.Equal(oidPBMAC1) {
			if newPfx.MacData.Mac.Algorithm.Parameters.FullBytes, err = makePBMAC1Parameters(macSalt, enc.macIterations); err != nil {
				return nil, err
			}
		} else {
			newPfx.MacData.MacSalt = macSalt
			newPfx.MacData.Iterations = enc.macIterations
		}
		if err = computeMac(&newPfx.MacData, authenticatedSafeBytes, newEncodedPassword); err != nil {
			return nil, err
		}
	}

	newPfx.AuthSafe.ContentType = oidDataContentType
	newPfx.AuthSafe.Content.Class = 2
	newPfx.AuthSafe.Content.Tag = 0
	newPfx.AuthSafe.Content.IsCompound = true
	if newPfx.AuthSafe.Content.Bytes, err = asn1.Marshal(authenticatedSafeBytes); err != nil {
		return nil, err
	}

	if newPfxData, err = asn1.Marshal(newPfx); err != nil {
		return nil, errors.New("pkcs12: error writing P12 data: " + err.Error())
	}
	return newPfxData, nil
}

// repackBag rewrites a single safe bag for the destination encoder. The bag's
// attributes and the certificate DER are preserved verbatim; key bags are
// decrypted with the old password and shrouded (or left unshrouded) according
// to the destination encoder. Any bag that cannot be safely re-encapsulated
// causes a NotImplementedError instead of being dropped.
func repackBag(bag *safeBag, enc *Encoder, oldPassword, newPassword []byte) (safeBag, error) {
	switch {
	case bag.Id.Equal(oidCertBag):
		// The certificate DER and all attributes are carried through as-is.
		return *bag, nil

	case bag.Id.Equal(oidKeyBag):
		// The value is already an unencrypted OneAsymmetricKey (PKCS#8).
		if enc.keyAlgorithm == nil {
			return *bag, nil
		}
		shrouded, err := encodeRawPkcs8ShroudedKeyBag(enc.rand, bag.Value.Bytes, enc.keyAlgorithm, newPassword, enc.encryptionIterations, enc.saltLen)
		if err != nil {
			return safeBag{}, err
		}
		return makeShroudedKeyBag(shrouded, bag.Attributes), nil

	case bag.Id.Equal(oidPKCS8ShroundedKeyBag):
		pkData, err := decryptPkcs8ShroudedKeyBag(bag.Value.Bytes, oldPassword)
		if err != nil {
			return safeBag{}, err
		}
		if enc.keyAlgorithm == nil {
			return makePlainKeyBag(pkData, bag.Attributes), nil
		}
		shrouded, err := encodeRawPkcs8ShroudedKeyBag(enc.rand, pkData, enc.keyAlgorithm, newPassword, enc.encryptionIterations, enc.saltLen)
		if err != nil {
			return safeBag{}, err
		}
		return makeShroudedKeyBag(shrouded, bag.Attributes), nil

	default:
		return safeBag{}, NotImplementedError("don't know how to re-encapsulate a safe bag of type " + bag.Id.String())
	}
}

func makePlainKeyBag(pkData []byte, attributes []pkcs12Attribute) safeBag {
	return safeBag{
		Id: oidKeyBag,
		Value: asn1.RawValue{
			Class:      2,
			Tag:        0,
			IsCompound: true,
			Bytes:      pkData,
		},
		Attributes: attributes,
	}
}

func makeShroudedKeyBag(shroudedData []byte, attributes []pkcs12Attribute) safeBag {
	return safeBag{
		Id: oidPKCS8ShroundedKeyBag,
		Value: asn1.RawValue{
			Class:      2,
			Tag:        0,
			IsCompound: true,
			Bytes:      shroudedData,
		},
		Attributes: attributes,
	}
}
