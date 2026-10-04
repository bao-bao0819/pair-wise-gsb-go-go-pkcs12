// Copyright 2026 Opsmate, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
)

// PasswordPurpose identifies which encryption layer of a PFX file is
// requesting a password.
type PasswordPurpose int

const (
	// PasswordPurposeMAC indicates the password is used to verify the
	// PFX-level MAC, which protects the integrity of the entire file.
	PasswordPurposeMAC PasswordPurpose = iota + 1

	// PasswordPurposeSafeContents indicates the password decrypts an
	// encrypted SafeContents within the AuthenticatedSafe.
	PasswordPurposeSafeContents

	// PasswordPurposeKeyBag indicates the password decrypts a PKCS#8
	// shrouded private key bag inside a SafeContents.
	PasswordPurposeKeyBag
)

func (p PasswordPurpose) String() string {
	switch p {
	case PasswordPurposeMAC:
		return "MAC"
	case PasswordPurposeSafeContents:
		return "SafeContents"
	case PasswordPurposeKeyBag:
		return "KeyBag"
	default:
		return "unknown"
	}
}

// PasswordRequest describes a single request for a password made by
// [DecodeWithPasswordFunc].  It contains only public information: the
// purpose of the password, the position of the SafeContents (and bag)
// within the file, and the algorithm parameters, which are public values
// such as the salt, iteration count, and IV.  It never contains any
// password material.
type PasswordRequest struct {
	// Purpose is the encryption layer that needs the password.
	Purpose PasswordPurpose

	// SafeContentsIndex is the zero-based position of the SafeContents
	// within the AuthenticatedSafe.  It is -1 when Purpose is
	// [PasswordPurposeMAC].
	SafeContentsIndex int

	// BagIndex is the zero-based position of the bag within the
	// SafeContents.  It is -1 unless Purpose is [PasswordPurposeKeyBag].
	BagIndex int

	// Algorithm is the algorithm identifier of the layer, including its
	// public parameters.  For [PasswordPurposeMAC] it is the MAC
	// algorithm; otherwise it is the password-based encryption algorithm.
	Algorithm pkix.AlgorithmIdentifier
}

// PasswordFunc is called by [DecodeWithPasswordFunc] to obtain the password
// for a single encryption layer.  It is called at most once per layer; if
// the returned password fails to decrypt the layer, the layer is left
// locked rather than retried with other candidate passwords.
//
// Return ok = false to decline to provide a password, in which case the
// layer is left locked (opaque) with an error of [ErrPasswordMissing].
//
// PasswordFunc must not log or otherwise retain the request in a way that
// associates it with the returned password.
type PasswordFunc func(req PasswordRequest) (password string, ok bool)

// SinglePassword returns a [PasswordFunc] that responds to every request
// with the same password, emulating the behavior of the single-password
// decoding functions such as [DecodeChain].
func SinglePassword(password string) PasswordFunc {
	return func(PasswordRequest) (string, bool) {
		return password, true
	}
}

// DecodedPFX is the result of [DecodeWithPasswordFunc].
type DecodedPFX struct {
	// SafeContents contains one entry per SafeContents in the
	// AuthenticatedSafe, in file order.
	SafeContents []DecodedSafeContents
}

// FullyDecrypted reports whether every SafeContents and every bag in the
// PFX was successfully decrypted and parsed, with no opaque layers and no
// errors.
func (d *DecodedPFX) FullyDecrypted() bool {
	for _, sc := range d.SafeContents {
		if sc.Opaque || sc.Err != nil {
			return false
		}
		for _, bag := range sc.Bags {
			if bag.Opaque || bag.Err != nil {
				return false
			}
		}
	}
	return true
}

// DecodedSafeContents is the decoded form of one SafeContents within the
// AuthenticatedSafe.
type DecodedSafeContents struct {
	// Opaque is true if this SafeContents is encrypted and could not be
	// decrypted, either because no password was provided, the password
	// was incorrect, or the algorithm is unsupported.  An opaque
	// SafeContents has no bags.
	Opaque bool

	// Err describes why the SafeContents is opaque or could not be
	// parsed: [ErrPasswordMissing] if no password was provided,
	// [ErrDecryption] if decryption failed (which is indistinguishable
	// from an incorrect password), a [NotImplementedError] if the
	// algorithm is unsupported, or a parsing error.  Err never contains
	// password material.
	Err error

	// Bags contains the decoded bags, in file order.  It is empty if the
	// SafeContents is opaque.
	Bags []DecodedBag
}

// DecodedBag is the decoded form of a single safe bag.
type DecodedBag struct {
	// ID is the bag type identifier (e.g. certBag, keyBag,
	// pkcs8ShroudedKeyBag).
	ID asn1.ObjectIdentifier

	// Opaque is true if this bag is a PKCS#8 shrouded key bag that could
	// not be decrypted, either because no password was provided, the
	// password was incorrect, or the algorithm is unsupported.
	Opaque bool

	// Err describes why the bag is opaque or could not be parsed:
	// [ErrPasswordMissing] if no password was provided, [ErrDecryption]
	// if decryption failed (which is indistinguishable from an incorrect
	// password), a [NotImplementedError] if the algorithm or bag type is
	// unsupported, or a parsing error.  Err never contains password
	// material.
	Err error

	// Certificates contains the certificates from a cert bag.
	Certificates []*x509.Certificate

	// PrivateKey contains the private key from a key bag or a
	// successfully decrypted PKCS#8 shrouded key bag.
	PrivateKey interface{}
}

// DecodeWithPasswordFunc decodes pfxData, which must be a DER-encoded
// PKCS#12 file, obtaining the password for each encryption layer from
// passwordFn.
//
// Unlike [DecodeChain], this function supports files whose layers use
// different passwords: the PFX-level MAC, each encrypted SafeContents, and
// each PKCS#8 shrouded key bag may all have distinct passwords.  The
// passwordFn callback is invoked with a [PasswordRequest] describing the
// purpose and position of the layer, and may return a password or decline.
//
// If the file has a MAC, it is verified first, before any other password
// is requested; if verification fails, an error is returned and passwordFn
// is never called for a decryption purpose.  Each layer's password is
// requested at most once.  Layers that cannot be unlocked are retained in
// the result with an explicit opaque status, while the other layers are
// still decoded and returned.
//
// To decode a file that uses a single password for all layers, pass
// [SinglePassword](password).
func DecodeWithPasswordFunc(pfxData []byte, passwordFn PasswordFunc) (*DecodedPFX, error) {
	pfx := new(pfxPdu)
	if err := unmarshal(pfxData, pfx); err != nil {
		return nil, errors.New("pkcs12: error reading P12 data: " + err.Error())
	}

	if pfx.Version != 3 {
		return nil, NotImplementedError("can only decode v3 PFX PDU's")
	}

	if !pfx.AuthSafe.ContentType.Equal(oidDataContentType) {
		return nil, NotImplementedError("only password-protected PFX is implemented")
	}

	// unmarshal the explicit bytes in the content for type 'data'
	if err := unmarshal(pfx.AuthSafe.Content.Bytes, &pfx.AuthSafe.Content); err != nil {
		return nil, err
	}

	// Verify the MAC before requesting any decryption passwords, so that
	// a tampered file never causes decryption passwords to be requested.
	if len(pfx.MacData.Mac.Algorithm.Algorithm) != 0 {
		password, ok := passwordFn(PasswordRequest{
			Purpose:           PasswordPurposeMAC,
			SafeContentsIndex: -1,
			BagIndex:          -1,
			Algorithm:         pfx.MacData.Mac.Algorithm,
		})
		if !ok {
			return nil, ErrPasswordMissing
		}
		encodedPassword, err := bmpStringZeroTerminated(password)
		if err != nil {
			return nil, ErrIncorrectPassword
		}
		if err := verifyMac(&pfx.MacData, pfx.AuthSafe.Content.Bytes, encodedPassword); err != nil {
			if err == ErrIncorrectPassword && len(encodedPassword) == 2 && encodedPassword[0] == 0 && encodedPassword[1] == 0 {
				// some implementations use an empty byte array
				// for the empty string password try one more
				// time with empty-empty password
				err = verifyMac(&pfx.MacData, pfx.AuthSafe.Content.Bytes, nil)
			}
			if err != nil {
				return nil, err
			}
		}
	}

	var authenticatedSafe []contentInfo
	if err := unmarshal(pfx.AuthSafe.Content.Bytes, &authenticatedSafe); err != nil {
		return nil, err
	}

	decoded := &DecodedPFX{}
	for i, ci := range authenticatedSafe {
		decoded.SafeContents = append(decoded.SafeContents, decodeSafeContents(ci, i, passwordFn))
	}
	return decoded, nil
}

func decodeSafeContents(ci contentInfo, index int, passwordFn PasswordFunc) DecodedSafeContents {
	var sc DecodedSafeContents
	var data []byte

	switch {
	case ci.ContentType.Equal(oidDataContentType):
		if err := unmarshal(ci.Content.Bytes, &data); err != nil {
			sc.Opaque = true
			sc.Err = err
			return sc
		}
	case ci.ContentType.Equal(oidEncryptedDataContentType):
		var encryptedData encryptedData
		if err := unmarshal(ci.Content.Bytes, &encryptedData); err != nil {
			sc.Opaque = true
			sc.Err = err
			return sc
		}
		if encryptedData.Version != 0 {
			sc.Opaque = true
			sc.Err = NotImplementedError("only version 0 of EncryptedData is supported")
			return sc
		}
		password, ok := passwordFn(PasswordRequest{
			Purpose:           PasswordPurposeSafeContents,
			SafeContentsIndex: index,
			BagIndex:          -1,
			Algorithm:         encryptedData.EncryptedContentInfo.ContentEncryptionAlgorithm,
		})
		if !ok {
			sc.Opaque = true
			sc.Err = ErrPasswordMissing
			return sc
		}
		encodedPassword, err := bmpStringZeroTerminated(password)
		if err != nil {
			sc.Opaque = true
			sc.Err = ErrIncorrectPassword
			return sc
		}
		if data, err = pbDecrypt(encryptedData.EncryptedContentInfo, encodedPassword); err != nil {
			sc.Opaque = true
			sc.Err = err
			return sc
		}
	default:
		sc.Opaque = true
		sc.Err = NotImplementedError("only data and encryptedData content types are supported in authenticated safe")
		return sc
	}

	var bags []safeBag
	if err := unmarshal(data, &bags); err != nil {
		sc.Opaque = true
		sc.Err = err
		return sc
	}
	for j, bag := range bags {
		sc.Bags = append(sc.Bags, decodeBag(bag, index, j, passwordFn))
	}
	return sc
}

func decodeBag(bag safeBag, safeContentsIndex, bagIndex int, passwordFn PasswordFunc) DecodedBag {
	decoded := DecodedBag{ID: bag.Id}

	switch {
	case bag.Id.Equal(oidCertBag):
		certsData, err := decodeCertBag(bag.Value.Bytes)
		if err != nil {
			decoded.Err = err
			return decoded
		}
		certs, err := x509.ParseCertificates(certsData)
		if err != nil {
			decoded.Err = err
			return decoded
		}
		decoded.Certificates = certs

	case bag.Id.Equal(oidKeyBag):
		privateKey, err := x509.ParsePKCS8PrivateKey(bag.Value.Bytes)
		if err != nil {
			decoded.Err = err
			return decoded
		}
		decoded.PrivateKey = privateKey

	case bag.Id.Equal(oidPKCS8ShroundedKeyBag):
		pkinfo := new(encryptedPrivateKeyInfo)
		if err := unmarshal(bag.Value.Bytes, pkinfo); err != nil {
			decoded.Opaque = true
			decoded.Err = errors.New("pkcs12: error decoding PKCS#8 shrouded key bag: " + err.Error())
			return decoded
		}
		password, ok := passwordFn(PasswordRequest{
			Purpose:           PasswordPurposeKeyBag,
			SafeContentsIndex: safeContentsIndex,
			BagIndex:          bagIndex,
			Algorithm:         pkinfo.AlgorithmIdentifier,
		})
		if !ok {
			decoded.Opaque = true
			decoded.Err = ErrPasswordMissing
			return decoded
		}
		encodedPassword, err := bmpStringZeroTerminated(password)
		if err != nil {
			decoded.Opaque = true
			decoded.Err = ErrIncorrectPassword
			return decoded
		}
		pkData, err := pbDecrypt(pkinfo, encodedPassword)
		if err != nil {
			decoded.Opaque = true
			decoded.Err = err
			return decoded
		}
		privateKey, err := x509.ParsePKCS8PrivateKey(pkData)
		if err != nil {
			// The padding check passed but the plaintext is not a
			// PKCS#8 private key, which is indistinguishable from an
			// incorrect password.
			decoded.Opaque = true
			decoded.Err = errors.New("pkcs12: error parsing decrypted PKCS#8 private key: " + err.Error())
			return decoded
		}
		decoded.PrivateKey = privateKey

	default:
		decoded.Opaque = true
		decoded.Err = NotImplementedError("unsupported bag type " + bag.Id.String())
	}
	return decoded
}
