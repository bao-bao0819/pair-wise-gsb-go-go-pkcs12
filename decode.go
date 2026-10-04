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

// PasswordPurpose identifies which encryption layer of a PFX is asking
// for a password.
type PasswordPurpose int

const (
	// PurposeMAC is the outer integrity check (MacData) of the PFX.
	PurposeMAC PasswordPurpose = iota + 1
	// PurposeSafeContents is an encrypted SafeContents (an encryptedData
	// content info) within the authenticated safe.
	PurposeSafeContents
	// PurposeKeyBag is a PKCS#8 shrouded key bag within a SafeContents.
	PurposeKeyBag
)

func (p PasswordPurpose) String() string {
	switch p {
	case PurposeMAC:
		return "integrity check"
	case PurposeSafeContents:
		return "encrypted safe contents"
	case PurposeKeyBag:
		return "shrouded key bag"
	default:
		return "unknown purpose"
	}
}

// PasswordRequest describes a single request for a password to unlock one
// encryption layer of a PFX file.
type PasswordRequest struct {
	// Purpose identifies the encryption layer that needs a password.
	Purpose PasswordPurpose

	// SafeContentsIndex is the position of the SafeContents within the
	// authenticated safe.  It is -1 when Purpose is PurposeMAC.
	SafeContentsIndex int

	// BagIndex is the position of the safe bag within its SafeContents.
	// It is -1 unless Purpose is PurposeKeyBag.
	BagIndex int

	// Algorithm is the algorithm identifier of the MAC or encryption
	// algorithm protecting this layer, including its public parameters
	// (such as the salt and iteration count).  It never contains any
	// password material.
	Algorithm pkix.AlgorithmIdentifier
}

// PasswordFunc is called by DecodeWithPasswordFunc each time an encryption
// layer of a PFX needs a password.  It is called exactly once per layer:
// first for the outer integrity check, then, only if the integrity check
// passed, for each encrypted SafeContents and each shrouded key bag, in
// the order in which they appear in the PFX.
//
// The callback should return the password for the requested layer, or
// ok == false to decline.  Declining the integrity check aborts decoding
// with ErrNoPassword; declining any other layer leaves the corresponding
// bags in an opaque state without affecting other bags.
//
// A wrong password is never retried and no other candidate passwords are
// tried: the layer is simply left locked.
type PasswordFunc func(req PasswordRequest) (password string, ok bool)

// OpaqueReason explains why a bag could not be decrypted.
type OpaqueReason int

const (
	// OpaqueNone indicates that the bag was decrypted successfully.
	OpaqueNone OpaqueReason = iota
	// OpaquePasswordUnavailable indicates that the PasswordFunc declined
	// to provide a password for this layer.
	OpaquePasswordUnavailable
	// OpaqueDecryptionFailed indicates that decryption failed, either
	// because the password was wrong or because the ciphertext was
	// otherwise undecryptable.  These two cases cannot be distinguished.
	OpaqueDecryptionFailed
	// OpaqueUnsupportedAlgorithm indicates that the layer uses an
	// encryption algorithm that this package does not support.
	OpaqueUnsupportedAlgorithm
)

func (r OpaqueReason) String() string {
	switch r {
	case OpaqueNone:
		return "decrypted"
	case OpaquePasswordUnavailable:
		return "no password provided"
	case OpaqueDecryptionFailed:
		return "decryption failed"
	case OpaqueUnsupportedAlgorithm:
		return "unsupported algorithm"
	default:
		return "unknown reason"
	}
}

// DecodedBag is a single safe bag produced by DecodeWithPasswordFunc, or
// an opaque placeholder for a bag (or an entire SafeContents) that could
// not be decrypted.
type DecodedBag struct {
	// SafeContentsIndex is the position of the SafeContents within the
	// authenticated safe that contained this bag.
	SafeContentsIndex int

	// Index is the position of the bag within its SafeContents.  It is -1
	// if this entry is a placeholder for an entire SafeContents that could
	// not be decrypted.
	Index int

	// Opaque is true if the bag is still encrypted.  Id, Value,
	// Certificate, and PrivateKey are then unset (except that Id is still
	// set for shrouded key bags, whose type is visible without
	// decryption).
	Opaque bool

	// Reason explains why the bag is opaque.  It is OpaqueNone for
	// decrypted bags.
	Reason OpaqueReason

	// Id is the OID identifying the bag type (e.g. certBag).
	Id asn1.ObjectIdentifier

	// Value is the raw decoded value of the bag.
	Value asn1.RawValue

	// Certificate is the parsed certificate, for cert bags.
	Certificate *x509.Certificate

	// PrivateKey is the parsed private key, for key bags and successfully
	// decrypted PKCS#8 shrouded key bags.
	PrivateKey interface{}
}

// DecodeWithPasswordFunc decodes a DER-encoded PFX file that may use a
// different password for each encryption layer: one password for the outer
// integrity check and separate passwords for individual encrypted
// SafeContents and PKCS#8 shrouded key bags.
//
// The outer integrity check is always performed first.  If the PFX has no
// MAC, if the callback declines to provide the integrity password, or if
// the check fails, decoding stops immediately and the callback is never
// invoked for any inner encryption layer.  A failed integrity check is
// reported as ErrIntegrity, a missing integrity password as ErrNoPassword.
//
// Each remaining encryption layer is requested from the callback exactly
// once.  Bags that cannot be unlocked - because no password was provided,
// because decryption failed, or because the algorithm is unsupported - are
// returned as opaque entries with an explicit reason, while all bags that
// were successfully decrypted are delivered normally.
//
// Passwords are never included in returned errors.  To decode a PFX that
// uses a single password for every layer, use Decode, DecodeChain, or
// DecodeTrustStore.
func DecodeWithPasswordFunc(pfxData []byte, passwordFunc PasswordFunc) ([]DecodedBag, error) {
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

	// The outer integrity check must pass before any password is requested
	// for an inner encryption layer.
	if len(pfx.MacData.Mac.Algorithm.Algorithm) == 0 {
		return nil, errors.New("pkcs12: no MAC in data")
	}
	macPassword, ok, err := requestPassword(passwordFunc, PasswordRequest{
		Purpose:           PurposeMAC,
		SafeContentsIndex: -1,
		BagIndex:          -1,
		Algorithm:         pfx.MacData.Mac.Algorithm,
	})
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNoPassword
	}
	if err := verifyMac(&pfx.MacData, pfx.AuthSafe.Content.Bytes, macPassword); err != nil {
		var ni NotImplementedError
		if errors.As(err, &ni) {
			return nil, err
		}
		return nil, ErrIntegrity
	}

	var authenticatedSafe []contentInfo
	if err := unmarshal(pfx.AuthSafe.Content.Bytes, &authenticatedSafe); err != nil {
		return nil, err
	}

	var bags []DecodedBag
	for safeContentsIndex, ci := range authenticatedSafe {
		var data []byte

		switch {
		case ci.ContentType.Equal(oidDataContentType):
			if err := unmarshal(ci.Content.Bytes, &data); err != nil {
				return nil, err
			}
		case ci.ContentType.Equal(oidEncryptedDataContentType):
			var encryptedData encryptedData
			if err := unmarshal(ci.Content.Bytes, &encryptedData); err != nil {
				return nil, err
			}
			if encryptedData.Version != 0 {
				return nil, NotImplementedError("only version 0 of EncryptedData is supported")
			}
			password, ok, err := requestPassword(passwordFunc, PasswordRequest{
				Purpose:           PurposeSafeContents,
				SafeContentsIndex: safeContentsIndex,
				BagIndex:          -1,
				Algorithm:         encryptedData.EncryptedContentInfo.ContentEncryptionAlgorithm,
			})
			if err != nil {
				return nil, err
			}
			if !ok {
				bags = append(bags, opaqueSafeContents(safeContentsIndex, OpaquePasswordUnavailable))
				continue
			}
			if data, err = pbDecrypt(encryptedData.EncryptedContentInfo, password); err != nil {
				bags = append(bags, opaqueSafeContents(safeContentsIndex, opaqueReasonFor(err)))
				continue
			}
		default:
			return nil, NotImplementedError("only data and encryptedData content types are supported in authenticated safe")
		}

		decoded, err := decodeSafeContentsBags(data, safeContentsIndex, passwordFunc)
		if err != nil {
			return nil, err
		}
		bags = append(bags, decoded...)
	}

	return bags, nil
}

// requestPassword asks passwordFunc for the password for one encryption
// layer and returns it encoded as a zero-terminated BMP string.  It is the
// only place where the callback is invoked, guaranteeing that each layer
// asks exactly once.
func requestPassword(passwordFunc PasswordFunc, req PasswordRequest) (encodedPassword []byte, ok bool, err error) {
	if passwordFunc == nil {
		return nil, false, nil
	}
	password, ok := passwordFunc(req)
	if !ok {
		return nil, false, nil
	}
	encodedPassword, err = bmpStringZeroTerminated(password)
	if err != nil {
		return nil, false, err
	}
	return encodedPassword, true, nil
}

// opaqueSafeContents returns an opaque placeholder for an entire
// SafeContents that could not be decrypted.
func opaqueSafeContents(safeContentsIndex int, reason OpaqueReason) DecodedBag {
	return DecodedBag{
		SafeContentsIndex: safeContentsIndex,
		Index:             -1,
		Opaque:            true,
		Reason:            reason,
	}
}

// opaqueReasonFor maps a decryption error to an opaque reason.
func opaqueReasonFor(err error) OpaqueReason {
	var ni NotImplementedError
	if errors.As(err, &ni) {
		return OpaqueUnsupportedAlgorithm
	}
	return OpaqueDecryptionFailed
}

func decodeSafeContentsBags(data []byte, safeContentsIndex int, passwordFunc PasswordFunc) ([]DecodedBag, error) {
	var safeContents []safeBag
	if err := unmarshal(data, &safeContents); err != nil {
		return nil, err
	}

	var bags []DecodedBag
	for bagIndex, bag := range safeContents {
		decoded := DecodedBag{
			SafeContentsIndex: safeContentsIndex,
			Index:             bagIndex,
			Id:                bag.Id,
			Value:             bag.Value,
		}

		switch {
		case bag.Id.Equal(oidCertBag):
			certsData, err := decodeCertBag(bag.Value.Bytes)
			if err != nil {
				return nil, err
			}
			certs, err := x509.ParseCertificates(certsData)
			if err != nil {
				return nil, err
			}
			if len(certs) != 1 {
				return nil, errors.New("pkcs12: expected exactly one certificate in the certBag")
			}
			decoded.Certificate = certs[0]

		case bag.Id.Equal(oidKeyBag):
			privateKey, err := x509.ParsePKCS8PrivateKey(bag.Value.Bytes)
			if err != nil {
				return nil, err
			}
			decoded.PrivateKey = privateKey

		case bag.Id.Equal(oidPKCS8ShroundedKeyBag):
			pkinfo := new(encryptedPrivateKeyInfo)
			if err := unmarshal(bag.Value.Bytes, pkinfo); err != nil {
				return nil, errors.New("pkcs12: error decoding PKCS#8 shrouded key bag: " + err.Error())
			}

			password, ok, err := requestPassword(passwordFunc, PasswordRequest{
				Purpose:           PurposeKeyBag,
				SafeContentsIndex: safeContentsIndex,
				BagIndex:          bagIndex,
				Algorithm:         pkinfo.AlgorithmIdentifier,
			})
			if err != nil {
				return nil, err
			}
			if !ok {
				bags = append(bags, DecodedBag{
					SafeContentsIndex: safeContentsIndex,
					Index:             bagIndex,
					Opaque:            true,
					Reason:            OpaquePasswordUnavailable,
					Id:                bag.Id,
				})
				continue
			}

			pkData, err := pbDecrypt(pkinfo, password)
			if err != nil {
				bags = append(bags, DecodedBag{
					SafeContentsIndex: safeContentsIndex,
					Index:             bagIndex,
					Opaque:            true,
					Reason:            opaqueReasonFor(err),
					Id:                bag.Id,
				})
				continue
			}

			privateKey, err := x509.ParsePKCS8PrivateKey(pkData)
			if err != nil {
				return nil, errors.New("pkcs12: error parsing PKCS#8 private key: " + err.Error())
			}
			decoded.PrivateKey = privateKey
		}

		bags = append(bags, decoded)
	}

	return bags, nil
}
