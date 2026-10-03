package pkcs12

import (
	"encoding/asn1"
	"errors"
)

type rawSafeBag struct {
	Id         asn1.ObjectIdentifier
	Value      asn1.RawValue        `asn1:"tag:0,explicit"`
	Attributes []rawPKCS12Attribute `asn1:"set,optional"`
}

type rawPKCS12Attribute struct {
	Id    asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

// Repackage verifies pfxData with oldPassword, decrypts its supported safe
// contents, and produces a new PFX using enc's algorithms and newPassword.
//
// The order of authenticated safes, safe bags, and attributes is retained.
// Friendly names, local key identifiers, duplicate attributes, and unknown
// attributes are retained as DER. Unknown and secret safe bags are retained
// only inside encrypted safe contents; otherwise Repackage returns an error
// instead of exposing or dropping them.
//
// Passwordless follows the same password semantics as [Encoder.Encode]: it
// produces no MAC or encryption and requires newPassword to be empty.
func (enc *Encoder) Repackage(pfxData []byte, oldPassword, newPassword string) ([]byte, error) {
	if enc == nil {
		return nil, errors.New("pkcs12: nil encoder")
	}
	passwordless := enc.macAlgorithm == nil && enc.certAlgorithm == nil && enc.keyAlgorithm == nil
	if passwordless && newPassword != "" {
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

	pfx := new(pfxPdu)
	if err := unmarshal(pfxData, pfx); err != nil {
		return nil, errors.New("pkcs12: error reading P12 data: " + err.Error())
	}
	if pfx.Version != 3 {
		return nil, NotImplementedError("can only decode v3 PFX PDU's")
	}
	if !pfx.AuthSafe.ContentType.Equal(oidDataContentType) {
		return nil, NotImplementedError("only data authenticated safes are supported")
	}

	if err := unmarshal(pfx.AuthSafe.Content.Bytes, &pfx.AuthSafe.Content); err != nil {
		return nil, err
	}
	authenticatedSafeBytes := pfx.AuthSafe.Content.Bytes
	oldEncodedPassword, err = verifyRepackageMac(pfx, oldEncodedPassword)
	if err != nil {
		return nil, err
	}

	var authenticatedSafe []contentInfo
	if err := unmarshal(authenticatedSafeBytes, &authenticatedSafe); err != nil {
		return nil, err
	}
	if len(authenticatedSafe) == 0 {
		return nil, errors.New("pkcs12: authenticated safe is empty")
	}

	newAuthenticatedSafe := make([]contentInfo, len(authenticatedSafe))
	for i := range authenticatedSafe {
		data, _, err := decodeAuthenticatedSafeContentInfo(authenticatedSafe[i], oldEncodedPassword)
		if err != nil {
			if oldPassword == "" {
				if retryData, _, retryErr := decodeAuthenticatedSafeContentInfo(authenticatedSafe[i], nil); retryErr == nil {
					data, err = retryData, nil
				}
			}
			if err != nil {
				return nil, err
			}
		}

		var bags []rawSafeBag
		if err := unmarshal(data, &bags); err != nil {
			return nil, err
		}

		info := inspectSafeBags(bags)
		outerAlgorithm := rewalkOuterAlgorithm(enc, info, passwordless)
		parentEncrypted := outerAlgorithm != nil
		for j := range bags {
			bags[j], err = rewrapSafeBag(bags[j], enc, oldEncodedPassword, newEncodedPassword, parentEncrypted, passwordless)
			if err != nil {
				return nil, err
			}
		}

		newAuthenticatedSafe[i], err = makeSafeContents(enc.rand, rawBagsToSafeBags(bags), outerAlgorithm, newEncodedPassword, enc.encryptionIterations, enc.saltLen)
		if err != nil {
			return nil, err
		}
	}

	newAuthenticatedSafeBytes, err := asn1.Marshal(newAuthenticatedSafe)
	if err != nil {
		return nil, err
	}

	pfx.MacData = macData{}
	if !passwordless {
		macSalt := make([]byte, enc.saltLen)
		if err := readRandom(enc.rand, macSalt); err != nil {
			return nil, err
		}
		pfx.MacData.Mac.Algorithm.Algorithm = enc.macAlgorithm
		if enc.macAlgorithm.Equal(oidPBMAC1) {
			pfx.MacData.Mac.Algorithm.Parameters.FullBytes, err = makePBMAC1Parameters(macSalt, enc.macIterations)
		} else {
			pfx.MacData.MacSalt = macSalt
			pfx.MacData.Iterations = enc.macIterations
		}
		if err != nil {
			return nil, err
		}
		if err := computeMac(&pfx.MacData, newAuthenticatedSafeBytes, newEncodedPassword); err != nil {
			return nil, err
		}
	}

	pfx.AuthSafe.Content = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true}
	if pfx.AuthSafe.Content.Bytes, err = asn1.Marshal(newAuthenticatedSafeBytes); err != nil {
		return nil, err
	}
	return asn1.Marshal(*pfx)
}

func verifyRepackageMac(pfx *pfxPdu, password []byte) ([]byte, error) {
	if len(pfx.MacData.Mac.Algorithm.Algorithm) == 0 {
		if len(password) != 2 || password[0] != 0 || password[1] != 0 {
			return nil, errors.New("pkcs12: no MAC in data")
		}
		return password, nil
	}
	if err := verifyMac(&pfx.MacData, pfx.AuthSafe.Content.Bytes, password); err != nil {
		if err == ErrIncorrectPassword && len(password) == 2 {
			if retryErr := verifyMac(&pfx.MacData, pfx.AuthSafe.Content.Bytes, nil); retryErr == nil {
				return nil, nil
			}
		}
		return nil, err
	}
	return password, nil
}

func decodeAuthenticatedSafeContentInfo(ci contentInfo, password []byte) ([]byte, bool, error) {
	switch {
	case ci.ContentType.Equal(oidDataContentType):
		var data []byte
		if err := unmarshal(ci.Content.Bytes, &data); err != nil {
			return nil, false, err
		}
		return data, false, nil
	case ci.ContentType.Equal(oidEncryptedDataContentType):
		var data encryptedData
		if err := unmarshal(ci.Content.Bytes, &data); err != nil {
			return nil, false, err
		}
		if data.Version != 0 {
			return nil, false, NotImplementedError("only version 0 of EncryptedData is supported")
		}
		plaintext, err := pbDecrypt(data.EncryptedContentInfo, password)
		return plaintext, true, err
	default:
		return nil, false, NotImplementedError("only data and encryptedData content types are supported in authenticated safe")
	}
}

type rewalkInfo struct {
	hasOtherBag bool
}

func inspectSafeBags(bags []rawSafeBag) rewalkInfo {
	var info rewalkInfo
	for _, bag := range bags {
		switch {
		case bag.Id.Equal(oidSafeContentsBag):
			var nestedBags []rawSafeBag
			if err := unmarshal(bag.Value.Bytes, &nestedBags); err == nil && inspectSafeBags(nestedBags).hasOtherBag {
				info.hasOtherBag = true
			}
		case bag.Id.Equal(oidKeyBag), bag.Id.Equal(oidPKCS8ShroundedKeyBag):
		default:
			info.hasOtherBag = true
		}
	}
	return info
}

func rewalkOuterAlgorithm(enc *Encoder, info rewalkInfo, passwordless bool) asn1.ObjectIdentifier {
	if passwordless {
		return nil
	}
	if info.hasOtherBag {
		return enc.certAlgorithm
	}
	return nil
}

func rewrapSafeBag(bag rawSafeBag, enc *Encoder, oldPassword, newPassword []byte, parentEncrypted, passwordless bool) (rawSafeBag, error) {
	switch {
	case bag.Id.Equal(oidKeyBag):
		if parentEncrypted || passwordless {
			return bag, nil
		}
		data, err := encodePkcs8ShroudedKeyBagData(enc.rand, bag.Value.Bytes, enc.keyAlgorithm, newPassword, enc.encryptionIterations, enc.saltLen)
		if err != nil {
			return rawSafeBag{}, err
		}
		bag.Id = oidPKCS8ShroundedKeyBag
		bag.Value.FullBytes = nil
		bag.Value.Bytes = data
		return bag, nil
	case bag.Id.Equal(oidPKCS8ShroundedKeyBag):
		pkData, err := decodePkcs8ShroudedKeyBagData(bag.Value.Bytes, oldPassword)
		if err != nil {
			return rawSafeBag{}, err
		}
		if passwordless || parentEncrypted {
			bag.Id = oidKeyBag
			bag.Value.FullBytes = nil
			bag.Value.Bytes = pkData
			return bag, nil
		}
		data, err := encodePkcs8ShroudedKeyBagData(enc.rand, pkData, enc.keyAlgorithm, newPassword, enc.encryptionIterations, enc.saltLen)
		if err != nil {
			return rawSafeBag{}, err
		}
		bag.Value.FullBytes = nil
		bag.Value.Bytes = data
		return bag, nil
	case bag.Id.Equal(oidCertBag) || bag.Id.Equal(oidCRLBag):
		return bag, nil
	case bag.Id.Equal(oidSecretBag):
		if !parentEncrypted {
			return rawSafeBag{}, NotImplementedError("cannot safely repackage an unencrypted secret bag")
		}
		return bag, nil
	case bag.Id.Equal(oidSafeContentsBag):
		var nestedBags []rawSafeBag
		if err := unmarshal(bag.Value.Bytes, &nestedBags); err != nil {
			return rawSafeBag{}, err
		}
		var err error
		for i := range nestedBags {
			nestedBags[i], err = rewrapSafeBag(nestedBags[i], enc, oldPassword, newPassword, parentEncrypted, passwordless)
			if err != nil {
				return rawSafeBag{}, err
			}
		}
		bag.Value.FullBytes = nil
		bag.Value.Bytes, err = asn1.Marshal(nestedBags)
		if err != nil {
			return rawSafeBag{}, err
		}
		return bag, nil
	default:
		if !parentEncrypted {
			return rawSafeBag{}, NotImplementedError("cannot safely repackage safe bag of type " + bag.Id.String())
		}
		return bag, nil
	}
}

func rawBagsToSafeBags(rawBags []rawSafeBag) []safeBag {
	bags := make([]safeBag, len(rawBags))
	for i, rawBag := range rawBags {
		bags[i].Id = rawBag.Id
		bags[i].Value = rawBag.Value
		bags[i].Attributes = make([]pkcs12Attribute, len(rawBag.Attributes))
		for j, rawAttribute := range rawBag.Attributes {
			bags[i].Attributes[j].Id = rawAttribute.Id
			bags[i].Attributes[j].Value = rawAttribute.Value
		}
	}
	return bags
}
