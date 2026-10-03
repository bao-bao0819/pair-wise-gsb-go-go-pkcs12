// Copyright 2015, 2018, 2019 Opsmate, Inc. All rights reserved.
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"io"
)

var (
	// see https://tools.ietf.org/html/rfc7292#appendix-D
	oidCertTypeX509Certificate = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 9, 22, 1})
	oidKeyBag                  = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 1})
	oidPKCS8ShroundedKeyBag    = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 2})
	oidCertBag                 = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 3})
)

type certBag struct {
	Id   asn1.ObjectIdentifier
	Data []byte `asn1:"tag:0,explicit"`
}

func decodePkcs8ShroudedKeyBag(asn1Data, password []byte) (privateKey interface{}, err error) {
	pkData, err := decryptPkcs8ShroudedKeyBag(asn1Data, password)
	if err != nil {
		return nil, err
	}

	if privateKey, err = x509.ParsePKCS8PrivateKey(pkData); err != nil {
		return nil, errors.New("pkcs12: error parsing PKCS#8 private key: " + err.Error())
	}

	return privateKey, nil
}

// decryptPkcs8ShroudedKeyBag decrypts a PKCS#8 shrouded key bag and returns
// the raw, unparsed PKCS#8 private key information. Returning the raw DER
// (rather than a parsed key) allows arbitrary key types and byte-exact key
// material to be carried through a re-encapsulation without loss.
func decryptPkcs8ShroudedKeyBag(asn1Data, password []byte) (pkData []byte, err error) {
	pkinfo := new(encryptedPrivateKeyInfo)
	if err = unmarshal(asn1Data, pkinfo); err != nil {
		return nil, errors.New("pkcs12: error decoding PKCS#8 shrouded key bag: " + err.Error())
	}

	pkData, err = pbDecrypt(pkinfo, password)
	if err != nil {
		return nil, errors.New("pkcs12: error decrypting PKCS#8 shrouded key bag: " + err.Error())
	}

	ret := new(asn1.RawValue)
	if err = unmarshal(pkData, ret); err != nil {
		return nil, errors.New("pkcs12: error unmarshaling decrypted private key: " + err.Error())
	}
	return pkData, nil
}

func encodePkcs8ShroudedKeyBag(rand io.Reader, privateKey interface{}, algoID asn1.ObjectIdentifier, password []byte, iterations int, saltLen int) (asn1Data []byte, err error) {
	var pkData []byte
	if pkData, err = x509.MarshalPKCS8PrivateKey(privateKey); err != nil {
		return nil, errors.New("pkcs12: error encoding PKCS#8 private key: " + err.Error())
	}
	return encodeRawPkcs8ShroudedKeyBag(rand, pkData, algoID, password, iterations, saltLen)
}

// encodeRawPkcs8ShroudedKeyBag encrypts raw PKCS#8 private key information
// without re-marshalling the key, preserving the exact original DER.
func encodeRawPkcs8ShroudedKeyBag(rand io.Reader, pkData []byte, algoID asn1.ObjectIdentifier, password []byte, iterations int, saltLen int) (asn1Data []byte, err error) {
	randomSalt := make([]byte, saltLen)
	if err = readRandom(rand, randomSalt); err != nil {
		return nil, err
	}

	var paramBytes []byte
	if algoID.Equal(oidPBES2) {
		if paramBytes, err = makePBES2Parameters(rand, randomSalt, iterations); err != nil {
			return nil, errors.New("pkcs12: error encoding params: " + err.Error())
		}
	} else {
		if paramBytes, err = asn1.Marshal(pbeParams{Salt: randomSalt, Iterations: iterations}); err != nil {
			return nil, errors.New("pkcs12: error encoding params: " + err.Error())
		}
	}

	var pkinfo encryptedPrivateKeyInfo
	pkinfo.AlgorithmIdentifier.Algorithm = algoID
	pkinfo.AlgorithmIdentifier.Parameters.FullBytes = paramBytes

	if err = pbEncrypt(&pkinfo, pkData, password); err != nil {
		return nil, errors.New("pkcs12: error encrypting PKCS#8 shrouded key bag: " + err.Error())
	}

	if asn1Data, err = asn1.Marshal(pkinfo); err != nil {
		return nil, errors.New("pkcs12: error encoding PKCS#8 shrouded key bag: " + err.Error())
	}

	return asn1Data, nil
}

func decodeCertBag(asn1Data []byte) (x509Certificates []byte, err error) {
	bag := new(certBag)
	if err := unmarshal(asn1Data, bag); err != nil {
		return nil, errors.New("pkcs12: error decoding cert bag: " + err.Error())
	}
	if !bag.Id.Equal(oidCertTypeX509Certificate) {
		return nil, NotImplementedError("only X509 certificates are supported in cert bags")
	}
	return bag.Data, nil
}

func encodeCertBag(x509Certificates []byte) (asn1Data []byte, err error) {
	var bag certBag
	bag.Id = oidCertTypeX509Certificate
	bag.Data = x509Certificates
	if asn1Data, err = asn1.Marshal(bag); err != nil {
		return nil, errors.New("pkcs12: error encoding cert bag: " + err.Error())
	}
	return asn1Data, nil
}
