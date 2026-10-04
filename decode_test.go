// Copyright 2026 Opsmate, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func makeTestCertificate(t *testing.T, commonName string) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

func mustBMPString(t *testing.T, password string) []byte {
	t.Helper()
	encoded, err := bmpStringZeroTerminated(password)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// buildMultiPasswordPFX builds a PFX with two independently-encrypted
// SafeContents and an outer MAC, each with its own password:
//   - SafeContents 0 is encrypted with sc0Password and contains a cert bag.
//   - SafeContents 1 is encrypted with sc1Password and contains a PKCS#8
//     shrouded key bag encrypted with keyPassword.
//   - The PFX MAC uses macPassword.
func buildMultiPasswordPFX(t *testing.T, macPassword, sc0Password, sc1Password, keyPassword string) (pfxData []byte, key *rsa.PrivateKey, cert *x509.Certificate) {
	t.Helper()

	key, cert = makeTestCertificate(t, "multi-password test")

	certBag, err := makeCertBag(cert.Raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	safeContents0, err := makeSafeContents(rand.Reader, []safeBag{*certBag}, oidPBEWithSHAAnd3KeyTripleDESCBC, mustBMPString(t, sc0Password), 2048, 8)
	if err != nil {
		t.Fatal(err)
	}

	shroudedKey, err := encodePkcs8ShroudedKeyBag(rand.Reader, key, oidPBEWithSHAAnd3KeyTripleDESCBC, mustBMPString(t, keyPassword), 2048, 8)
	if err != nil {
		t.Fatal(err)
	}
	keyBag := safeBag{
		Id: oidPKCS8ShroundedKeyBag,
		Value: asn1.RawValue{
			Class:      2,
			Tag:        0,
			IsCompound: true,
			Bytes:      shroudedKey,
		},
	}
	safeContents1, err := makeSafeContents(rand.Reader, []safeBag{keyBag}, oidPBEWithSHAAnd3KeyTripleDESCBC, mustBMPString(t, sc1Password), 2048, 8)
	if err != nil {
		t.Fatal(err)
	}

	authenticatedSafeBytes, err := asn1.Marshal([]contentInfo{safeContents0, safeContents1})
	if err != nil {
		t.Fatal(err)
	}

	var pfx pfxPdu
	pfx.Version = 3

	macSalt := make([]byte, 8)
	if _, err := rand.Read(macSalt); err != nil {
		t.Fatal(err)
	}
	pfx.MacData.Mac.Algorithm.Algorithm = oidSHA1
	pfx.MacData.MacSalt = macSalt
	pfx.MacData.Iterations = 1
	if err := computeMac(&pfx.MacData, authenticatedSafeBytes, mustBMPString(t, macPassword)); err != nil {
		t.Fatal(err)
	}

	pfx.AuthSafe.ContentType = oidDataContentType
	pfx.AuthSafe.Content.Class = 2
	pfx.AuthSafe.Content.Tag = 0
	pfx.AuthSafe.Content.IsCompound = true
	if pfx.AuthSafe.Content.Bytes, err = asn1.Marshal(authenticatedSafeBytes); err != nil {
		t.Fatal(err)
	}

	if pfxData, err = asn1.Marshal(pfx); err != nil {
		t.Fatal(err)
	}
	return pfxData, key, cert
}

type recordedPasswordRequest struct {
	Purpose           PasswordPurpose
	SafeContentsIndex int
	BagIndex          int
	Algorithm         asn1.ObjectIdentifier
}

// recordingPasswordFunc records every request and answers it using
// responder, which may return ok = false to decline.
func recordingPasswordFunc(requests *[]recordedPasswordRequest, responder func(PasswordRequest) (string, bool)) PasswordFunc {
	return func(req PasswordRequest) (string, bool) {
		*requests = append(*requests, recordedPasswordRequest{
			Purpose:           req.Purpose,
			SafeContentsIndex: req.SafeContentsIndex,
			BagIndex:          req.BagIndex,
			Algorithm:         req.Algorithm.Algorithm,
		})
		return responder(req)
	}
}
