package pkcs12

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"reflect"
	"testing"
	"time"
)

type shortRandomReader struct{}

func (shortRandomReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return 1, nil
}

type failingRandomReader struct{}

func (failingRandomReader) Read(p []byte) (int, error) {
	return 0, errors.New("random source unavailable")
}

func TestRepackagePreservesStructureAndSecrets(t *testing.T) {
	leafKey, leafCert, caCert := generateTestCertificateChain(t)
	leafPKCS8, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}

	localKeyID := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	unknownOID := asn1.ObjectIdentifier([]int{1, 2, 3, 4, 5, 6, 7, 8, 9})

	leafAttributes := []pkcs12Attribute{
		testBMPStringAttribute(oidFriendlyName, "leaf certificate"),
		testOctetStringSetAttribute(oidLocalKeyID, localKeyID),
	}
	caAttributes := []pkcs12Attribute{
		testBMPStringAttribute(oidFriendlyName, "issuing CA"),
		testOctetStringSetAttribute(oidLocalKeyID, localKeyID),
		testOctetStringSetAttribute(unknownOID, []byte("first unknown attribute")),
		testOctetStringSetAttribute(unknownOID, []byte("second unknown attribute")),
	}

	leafBag := testCertificateBag(t, leafCert.Raw, leafAttributes)
	caBag := testCertificateBag(t, caCert.Raw, caAttributes)
	keyBag := rawSafeBag{
		Id:    oidPKCS8ShroundedKeyBag,
		Value: asn1.RawValue{Class: 2, Tag: 0, IsCompound: true},
		Attributes: testRawAttributes(
			testBMPStringAttribute(oidFriendlyName, "leaf key"),
			testOctetStringSetAttribute(oidLocalKeyID, localKeyID),
			testOctetStringSetAttribute(unknownOID, []byte("first key attribute")),
			testOctetStringSetAttribute(unknownOID, []byte("second key attribute")),
		),
	}
	keyBag.Value.Bytes, err = encodePkcs8ShroudedKeyBagData(rand.Reader, leafPKCS8, LegacyDES.keyAlgorithm, testEncodedPassword(t, "old-password"), LegacyDES.encryptionIterations, LegacyDES.saltLen)
	if err != nil {
		t.Fatal(err)
	}

	originalPFX := testBuildPFX(t, [][]rawSafeBag{{leafBag, caBag}, {keyBag}}, LegacyDES, "old-password")
	originalStructure := testCanonicalGroups(t, originalPFX, "old-password")
	for _, encoder := range []*Encoder{Modern2023, Modern2026} {
		t.Run(encoder.macAlgorithm.String(), func(t *testing.T) {
			rewrappedPFX, err := encoder.Repackage(originalPFX, "old-password", "new-password")
			if err != nil {
				t.Fatalf("Repackage failed: %v", err)
			}
			if _, _, _, err := DecodeChain(rewrappedPFX, "old-password"); !errors.Is(err, ErrIncorrectPassword) {
				t.Fatalf("DecodeChain with old password = %v, want %v", err, ErrIncorrectPassword)
			}

			key, cert, caCerts, err := DecodeChain(rewrappedPFX, "new-password")
			if err != nil {
				t.Fatalf("DecodeChain with new password failed: %v", err)
			}
			if !testSamePrivateKey(t, key, leafKey) || !cert.Equal(leafCert) || len(caCerts) != 1 || !caCerts[0].Equal(caCert) {
				t.Fatal("rewrapped certificate chain or private key does not match the original")
			}

			rewrappedStructure := testCanonicalGroups(t, rewrappedPFX, "new-password")
			if !reflect.DeepEqual(originalStructure, rewrappedStructure) {
				t.Fatal("rewrapped PFX structure or decrypted secrets differ")
			}
		})
	}

	if _, err := Modern2023.Repackage(originalPFX, "wrong-password", "new-password"); !errors.Is(err, ErrIncorrectPassword) {
		t.Fatalf("Repackage with wrong old password = %v, want %v", err, ErrIncorrectPassword)
	}
}

func TestRepackageRandomSourceFailures(t *testing.T) {
	_, leafCert, caCert := generateTestCertificateChain(t)
	pfx := testBuildPFX(t, [][]rawSafeBag{
		{testCertificateBag(t, leafCert.Raw, nil), testCertificateBag(t, caCert.Raw, nil)},
	}, LegacyDES, "old-password")

	for _, reader := range []interface{ Read([]byte) (int, error) }{shortRandomReader{}, failingRandomReader{}} {
		if _, err := Modern2023.WithRand(reader).Repackage(pfx, "old-password", "new-password"); err == nil {
			t.Fatal("Repackage succeeded with an unreliable random source")
		}
	}
}

func TestRepackagePasswordless(t *testing.T) {
	_, leafCert, caCert := generateTestCertificateChain(t)
	certBags := []rawSafeBag{testCertificateBag(t, leafCert.Raw, nil), testCertificateBag(t, caCert.Raw, nil)}
	pfx := testBuildPFX(t, [][]rawSafeBag{certBags}, Passwordless, "")

	rewrappedPFX, err := Passwordless.Repackage(pfx, "", "")
	if err != nil {
		t.Fatalf("passwordless Repackage failed: %v", err)
	}
	passwordlessStructure := testCanonicalGroups(t, rewrappedPFX, "")
	if len(passwordlessStructure) != 1 || len(passwordlessStructure[0]) != 2 {
		t.Fatalf("passwordless PFX contains %v groups, want one group with two bags", passwordlessStructure)
	}

	if _, err := Passwordless.Repackage(pfx, "", "new-password"); err == nil {
		t.Fatal("passwordless Repackage accepted a non-empty password")
	}

	unknownBag := rawSafeBag{
		Id:    asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 9, 99, 1}),
		Value: asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: testMarshalRaw(t, []byte("unknown"))},
	}
	passwordlessWithUnknown := testBuildPFX(t, [][]rawSafeBag{append(certBags, unknownBag)}, Passwordless, "")
	_, err = Passwordless.Repackage(passwordlessWithUnknown, "", "")
	if _, ok := err.(NotImplementedError); !ok {
		t.Fatalf("passwordless Repackage with unknown bag returned %v, want NotImplementedError", err)
	}

	rewrappedUnknown, err := Modern2023.Repackage(passwordlessWithUnknown, "", "new-password")
	if err != nil {
		t.Fatalf("encrypted Repackage should retain unknown bag: %v", err)
	}
	originalStructure := testCanonicalGroups(t, passwordlessWithUnknown, "")
	rewrappedStructure := testCanonicalGroups(t, rewrappedUnknown, "new-password")
	if !reflect.DeepEqual(originalStructure, rewrappedStructure) {
		t.Fatal("unknown bag was not retained in encrypted output")
	}
}

func TestRepackageEmptyPassword(t *testing.T) {
	leafKey, leafCert, caCert := generateTestCertificateChain(t)
	pfx, err := LegacyDES.Encode(leafKey, leafCert, []*x509.Certificate{caCert}, "")
	if err != nil {
		t.Fatal(err)
	}

	rewrappedPFX, err := Modern2023.Repackage(pfx, "", "")
	if err != nil {
		t.Fatalf("Repackage with an empty password failed: %v", err)
	}
	key, cert, caCerts, err := DecodeChain(rewrappedPFX, "")
	if err != nil {
		t.Fatalf("decoding empty-password PFX failed: %v", err)
	}
	if !testSamePrivateKey(t, key, leafKey) || !cert.Equal(leafCert) || len(caCerts) != 1 || !caCerts[0].Equal(caCert) {
		t.Fatal("empty-password Repackage changed the certificate chain or private key")
	}

	passwordlessPFX, err := Passwordless.EncodeTrustStore([]*x509.Certificate{leafCert, caCert}, "")
	if err != nil {
		t.Fatal(err)
	}
	upgradedPFX, err := Modern2023.Repackage(passwordlessPFX, "", "new-password")
	if err != nil {
		t.Fatalf("Repackage from passwordless input to encrypted output failed: %v", err)
	}
	upgradedStructure := testCanonicalGroups(t, upgradedPFX, "new-password")
	if len(upgradedStructure) != 1 || len(upgradedStructure[0]) != 2 {
		t.Fatalf("upgraded passwordless PFX contains %v groups, want one group with two bags", upgradedStructure)
	}
}

func testSamePrivateKey(t *testing.T, actual, expected interface{}) bool {
	t.Helper()
	actualDER, err := x509.MarshalPKCS8PrivateKey(actual)
	if err != nil {
		t.Fatal(err)
	}
	expectedDER, err := x509.MarshalPKCS8PrivateKey(expected)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Equal(actualDER, expectedDER)
}

func generateTestCertificateChain(t *testing.T) (*rsa.PrivateKey, *x509.Certificate, *x509.Certificate) {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2031, time.January, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "example.test"},
		NotBefore:    time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return leafKey, leafCert, caCert
}

func testEncodedPassword(t *testing.T, password string) []byte {
	t.Helper()
	encodedPassword, err := bmpStringZeroTerminated(password)
	if err != nil {
		t.Fatal(err)
	}
	return encodedPassword
}

func testBMPStringAttribute(id asn1.ObjectIdentifier, value string) pkcs12Attribute {
	bmpValue, err := bmpString(value)
	if err != nil {
		panic(err)
	}
	encodedValue, err := asn1.Marshal(asn1.RawValue{Class: 0, Tag: asn1.TagBMPString, Bytes: bmpValue})
	if err != nil {
		panic(err)
	}
	return pkcs12Attribute{
		Id: id,
		Value: asn1.RawValue{
			Class:      0,
			Tag:        asn1.TagSet,
			IsCompound: true,
			Bytes:      encodedValue,
		},
	}
}

func testOctetStringSetAttribute(id asn1.ObjectIdentifier, value []byte) pkcs12Attribute {
	encodedValue, err := asn1.Marshal(value)
	if err != nil {
		panic(err)
	}
	return pkcs12Attribute{
		Id: id,
		Value: asn1.RawValue{
			Class:      0,
			Tag:        asn1.TagSet,
			IsCompound: true,
			Bytes:      encodedValue,
		},
	}
}

func testRawAttributes(attributes ...pkcs12Attribute) []rawPKCS12Attribute {
	rawAttributes := make([]rawPKCS12Attribute, len(attributes))
	for i, attribute := range attributes {
		rawAttributes[i].Id = attribute.Id
		rawAttributes[i].Value = attribute.Value
	}
	return rawAttributes
}

func testCertificateBag(t *testing.T, certificate []byte, attributes []pkcs12Attribute) rawSafeBag {
	t.Helper()
	certBagData, err := encodeCertBag(certificate)
	if err != nil {
		t.Fatal(err)
	}
	return rawSafeBag{
		Id:         oidCertBag,
		Value:      asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: certBagData},
		Attributes: testRawAttributes(attributes...),
	}
}

func testMarshalRaw(t *testing.T, value []byte) []byte {
	t.Helper()
	raw, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func testBuildPFX(t *testing.T, groups [][]rawSafeBag, enc *Encoder, password string) []byte {
	t.Helper()
	encodedPassword := testEncodedPassword(t, password)
	authenticatedSafe := make([]contentInfo, len(groups))
	for i, bags := range groups {
		algorithm := enc.certAlgorithm
		if testGroupContainsKey(bags) {
			algorithm = nil
		}
		var err error
		authenticatedSafe[i], err = makeSafeContents(rand.Reader, rawBagsToSafeBags(bags), algorithm, encodedPassword, enc.encryptionIterations, enc.saltLen)
		if err != nil {
			t.Fatal(err)
		}
	}

	authenticatedSafeBytes, err := asn1.Marshal(authenticatedSafe)
	if err != nil {
		t.Fatal(err)
	}

	var pfx pfxPdu
	pfx.Version = 3
	passwordless := enc.macAlgorithm == nil && enc.certAlgorithm == nil && enc.keyAlgorithm == nil
	if !passwordless {
		macSalt := make([]byte, enc.saltLen)
		if _, err := rand.Read(macSalt); err != nil {
			t.Fatal(err)
		}
		pfx.MacData.Mac.Algorithm.Algorithm = enc.macAlgorithm
		if enc.macAlgorithm.Equal(oidPBMAC1) {
			pfx.MacData.Mac.Algorithm.Parameters.FullBytes, err = makePBMAC1Parameters(macSalt, enc.macIterations)
		} else {
			pfx.MacData.MacSalt = macSalt
			pfx.MacData.Iterations = enc.macIterations
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := computeMac(&pfx.MacData, authenticatedSafeBytes, encodedPassword); err != nil {
			t.Fatal(err)
		}
	}

	pfx.AuthSafe.ContentType = oidDataContentType
	pfx.AuthSafe.Content = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true}
	if pfx.AuthSafe.Content.Bytes, err = asn1.Marshal(authenticatedSafeBytes); err != nil {
		t.Fatal(err)
	}
	pfxData, err := asn1.Marshal(pfx)
	if err != nil {
		t.Fatal(err)
	}
	return pfxData
}

func testGroupContainsKey(bags []rawSafeBag) bool {
	for _, bag := range bags {
		if bag.Id.Equal(oidKeyBag) || bag.Id.Equal(oidPKCS8ShroundedKeyBag) {
			return true
		}
	}
	return false
}

func testCanonicalGroups(t *testing.T, pfxData []byte, password string) [][]rawSafeBag {
	t.Helper()
	encodedPassword := testEncodedPassword(t, password)
	var pfx pfxPdu
	if err := unmarshal(pfxData, &pfx); err != nil {
		t.Fatal(err)
	}
	if err := unmarshal(pfx.AuthSafe.Content.Bytes, &pfx.AuthSafe.Content); err != nil {
		t.Fatal(err)
	}
	if len(pfx.MacData.Mac.Algorithm.Algorithm) != 0 {
		if err := verifyMac(&pfx.MacData, pfx.AuthSafe.Content.Bytes, encodedPassword); err != nil {
			t.Fatal(err)
		}
	}

	var authenticatedSafe []contentInfo
	if err := unmarshal(pfx.AuthSafe.Content.Bytes, &authenticatedSafe); err != nil {
		t.Fatal(err)
	}
	groups := make([][]rawSafeBag, len(authenticatedSafe))
	for i, contentInfo := range authenticatedSafe {
		data, _, err := decodeAuthenticatedSafeContentInfo(contentInfo, encodedPassword)
		if err != nil && password == "" {
			data, _, err = decodeAuthenticatedSafeContentInfo(contentInfo, nil)
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := unmarshal(data, &groups[i]); err != nil {
			t.Fatal(err)
		}
		for j := range groups[i] {
			groups[i][j] = testCanonicalBag(t, groups[i][j], encodedPassword)
		}
	}
	return groups
}

func testCanonicalBag(t *testing.T, bag rawSafeBag, password []byte) rawSafeBag {
	t.Helper()
	switch {
	case bag.Id.Equal(oidPKCS8ShroundedKeyBag):
		privateKeyData, err := decodePkcs8ShroudedKeyBagData(bag.Value.Bytes, password)
		if err != nil {
			t.Fatal(err)
		}
		bag.Id = oidKeyBag
		bag.Value = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: privateKeyData}
	case bag.Id.Equal(oidCertBag):
		certificate, err := decodeCertBag(bag.Value.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		normalizedCertBag, err := encodeCertBag(certificate)
		if err != nil {
			t.Fatal(err)
		}
		bag.Value = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: normalizedCertBag}
	case bag.Id.Equal(oidSafeContentsBag):
		var nestedBags []rawSafeBag
		if err := unmarshal(bag.Value.Bytes, &nestedBags); err != nil {
			t.Fatal(err)
		}
		for i := range nestedBags {
			nestedBags[i] = testCanonicalBag(t, nestedBags[i], password)
		}
		normalizedNestedBags, err := asn1.Marshal(nestedBags)
		if err != nil {
			t.Fatal(err)
		}
		bag.Value = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: normalizedNestedBags}
	}
	return bag
}
