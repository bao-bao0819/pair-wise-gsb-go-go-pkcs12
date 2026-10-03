// Copyright 2026 Opsmate, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

const testPassword = "t3st-p@ssw0rd"

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// testCA generates a short-lived, self-signed CA certificate for use in
// tests.
func testCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key := testKey(t)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pkcs12 test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// issueCert issues a short-lived certificate signed by ca.
func issueCert(t *testing.T, commonName string, serial int64, publicKey crypto.PublicKey, ca *x509.Certificate, caKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, publicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func localKeyIDAttr(t *testing.T, ids ...[]byte) pkcs12Attribute {
	t.Helper()
	var value []byte
	for _, id := range ids {
		encoded, err := asn1.Marshal(id)
		if err != nil {
			t.Fatal(err)
		}
		value = append(value, encoded...)
	}
	return pkcs12Attribute{
		Id:    oidLocalKeyID,
		Value: asn1.RawValue{Class: 0, Tag: 17, IsCompound: true, Bytes: value},
	}
}

func friendlyNameAttr(t *testing.T, name string) pkcs12Attribute {
	t.Helper()
	bmpName, err := bmpString(name)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := asn1.Marshal(asn1.RawValue{Class: 0, Tag: 30, Bytes: bmpName})
	if err != nil {
		t.Fatal(err)
	}
	return pkcs12Attribute{
		Id:    oidFriendlyName,
		Value: asn1.RawValue{Class: 0, Tag: 17, IsCompound: true, Bytes: encoded},
	}
}

func testKeyBag(t *testing.T, key crypto.Signer, attrs ...pkcs12Attribute) safeBag {
	t.Helper()
	encodedPassword, err := bmpStringZeroTerminated(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	asn1Data, err := encodePkcs8ShroudedKeyBag(rand.Reader, key, oidPBES2, encodedPassword, 2048, 16)
	if err != nil {
		t.Fatal(err)
	}
	bag := safeBag{
		Id:         oidPKCS8ShroundedKeyBag,
		Attributes: attrs,
	}
	bag.Value.Class = 2
	bag.Value.Tag = 0
	bag.Value.IsCompound = true
	bag.Value.Bytes = asn1Data
	return bag
}

func testCertBag(t *testing.T, cert *x509.Certificate, attrs ...pkcs12Attribute) safeBag {
	t.Helper()
	bag, err := makeCertBag(cert.Raw, attrs)
	if err != nil {
		t.Fatal(err)
	}
	return *bag
}

// encodeTestPFX assembles an arbitrary set of safe bags into a single
// SafeContents inside a MACed PFX, so that tests can construct
// multi-identity files that Encoder.Encode cannot produce.
func encodeTestPFX(t *testing.T, bags []safeBag) []byte {
	t.Helper()
	encodedPassword, err := bmpStringZeroTerminated(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	ci, err := makeSafeContents(rand.Reader, bags, nil, nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	authenticatedSafeBytes, err := asn1.Marshal([]contentInfo{ci})
	if err != nil {
		t.Fatal(err)
	}

	var pfx pfxPdu
	pfx.Version = 3
	macSalt := make([]byte, 8)
	if _, err := rand.Read(macSalt); err != nil {
		t.Fatal(err)
	}
	pfx.MacData.Mac.Algorithm.Algorithm = oidSHA256
	pfx.MacData.MacSalt = macSalt
	pfx.MacData.Iterations = 2048
	if err := computeMac(&pfx.MacData, authenticatedSafeBytes, encodedPassword); err != nil {
		t.Fatal(err)
	}

	pfx.AuthSafe.ContentType = oidDataContentType
	pfx.AuthSafe.Content.Class = 2
	pfx.AuthSafe.Content.Tag = 0
	pfx.AuthSafe.Content.IsCompound = true
	if pfx.AuthSafe.Content.Bytes, err = asn1.Marshal(authenticatedSafeBytes); err != nil {
		t.Fatal(err)
	}

	pfxData, err := asn1.Marshal(pfx)
	if err != nil {
		t.Fatal(err)
	}
	return pfxData
}

func publicKeyDER(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// findIdentity returns the identity whose private key corresponds to key.
func findIdentity(t *testing.T, identities []*Identity, key crypto.Signer) *Identity {
	t.Helper()
	want := publicKeyDER(t, key)
	for _, id := range identities {
		signer, ok := id.PrivateKey.(crypto.Signer)
		if !ok {
			t.Fatalf("private key of type %T is not a crypto.Signer", id.PrivateKey)
		}
		got, err := x509.MarshalPKIXPublicKey(signer.Public())
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(got, want) {
			return id
		}
	}
	t.Fatalf("no identity found for public key %x", sha256.Sum256(want))
	return nil
}

func certRaws(certs []*x509.Certificate) [][]byte {
	raws := make([][]byte, len(certs))
	for i, c := range certs {
		raws[i] = c.Raw
	}
	return raws
}

// canonicalForm renders the decode result in a canonical, deterministic
// form so that results from differently-ordered files can be compared.
func canonicalForm(identities []*Identity, unassociated []*x509.Certificate) string {
	var b strings.Builder
	for _, id := range identities {
		signer := id.PrivateKey.(crypto.Signer)
		pub, _ := x509.MarshalPKIXPublicKey(signer.Public())
		fmt.Fprintf(&b, "identity %x\n", sha256.Sum256(pub))
		for _, c := range id.LeafCertificates {
			fmt.Fprintf(&b, "  leaf %x\n", sha256.Sum256(c.Raw))
		}
		for _, c := range id.Certificates {
			fmt.Fprintf(&b, "  cert %x\n", sha256.Sum256(c.Raw))
		}
		for _, a := range id.Attributes {
			fmt.Fprintf(&b, "  attr %s=%s\n", a.Name, a.Value)
		}
	}
	for _, c := range unassociated {
		fmt.Fprintf(&b, "unassociated %x\n", sha256.Sum256(c.Raw))
	}
	return b.String()
}

func TestDecodeIdentitiesMultiple(t *testing.T) {
	ca, caKey := testCA(t)
	key1, key2 := testKey(t), testKey(t)
	cert1 := issueCert(t, "identity one", 2, key1.Public(), ca, caKey)
	cert2 := issueCert(t, "identity two", 3, key2.Public(), ca, caKey)

	// Both identities share the same friendlyName; it must not be used
	// to tell them apart.
	pfxData := encodeTestPFX(t, []safeBag{
		testKeyBag(t, key1, localKeyIDAttr(t, []byte{1}), friendlyNameAttr(t, "same-name")),
		testKeyBag(t, key2, localKeyIDAttr(t, []byte{2}), friendlyNameAttr(t, "same-name")),
		testCertBag(t, cert1, localKeyIDAttr(t, []byte{1}), friendlyNameAttr(t, "same-name")),
		testCertBag(t, cert2, localKeyIDAttr(t, []byte{2})),
		testCertBag(t, ca),
	})

	identities, unassociated, err := DecodeIdentities(pfxData, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if len(identities) != 2 {
		t.Fatalf("expected 2 identities, got %d", len(identities))
	}

	id1 := findIdentity(t, identities, key1)
	if got := certRaws(id1.LeafCertificates); len(got) != 1 || !bytes.Equal(got[0], cert1.Raw) {
		t.Errorf("identity 1: unexpected leaf certificates %x", got)
	}
	if len(id1.Certificates) != 0 {
		t.Errorf("identity 1: unexpected associated certificates %x", certRaws(id1.Certificates))
	}
	if name := id1.FriendlyName(); name != "same-name" {
		t.Errorf("identity 1: expected friendlyName %q, got %q", "same-name", name)
	}

	id2 := findIdentity(t, identities, key2)
	if got := certRaws(id2.LeafCertificates); len(got) != 1 || !bytes.Equal(got[0], cert2.Raw) {
		t.Errorf("identity 2: unexpected leaf certificates %x", got)
	}
	if name := id2.FriendlyName(); name != "same-name" {
		t.Errorf("identity 2: expected friendlyName %q, got %q", "same-name", name)
	}

	if got := certRaws(unassociated); len(got) != 1 || !bytes.Equal(got[0], ca.Raw) {
		t.Errorf("unexpected unassociated certificates %x", got)
	}
}

func TestDecodeIdentitiesBagOrderInvariance(t *testing.T) {
	ca, caKey := testCA(t)
	key1, key2 := testKey(t), testKey(t)
	cert1 := issueCert(t, "identity one", 2, key1.Public(), ca, caKey)
	cert2 := issueCert(t, "identity two", 3, key2.Public(), ca, caKey)
	orphan := issueCert(t, "orphan", 4, testKey(t).Public(), ca, caKey)

	bags := []safeBag{
		testKeyBag(t, key1, localKeyIDAttr(t, []byte{1}), friendlyNameAttr(t, "one")),
		testCertBag(t, cert1, localKeyIDAttr(t, []byte{1})),
		testCertBag(t, ca),
		testKeyBag(t, key2, localKeyIDAttr(t, []byte{2}), friendlyNameAttr(t, "two")),
		testCertBag(t, cert2, localKeyIDAttr(t, []byte{2})),
		testCertBag(t, orphan),
	}

	reversed := make([]safeBag, len(bags))
	for i, bag := range bags {
		reversed[len(bags)-1-i] = bag
	}
	rotated := append(append([]safeBag{}, bags[3:]...), bags[:3]...)

	want := canonicalForm(mustDecodeIdentities(t, encodeTestPFX(t, bags)))
	for name, shuffled := range map[string][]safeBag{"reversed": reversed, "rotated": rotated} {
		got := canonicalForm(mustDecodeIdentities(t, encodeTestPFX(t, shuffled)))
		if got != want {
			t.Errorf("%s bag order produced a different result:\n got:\n%s\nwant:\n%s", name, got, want)
		}
	}
}

func mustDecodeIdentities(t *testing.T, pfxData []byte) ([]*Identity, []*x509.Certificate) {
	t.Helper()
	identities, unassociated, err := DecodeIdentities(pfxData, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	return identities, unassociated
}

func TestDecodeIdentitiesDuplicateLocalKeyID(t *testing.T) {
	ca, caKey := testCA(t)
	key := testKey(t)
	otherKey := testKey(t)

	leaf := issueCert(t, "current cert", 2, key.Public(), ca, caKey)
	// A renewed certificate for the same key, sharing the localKeyId.
	renewed := issueCert(t, "renewed cert", 3, key.Public(), ca, caKey)
	// A certificate for a different key that (incorrectly) shares the
	// same localKeyId.
	stale := issueCert(t, "stale cert", 4, otherKey.Public(), ca, caKey)

	pfxData := encodeTestPFX(t, []safeBag{
		testKeyBag(t, key, localKeyIDAttr(t, []byte{7})),
		testCertBag(t, leaf, localKeyIDAttr(t, []byte{7})),
		testCertBag(t, renewed, localKeyIDAttr(t, []byte{7})),
		testCertBag(t, stale, localKeyIDAttr(t, []byte{7})),
	})

	identities, unassociated, err := DecodeIdentities(pfxData, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if len(identities) != 1 {
		t.Fatalf("expected 1 identity, got %d", len(identities))
	}
	id := identities[0]

	// Both certificates for the key are kept as leaves, sorted by DER.
	wantLeaves := [][]byte{leaf.Raw, renewed.Raw}
	if bytes.Compare(renewed.Raw, leaf.Raw) < 0 {
		wantLeaves[0], wantLeaves[1] = wantLeaves[1], wantLeaves[0]
	}
	if got := certRaws(id.LeafCertificates); len(got) != 2 || !bytes.Equal(got[0], wantLeaves[0]) || !bytes.Equal(got[1], wantLeaves[1]) {
		t.Errorf("unexpected leaf certificates %x, want %x", got, wantLeaves)
	}

	// The certificate with a mismatched public key is associated via
	// localKeyId but is not a leaf.
	if got := certRaws(id.Certificates); len(got) != 1 || !bytes.Equal(got[0], stale.Raw) {
		t.Errorf("unexpected associated certificates %x", got)
	}
	if len(unassociated) != 0 {
		t.Errorf("unexpected unassociated certificates %x", certRaws(unassociated))
	}
}

func TestDecodeIdentitiesOrphanCertificates(t *testing.T) {
	ca, caKey := testCA(t)
	key := testKey(t)
	leaf := issueCert(t, "leaf", 2, key.Public(), ca, caKey)
	// Orphan with a localKeyId that matches no key.
	orphanWithID := issueCert(t, "orphan with id", 3, testKey(t).Public(), ca, caKey)
	// Orphan without any attributes.
	orphanNoID := issueCert(t, "orphan without id", 4, testKey(t).Public(), ca, caKey)

	pfxData := encodeTestPFX(t, []safeBag{
		testKeyBag(t, key, localKeyIDAttr(t, []byte{1})),
		testCertBag(t, leaf, localKeyIDAttr(t, []byte{1})),
		testCertBag(t, orphanWithID, localKeyIDAttr(t, []byte{9})),
		testCertBag(t, orphanNoID),
	})

	identities, unassociated, err := DecodeIdentities(pfxData, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if len(identities) != 1 {
		t.Fatalf("expected 1 identity, got %d", len(identities))
	}
	if got := certRaws(identities[0].LeafCertificates); len(got) != 1 || !bytes.Equal(got[0], leaf.Raw) {
		t.Errorf("unexpected leaf certificates %x", got)
	}
	if len(unassociated) != 2 {
		t.Fatalf("expected 2 unassociated certificates, got %d", len(unassociated))
	}
	// Unassociated certificates are sorted by DER.
	if bytes.Compare(unassociated[0].Raw, unassociated[1].Raw) > 0 {
		t.Errorf("unassociated certificates are not sorted")
	}
	got := map[string]bool{}
	for _, c := range unassociated {
		got[c.Subject.CommonName] = true
	}
	for _, want := range []string{"orphan with id", "orphan without id"} {
		if !got[want] {
			t.Errorf("expected %q among unassociated certificates", want)
		}
	}
}

func TestDecodeIdentitiesPublicKeyMatchWithoutID(t *testing.T) {
	ca, caKey := testCA(t)
	key := testKey(t)
	// Neither the key bag nor the cert bag carries a localKeyId; the
	// unique public key match is enough to associate them.
	leaf := issueCert(t, "leaf", 2, key.Public(), ca, caKey)

	pfxData := encodeTestPFX(t, []safeBag{
		testKeyBag(t, key),
		testCertBag(t, leaf),
	})

	identities, unassociated, err := DecodeIdentities(pfxData, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if len(identities) != 1 {
		t.Fatalf("expected 1 identity, got %d", len(identities))
	}
	if got := certRaws(identities[0].LeafCertificates); len(got) != 1 || !bytes.Equal(got[0], leaf.Raw) {
		t.Errorf("unexpected leaf certificates %x", got)
	}
	if len(unassociated) != 0 {
		t.Errorf("unexpected unassociated certificates %x", certRaws(unassociated))
	}
}

func TestDecodeIdentitiesAmbiguous(t *testing.T) {
	ca, caKey := testCA(t)
	key := testKey(t)
	leaf := issueCert(t, "leaf", 2, key.Public(), ca, caKey)

	// The same key is stored in two key bags, so the certificate's
	// public key matches two candidates and no unique association is
	// possible.
	pfxData := encodeTestPFX(t, []safeBag{
		testKeyBag(t, key),
		testKeyBag(t, key),
		testCertBag(t, leaf),
	})

	_, _, err := DecodeIdentities(pfxData, testPassword)
	var ambErr *AmbiguousAssociationError
	if !errors.As(err, &ambErr) {
		t.Fatalf("expected AmbiguousAssociationError, got %v", err)
	}
	if !bytes.Equal(ambErr.Certificate.Raw, leaf.Raw) {
		t.Errorf("unexpected certificate in AmbiguousAssociationError")
	}
	if len(ambErr.CandidateKeyFingerprints) != 2 {
		t.Errorf("expected 2 candidate key fingerprints, got %d", len(ambErr.CandidateKeyFingerprints))
	}
	if strings.Contains(err.Error(), testPassword) {
		t.Errorf("error message contains the password: %q", err.Error())
	}
}

func TestDecodeIdentitiesAmbiguousLocalKeyID(t *testing.T) {
	ca, caKey := testCA(t)
	key1, key2 := testKey(t), testKey(t)
	// Two keys share a localKeyId, and a certificate for a third,
	// absent key carries the same localKeyId.
	stale := issueCert(t, "stale", 2, testKey(t).Public(), ca, caKey)

	pfxData := encodeTestPFX(t, []safeBag{
		testKeyBag(t, key1, localKeyIDAttr(t, []byte{5})),
		testKeyBag(t, key2, localKeyIDAttr(t, []byte{5})),
		testCertBag(t, stale, localKeyIDAttr(t, []byte{5})),
	})

	_, _, err := DecodeIdentities(pfxData, testPassword)
	var ambErr *AmbiguousAssociationError
	if !errors.As(err, &ambErr) {
		t.Fatalf("expected AmbiguousAssociationError, got %v", err)
	}
	if len(ambErr.CandidateKeyFingerprints) != 2 {
		t.Errorf("expected 2 candidate key fingerprints, got %d", len(ambErr.CandidateKeyFingerprints))
	}
}

func TestDecodeIdentitiesDuplicateCertificates(t *testing.T) {
	ca, caKey := testCA(t)
	key := testKey(t)
	leaf := issueCert(t, "leaf", 2, key.Public(), ca, caKey)

	// The same certificate appears in two cert bags; both occurrences
	// are preserved so the relationship stays explainable.
	pfxData := encodeTestPFX(t, []safeBag{
		testKeyBag(t, key, localKeyIDAttr(t, []byte{1})),
		testCertBag(t, leaf, localKeyIDAttr(t, []byte{1})),
		testCertBag(t, leaf, localKeyIDAttr(t, []byte{1})),
	})

	identities, _, err := DecodeIdentities(pfxData, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if len(identities) != 1 {
		t.Fatalf("expected 1 identity, got %d", len(identities))
	}
	leaves := identities[0].LeafCertificates
	if len(leaves) != 2 || !bytes.Equal(leaves[0].Raw, leaf.Raw) || !bytes.Equal(leaves[1].Raw, leaf.Raw) {
		t.Errorf("expected the duplicated certificate to be preserved twice, got %x", certRaws(leaves))
	}
}

func TestDecodeChainRejectsMultiIdentity(t *testing.T) {
	ca, caKey := testCA(t)
	key1, key2 := testKey(t), testKey(t)
	cert1 := issueCert(t, "one", 2, key1.Public(), ca, caKey)
	cert2 := issueCert(t, "two", 3, key2.Public(), ca, caKey)

	pfxData := encodeTestPFX(t, []safeBag{
		testKeyBag(t, key1, localKeyIDAttr(t, []byte{1})),
		testKeyBag(t, key2, localKeyIDAttr(t, []byte{2})),
		testCertBag(t, cert1, localKeyIDAttr(t, []byte{1})),
		testCertBag(t, cert2, localKeyIDAttr(t, []byte{2})),
	})

	// The legacy single-identity interface keeps its contract and
	// rejects files with more than one private key.
	if _, _, _, err := DecodeChain(pfxData, testPassword); err == nil {
		t.Fatal("expected DecodeChain to reject a multi-identity file")
	} else if !strings.Contains(err.Error(), "expected exactly one key bag") {
		t.Errorf("unexpected DecodeChain error: %v", err)
	}
}

func TestDecodeIdentitiesIncorrectPassword(t *testing.T) {
	ca, caKey := testCA(t)
	key := testKey(t)
	leaf := issueCert(t, "leaf", 2, key.Public(), ca, caKey)

	pfxData := encodeTestPFX(t, []safeBag{
		testKeyBag(t, key, localKeyIDAttr(t, []byte{1})),
		testCertBag(t, leaf, localKeyIDAttr(t, []byte{1})),
	})

	wrongPassword := "wr0ng-p@ssw0rd"
	_, _, err := DecodeIdentities(pfxData, wrongPassword)
	if !errors.Is(err, ErrIncorrectPassword) {
		t.Fatalf("expected ErrIncorrectPassword, got %v", err)
	}
	if strings.Contains(err.Error(), wrongPassword) || strings.Contains(err.Error(), testPassword) {
		t.Errorf("error message contains a password: %q", err.Error())
	}
}
