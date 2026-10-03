// Copyright 2026 Opsmate, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"
)

// setAttribute builds a pkcs12Attribute whose SET value wraps the given
// (already DER-encoded) inner value.
func setAttribute(t *testing.T, oid asn1.ObjectIdentifier, innerDER []byte) pkcs12Attribute {
	t.Helper()
	return pkcs12Attribute{
		Id: oid,
		Value: asn1.RawValue{
			Class:      0,
			Tag:        17,
			IsCompound: true,
			Bytes:      innerDER,
		},
	}
}

func bmpAttribute(t *testing.T, oid asn1.ObjectIdentifier, value string) pkcs12Attribute {
	t.Helper()
	bmp, err := bmpString(value)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := asn1.Marshal(asn1.RawValue{
		Class:      0,
		Tag:        30, // BMPString
		IsCompound: false,
		Bytes:      bmp,
	})
	if err != nil {
		t.Fatal(err)
	}
	return setAttribute(t, oid, encoded)
}

func octetAttribute(t *testing.T, oid asn1.ObjectIdentifier, value []byte) pkcs12Attribute {
	t.Helper()
	encoded, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return setAttribute(t, oid, encoded)
}

func integerAttribute(t *testing.T, oid asn1.ObjectIdentifier, value int) pkcs12Attribute {
	t.Helper()
	encoded, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return setAttribute(t, oid, encoded)
}

var oidUnknownAttribute = asn1.ObjectIdentifier([]int{1, 2, 3, 4, 5, 6, 7})
var oidUnknownBagType = asn1.ObjectIdentifier([]int{1, 2, 3, 4, 5, 6, 8})

func selfSigned(t *testing.T, name string, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	if isCA {
		template.IsCA = true
		template.BasicConstraintsValid = true
		template.KeyUsage = x509.KeyUsageCertSign
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	if parent == nil {
		parent = template
		parentKey = key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

// buildCustomPFX builds a PFX with two authenticated safe contents:
// an encrypted cert safe (three cert bags carrying a variety of attributes)
// and a plain safe holding a shrouded key bag. It uses Modern2023 algorithms.
func buildCustomPFX(t *testing.T, password string) (pfxData []byte, key *ecdsa.PrivateKey, leafDER, intermediateDER, rootDER []byte) {
	t.Helper()
	encodedPassword, err := bmpStringZeroTerminated(password)
	if err != nil {
		t.Fatal(err)
	}

	rootKey, root := selfSigned(t, "Test Root", true, nil, nil)
	intKey, intermediate := selfSigned(t, "Test Intermediate", true, root, rootKey)
	key, leaf := selfSigned(t, "leaf.example", false, intermediate, intKey)

	leafDER, intermediateDER, rootDER = leaf.Raw, intermediate.Raw, root.Raw

	leafAttrs := []pkcs12Attribute{
		bmpAttribute(t, oidFriendlyName, "leaf-friendly"),
		bmpAttribute(t, oidFriendlyName, "duplicate-friendly"),
		octetAttribute(t, oidLocalKeyID, []byte{0x01, 0x02, 0x03, 0x04}),
		integerAttribute(t, oidUnknownAttribute, 12345),
	}
	intAttrs := []pkcs12Attribute{
		bmpAttribute(t, oidFriendlyName, "intermediate-friendly"),
		octetAttribute(t, oidLocalKeyID, []byte{0xaa, 0xbb}),
	}
	rootAttrs := []pkcs12Attribute{
		bmpAttribute(t, oidMicrosoftCSPName, "custom-csp"),
		integerAttribute(t, oidUnknownAttribute, 67890),
	}

	leafBag, err := makeCertBag(leafDER, leafAttrs)
	if err != nil {
		t.Fatal(err)
	}
	intBag, err := makeCertBag(intermediateDER, intAttrs)
	if err != nil {
		t.Fatal(err)
	}
	rootBag, err := makeCertBag(rootDER, rootAttrs)
	if err != nil {
		t.Fatal(err)
	}

	shroudedKey, err := encodePkcs8ShroudedKeyBag(rand.Reader, key, Modern2023.keyAlgorithm, encodedPassword, Modern2023.encryptionIterations, Modern2023.saltLen)
	if err != nil {
		t.Fatal(err)
	}
	keyBag := makeShroudedKeyBag(shroudedKey, []pkcs12Attribute{
		bmpAttribute(t, oidFriendlyName, "leaf-friendly"),
		octetAttribute(t, oidLocalKeyID, []byte{0x01, 0x02, 0x03, 0x04}),
		integerAttribute(t, oidUnknownAttribute, 12345),
	})

	certSafe, err := makeSafeContents(rand.Reader, []safeBag{*leafBag, *intBag, *rootBag}, Modern2023.certAlgorithm, encodedPassword, Modern2023.encryptionIterations, Modern2023.saltLen)
	if err != nil {
		t.Fatal(err)
	}
	keySafe, err := makeSafeContents(rand.Reader, []safeBag{keyBag}, nil, nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	authenticatedSafe := []contentInfo{certSafe, keySafe}
	authenticatedSafeBytes, err := asn1.Marshal(authenticatedSafe)
	if err != nil {
		t.Fatal(err)
	}

	var pfx pfxPdu
	pfx.Version = 3
	macSalt := make([]byte, Modern2023.saltLen)
	if _, err := io.ReadFull(rand.Reader, macSalt); err != nil {
		t.Fatal(err)
	}
	pfx.MacData.Mac.Algorithm.Algorithm = Modern2023.macAlgorithm
	pfx.MacData.MacSalt = macSalt
	pfx.MacData.Iterations = Modern2023.macIterations
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
	pfxData, err = asn1.Marshal(pfx)
	if err != nil {
		t.Fatal(err)
	}
	return
}

// normalizedBag holds the decrypted essence of a bag: its type, the plaintext
// inner DER (cert bag DER or plaintext PKCS#8), and verbatim attributes.
type normalizedBag struct {
	id         asn1.ObjectIdentifier
	value      []byte
	attributes []pkcs12Attribute
}

func normalizeBags(t *testing.T, pfxData []byte, password string) []normalizedBag {
	t.Helper()
	encodedPassword, err := bmpStringZeroTerminated(password)
	if err != nil {
		t.Fatal(err)
	}
	bags, updatedPassword, err := getSafeContents(pfxData, encodedPassword, 1, 2)
	if err != nil {
		t.Fatal(err)
	}

	normalized := make([]normalizedBag, 0, len(bags))
	for _, bag := range bags {
		nb := normalizedBag{id: bag.Id, attributes: bag.Attributes}
		switch {
		case bag.Id.Equal(oidCertBag):
			nb.value = bag.Value.Bytes
		case bag.Id.Equal(oidKeyBag):
			nb.value = bag.Value.Bytes
		case bag.Id.Equal(oidPKCS8ShroundedKeyBag):
			nb.id = oidKeyBag
			if nb.value, err = decryptPkcs8ShroudedKeyBag(bag.Value.Bytes, updatedPassword); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatalf("unexpected bag type %s", bag.Id)
		}
		normalized = append(normalized, nb)
	}
	return normalized
}

func assertBagsEqual(t *testing.T, got, want []normalizedBag) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("bag count changed: got %d, want %d", len(got), len(want))
	}
	for i := range got {
		if !got[i].id.Equal(want[i].id) {
			t.Errorf("bag %d: id changed: got %s, want %s", i, got[i].id, want[i].id)
		}
		if !bytes.Equal(got[i].value, want[i].value) {
			t.Errorf("bag %d (%s): plaintext content changed", i, got[i].id)
		}
		if len(got[i].attributes) != len(want[i].attributes) {
			t.Errorf("bag %d (%s): attribute count changed: got %d, want %d", i, got[i].id, len(got[i].attributes), len(want[i].attributes))
			continue
		}
		for j := range got[i].attributes {
			if !got[i].attributes[j].Id.Equal(want[i].attributes[j].Id) {
				t.Errorf("bag %d attribute %d: OID changed: got %s, want %s", i, j, got[i].attributes[j].Id, want[i].attributes[j].Id)
			}
			if !bytes.Equal(got[i].attributes[j].Value.FullBytes, want[i].attributes[j].Value.FullBytes) {
				t.Errorf("bag %d attribute %d (%s): raw attribute DER changed", i, j, got[i].attributes[j].Id)
			}
		}
	}
}

func contentInfoTypes(t *testing.T, pfxData []byte) []asn1.ObjectIdentifier {
	t.Helper()
	pfx := new(pfxPdu)
	if err := unmarshal(pfxData, pfx); err != nil {
		t.Fatal(err)
	}
	if err := unmarshal(pfx.AuthSafe.Content.Bytes, &pfx.AuthSafe.Content); err != nil {
		t.Fatal(err)
	}
	var authenticatedSafe []contentInfo
	if err := unmarshal(pfx.AuthSafe.Content.Bytes, &authenticatedSafe); err != nil {
		t.Fatal(err)
	}
	types := make([]asn1.ObjectIdentifier, len(authenticatedSafe))
	for i, ci := range authenticatedSafe {
		types[i] = ci.ContentType
	}
	return types
}

func TestRepackChangesPasswordAndPreservesStructure(t *testing.T) {
	const oldPassword = "old-password"
	const newPassword = "new-password"

	original, key, leafDER, intermediateDER, rootDER := buildCustomPFX(t, oldPassword)
	originalBags := normalizeBags(t, original, oldPassword)
	originalContentTypes := contentInfoTypes(t, original)

	encoders := map[string]*Encoder{
		"Modern2026": Modern2026,
		"Modern2023": Modern2023,
		"LegacyDES":  LegacyDES,
		"LegacyRC2":  LegacyRC2,
	}
	for name, enc := range encoders {
		t.Run(name, func(t *testing.T) {
			repacked, err := enc.Repack(original, oldPassword, newPassword)
			if err != nil {
				t.Fatalf("Repack failed: %v", err)
			}

			if bytes.Equal(repacked, original) {
				t.Error("repacked DER is byte-identical to original; expected fresh salts/IVs")
			}

			// The old password must no longer work.
			if _, _, _, err := DecodeChain(repacked, oldPassword); !errors.Is(err, ErrIncorrectPassword) {
				t.Errorf("DecodeChain with old password: expected ErrIncorrectPassword, got %v", err)
			}

			// The new password must work and the certificate relationships must hold.
			decodedKey, leaf, caCerts, err := DecodeChain(repacked, newPassword)
			if err != nil {
				t.Fatalf("DecodeChain with new password failed: %v", err)
			}
			if !decodedKey.(*ecdsa.PrivateKey).PublicKey.Equal(&key.PublicKey) {
				t.Error("private key changed after repack")
			}
			if !bytes.Equal(leaf.Raw, leafDER) {
				t.Error("leaf certificate changed after repack")
			}
			if len(caCerts) != 2 {
				t.Fatalf("expected 2 CA certs, got %d", len(caCerts))
			}
			if !bytes.Equal(caCerts[0].Raw, intermediateDER) || !bytes.Equal(caCerts[1].Raw, rootDER) {
				t.Error("CA certificate chain changed after repack")
			}
			if err := leaf.CheckSignatureFrom(caCerts[0]); err != nil {
				t.Errorf("leaf/CA signature relationship broken: %v", err)
			}

			// Structure and secret content must be unchanged.
			assertBagsEqual(t, normalizeBags(t, repacked, newPassword), originalBags)
			if got := contentInfoTypes(t, repacked); len(got) != len(originalContentTypes) {
				t.Errorf("authenticated safe content count changed: got %d, want %d", len(got), len(originalContentTypes))
			} else {
				for i := range got {
					if !got[i].Equal(originalContentTypes[i]) {
						t.Errorf("content info %d type changed: got %s, want %s", i, got[i], originalContentTypes[i])
					}
				}
			}
		})
	}
}

func TestRepackWrongOldPassword(t *testing.T) {
	original, _, _, _, _ := buildCustomPFX(t, "old-password")
	if _, err := Modern2023.Repack(original, "wrong-password", "new-password"); !errors.Is(err, ErrIncorrectPassword) {
		t.Errorf("expected ErrIncorrectPassword, got %v", err)
	}
}

func TestRepackEmptyAndPasswordlessPasswords(t *testing.T) {
	original, _, _, _, _ := buildCustomPFX(t, "old-password")
	originalBags := normalizeBags(t, original, "old-password")

	// A literal empty password is valid for non-passwordless encoders and is
	// distinct from a password-less file.
	emptyPasswordPFX, err := LegacyDES.Repack(original, "old-password", "")
	if err != nil {
		t.Fatalf("Repack to empty password failed: %v", err)
	}
	if len(contentInfoTypes(t, emptyPasswordPFX)) != 2 {
		t.Fatal("expected two authenticated safe contents")
	}
	pfx := new(pfxPdu)
	if err := unmarshal(emptyPasswordPFX, pfx); err != nil {
		t.Fatal(err)
	}
	if len(pfx.MacData.Mac.Algorithm.Algorithm) == 0 {
		t.Error("literal empty-password file must still contain a MAC")
	}
	if _, _, _, err := DecodeChain(emptyPasswordPFX, ""); err != nil {
		t.Errorf("DecodeChain with empty password failed: %v", err)
	}
	if _, _, _, err := DecodeChain(emptyPasswordPFX, "not-empty"); !errors.Is(err, ErrIncorrectPassword) {
		t.Errorf("expected ErrIncorrectPassword for wrong password, got %v", err)
	}
	assertBagsEqual(t, normalizeBags(t, emptyPasswordPFX, ""), originalBags)

	// Passwordless encoding requires an empty new password and drops the MAC.
	if _, err := Passwordless.Repack(original, "old-password", "non-empty"); err == nil {
		t.Error("expected error when using a non-empty password with Passwordless")
	}
	passwordlessPFX, err := Passwordless.Repack(original, "old-password", "")
	if err != nil {
		t.Fatalf("Repack to passwordless failed: %v", err)
	}
	pfx = new(pfxPdu)
	if err := unmarshal(passwordlessPFX, pfx); err != nil {
		t.Fatal(err)
	}
	if len(pfx.MacData.Mac.Algorithm.Algorithm) != 0 {
		t.Error("passwordless file must not contain a MAC")
	}
	if _, _, _, err := DecodeChain(passwordlessPFX, ""); err != nil {
		t.Errorf("DecodeChain passwordless with empty password failed: %v", err)
	}
	assertBagsEqual(t, normalizeBags(t, passwordlessPFX, ""), originalBags)

	// A passwordless source can be re-protected with a real password.
	reprotected, err := Modern2023.Repack(passwordlessPFX, "", "restored")
	if err != nil {
		t.Fatalf("Repack from passwordless failed: %v", err)
	}
	if _, err := Modern2023.Repack(passwordlessPFX, "wrong", "restored"); err == nil {
		t.Error("expected error when supplying a non-empty old password for a passwordless file")
	}
	if _, _, _, err := DecodeChain(reprotected, "restored"); err != nil {
		t.Errorf("DecodeChain reprotected file failed: %v", err)
	}
	assertBagsEqual(t, normalizeBags(t, reprotected, "restored"), originalBags)
}

func TestRepackRejectsUnknownBag(t *testing.T) {
	unknownBag := safeBag{
		Id: oidUnknownBagType,
		Value: asn1.RawValue{
			Class:      2,
			Tag:        0,
			IsCompound: true,
			Bytes:      []byte{0x01, 0x01, 0x2a},
		},
	}
	safe, err := makeSafeContents(rand.Reader, []safeBag{unknownBag}, nil, nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	authenticatedSafeBytes, err := asn1.Marshal([]contentInfo{safe})
	if err != nil {
		t.Fatal(err)
	}

	encodedPassword, err := bmpStringZeroTerminated("")
	if err != nil {
		t.Fatal(err)
	}

	var pfx pfxPdu
	pfx.Version = 3
	macSalt := make([]byte, Modern2023.saltLen)
	if _, err := io.ReadFull(rand.Reader, macSalt); err != nil {
		t.Fatal(err)
	}
	pfx.MacData.Mac.Algorithm.Algorithm = Modern2023.macAlgorithm
	pfx.MacData.MacSalt = macSalt
	pfx.MacData.Iterations = Modern2023.macIterations
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

	if _, err := Modern2023.Repack(pfxData, "", "new"); err == nil {
		t.Fatal("expected Repack to reject an unknown bag, got nil error")
	} else if _, ok := err.(NotImplementedError); !ok {
		t.Errorf("expected NotImplementedError for unknown bag, got %T: %v", err, err)
	}
}

type failingReader struct{}

func (failingReader) Read(p []byte) (int, error) {
	return 0, errors.New("boom: entropy source unavailable")
}

type shortReader struct {
	reads int
}

func (s *shortReader) Read(p []byte) (int, error) {
	s.reads++
	if s.reads == 1 {
		return 3, nil
	}
	return 0, io.EOF
}

func TestRepackRandomSourceFailures(t *testing.T) {
	original, _, _, _, _ := buildCustomPFX(t, "old-password")

	if _, err := Modern2023.WithRand(failingReader{}).Repack(original, "old-password", "new-password"); err == nil {
		t.Error("expected Repack to fail when the random source errors")
	}
	if _, err := Modern2023.WithRand(&shortReader{}).Repack(original, "old-password", "new-password"); err == nil {
		t.Error("expected Repack to fail on a short read from the random source")
	}
}

func TestRepackAcrossEncoders(t *testing.T) {
	key, leaf := selfSigned(t, "leaf", false, nil, nil)
	rootKey, root := selfSigned(t, "Root CA", true, nil, nil)

	original, err := LegacyDES.Encode(key, leaf, []*x509.Certificate{root}, "first")
	if err != nil {
		t.Fatal(err)
	}
	originalBags := normalizeBags(t, original, "first")

	chain := []struct {
		name     string
		enc      *Encoder
		old, new string
	}{
		{"legacy-to-modern2023", Modern2023, "first", "second"},
		{"modern2023-to-modern2026", Modern2026, "second", "third"},
		{"modern2026-to-passwordless", Passwordless, "third", ""},
		{"passwordless-to-legacy", LegacyRC2, "", "fourth"},
	}

	current := original
	for _, step := range chain {
		t.Run(step.name, func(t *testing.T) {
			var err error
			current, err = step.enc.Repack(current, step.old, step.new)
			if err != nil {
				t.Fatalf("Repack failed: %v", err)
			}

			// The previous password must stop working when it changes.
			if step.old != step.new {
				if _, _, _, err := DecodeChain(current, step.old); err == nil {
					t.Errorf("DecodeChain unexpectedly succeeded with old password %q", step.old)
				}
			}

			decodedKey, decodedLeaf, decodedCAs, err := DecodeChain(current, step.new)
			if err != nil {
				t.Fatalf("DecodeChain with new password failed: %v", err)
			}
			if !decodedKey.(*ecdsa.PrivateKey).PublicKey.Equal(&key.PublicKey) {
				t.Error("private key changed")
			}
			if !bytes.Equal(decodedLeaf.Raw, leaf.Raw) || len(decodedCAs) != 1 || !bytes.Equal(decodedCAs[0].Raw, root.Raw) {
				t.Error("certificate content changed")
			}

			assertBagsEqual(t, normalizeBags(t, current, step.new), originalBags)

			// Silence unused variable linters for rootKey which exists only
			// to keep the generated CA self-consistent.
			_ = rootKey
		})
	}
}
