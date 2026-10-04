// Copyright 2026 Opsmate, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"testing"
)

// makeShroudedKeyBag builds a safeBag holding a PKCS#8 shrouded key bag
// encrypted with the given password.
func makeShroudedKeyBag(t *testing.T, privateKey interface{}, password string) safeBag {
	t.Helper()

	encodedPassword, err := bmpStringZeroTerminated(password)
	if err != nil {
		t.Fatal(err)
	}
	asn1Data, err := encodePkcs8ShroudedKeyBag(rand.Reader, privateKey, oidPBEWithSHAAnd3KeyTripleDESCBC, encodedPassword, 2048, 8)
	if err != nil {
		t.Fatal(err)
	}

	bag := safeBag{Id: oidPKCS8ShroundedKeyBag}
	bag.Value.Class = 2
	bag.Value.Tag = 0
	bag.Value.IsCompound = true
	bag.Value.Bytes = asn1Data
	return bag
}

// makeMultiPasswordPFX builds a PFX with an outer MAC protected by
// macPassword and a single plaintext SafeContents containing the given
// bags.
func makeMultiPasswordPFX(t *testing.T, macPassword string, bags ...safeBag) []byte {
	t.Helper()

	ci, err := makeSafeContents(rand.Reader, bags, nil, nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	authenticatedSafe := []contentInfo{ci}
	authenticatedSafeBytes, err := asn1.Marshal(authenticatedSafe)
	if err != nil {
		t.Fatal(err)
	}

	encodedMacPassword, err := bmpStringZeroTerminated(macPassword)
	if err != nil {
		t.Fatal(err)
	}

	var pfx pfxPdu
	pfx.Version = 3
	pfx.MacData.Mac.Algorithm.Algorithm = oidSHA256
	pfx.MacData.MacSalt = make([]byte, 8)
	if _, err := rand.Read(pfx.MacData.MacSalt); err != nil {
		t.Fatal(err)
	}
	pfx.MacData.Iterations = 1
	if err := computeMac(&pfx.MacData, authenticatedSafeBytes, encodedMacPassword); err != nil {
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

// twoKeyPFX builds a PFX with two independently encrypted shrouded key
// bags and an outer MAC, each layer using a different password.
func twoKeyPFX(t *testing.T) (pfxData []byte, key1, key2 *rsa.PrivateKey) {
	t.Helper()

	key1, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatal(err)
	}
	key2, err = rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatal(err)
	}

	bag1 := makeShroudedKeyBag(t, key1, "key-password-1")
	bag2 := makeShroudedKeyBag(t, key2, "key-password-2")
	pfxData = makeMultiPasswordPFX(t, "mac-password", bag1, bag2)
	return pfxData, key1, key2
}

// layerKey uniquely identifies an encryption layer for counting requests.
type layerKey struct {
	purpose           PasswordPurpose
	safeContentsIndex int
	bagIndex          int
}

func countRequestsByLayer(requests []PasswordRequest) map[layerKey]int {
	counts := make(map[layerKey]int)
	for _, req := range requests {
		counts[layerKey{req.Purpose, req.SafeContentsIndex, req.BagIndex}]++
	}
	return counts
}

func TestDecodeWithPasswordFunc(t *testing.T) {
	pfxData, key1, key2 := twoKeyPFX(t)

	var requests []PasswordRequest
	passwordFunc := func(req PasswordRequest) (string, bool) {
		requests = append(requests, req)
		switch {
		case req.Purpose == PurposeMAC:
			return "mac-password", true
		case req.Purpose == PurposeKeyBag && req.BagIndex == 0:
			return "key-password-1", true
		case req.Purpose == PurposeKeyBag && req.BagIndex == 1:
			return "key-password-2", true
		}
		return "", false
	}

	bags, err := DecodeWithPasswordFunc(pfxData, passwordFunc)
	if err != nil {
		t.Fatal(err)
	}

	// The integrity check must be requested first, followed by the two key
	// bags in order, each layer exactly once.
	if len(requests) != 3 {
		t.Fatalf("expected 3 password requests, got %d", len(requests))
	}
	if requests[0].Purpose != PurposeMAC || requests[0].SafeContentsIndex != -1 || requests[0].BagIndex != -1 {
		t.Errorf("unexpected first request: %+v", requests[0])
	}
	if !requests[0].Algorithm.Algorithm.Equal(oidSHA256) {
		t.Errorf("unexpected MAC algorithm: %v", requests[0].Algorithm.Algorithm)
	}
	for i, bagIndex := range []int{0, 1} {
		req := requests[1+i]
		if req.Purpose != PurposeKeyBag || req.SafeContentsIndex != 0 || req.BagIndex != bagIndex {
			t.Errorf("unexpected request %d: %+v", 1+i, req)
		}
		if !req.Algorithm.Algorithm.Equal(oidPBEWithSHAAnd3KeyTripleDESCBC) {
			t.Errorf("unexpected key bag algorithm: %v", req.Algorithm.Algorithm)
		}
		if len(req.Algorithm.Parameters.FullBytes) == 0 {
			t.Errorf("request %d carries no public algorithm parameters", 1+i)
		}
	}
	for layer, count := range countRequestsByLayer(requests) {
		if count != 1 {
			t.Errorf("layer %+v was requested %d times, want exactly 1", layer, count)
		}
	}

	if len(bags) != 2 {
		t.Fatalf("expected 2 bags, got %d", len(bags))
	}
	for i, key := range []*rsa.PrivateKey{key1, key2} {
		if bags[i].Opaque {
			t.Errorf("bag %d is unexpectedly opaque: %v", i, bags[i].Reason)
			continue
		}
		if bags[i].Reason != OpaqueNone {
			t.Errorf("bag %d has reason %v, want %v", i, bags[i].Reason, OpaqueNone)
		}
		if !bags[i].Id.Equal(oidPKCS8ShroundedKeyBag) {
			t.Errorf("bag %d has unexpected type %v", i, bags[i].Id)
		}
		if !key.Equal(bags[i].PrivateKey) {
			t.Errorf("bag %d contains the wrong private key", i)
		}
	}
}

func TestDecodeWithPasswordFuncDeclinedKeyBag(t *testing.T) {
	pfxData, key1, _ := twoKeyPFX(t)

	var requests []PasswordRequest
	passwordFunc := func(req PasswordRequest) (string, bool) {
		requests = append(requests, req)
		switch {
		case req.Purpose == PurposeMAC:
			return "mac-password", true
		case req.Purpose == PurposeKeyBag && req.BagIndex == 0:
			return "key-password-1", true
		}
		// Decline to provide a password for the second key bag.
		return "", false
	}

	bags, err := DecodeWithPasswordFunc(pfxData, passwordFunc)
	if err != nil {
		t.Fatal(err)
	}

	if len(bags) != 2 {
		t.Fatalf("expected 2 bags, got %d", len(bags))
	}

	// The first bag must still be delivered, fully decrypted.
	if bags[0].Opaque {
		t.Fatalf("bag 0 is unexpectedly opaque: %v", bags[0].Reason)
	}
	if !key1.Equal(bags[0].PrivateKey) {
		t.Error("bag 0 contains the wrong private key")
	}

	// The second bag must be kept as an explicit opaque entry and must not
	// masquerade as decrypted.
	if !bags[1].Opaque {
		t.Fatal("bag 1 is not marked opaque despite its password being declined")
	}
	if bags[1].Reason != OpaquePasswordUnavailable {
		t.Errorf("bag 1 has reason %v, want %v", bags[1].Reason, OpaquePasswordUnavailable)
	}
	if bags[1].PrivateKey != nil {
		t.Error("opaque bag 1 unexpectedly carries a private key")
	}

	// Each layer must have been asked exactly once; a declined or failed
	// layer must not trigger requests for other candidate passwords.
	for layer, count := range countRequestsByLayer(requests) {
		if count != 1 {
			t.Errorf("layer %+v was requested %d times, want exactly 1", layer, count)
		}
	}
}

func TestDecodeWithPasswordFuncIntegrityFailure(t *testing.T) {
	pfxData, _, _ := twoKeyPFX(t)

	var requests []PasswordRequest
	passwordFunc := func(req PasswordRequest) (string, bool) {
		requests = append(requests, req)
		return "wrong-mac-password", true
	}

	_, err := DecodeWithPasswordFunc(pfxData, passwordFunc)
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("expected ErrIntegrity, got %v", err)
	}

	// When the integrity check fails, no password may be requested for any
	// inner encryption layer.
	for _, req := range requests {
		if req.Purpose != PurposeMAC {
			t.Errorf("password requested for inner layer %+v after integrity failure", req)
		}
	}
}

func TestDecodeWithPasswordFuncNoMacPassword(t *testing.T) {
	pfxData, _, _ := twoKeyPFX(t)

	var requests []PasswordRequest
	passwordFunc := func(req PasswordRequest) (string, bool) {
		requests = append(requests, req)
		return "", false
	}

	_, err := DecodeWithPasswordFunc(pfxData, passwordFunc)
	if !errors.Is(err, ErrNoPassword) {
		t.Fatalf("expected ErrNoPassword, got %v", err)
	}
	for _, req := range requests {
		if req.Purpose != PurposeMAC {
			t.Errorf("password requested for inner layer %+v without integrity password", req)
		}
	}
}

func TestDecodeWithPasswordFuncWrongKeyPassword(t *testing.T) {
	pfxData, _, key2 := twoKeyPFX(t)

	passwordFunc := func(req PasswordRequest) (string, bool) {
		switch {
		case req.Purpose == PurposeMAC:
			return "mac-password", true
		case req.Purpose == PurposeKeyBag && req.BagIndex == 0:
			return "wrong-key-password", true
		case req.Purpose == PurposeKeyBag && req.BagIndex == 1:
			return "key-password-2", true
		}
		return "", false
	}

	bags, err := DecodeWithPasswordFunc(pfxData, passwordFunc)
	if err != nil {
		t.Fatal(err)
	}

	if len(bags) != 2 {
		t.Fatalf("expected 2 bags, got %d", len(bags))
	}
	if !bags[0].Opaque || bags[0].Reason != OpaqueDecryptionFailed {
		t.Errorf("bag 0: opaque=%v reason=%v, want opaque with %v", bags[0].Opaque, bags[0].Reason, OpaqueDecryptionFailed)
	}
	if bags[1].Opaque {
		t.Fatalf("bag 1 is unexpectedly opaque: %v", bags[1].Reason)
	}
	if !key2.Equal(bags[1].PrivateKey) {
		t.Error("bag 1 contains the wrong private key")
	}
}

func TestDecodeWithPasswordFuncUnsupportedAlgorithm(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatal(err)
	}

	// A shrouded key bag using an algorithm OID this package does not
	// support.
	var pkinfo encryptedPrivateKeyInfo
	pkinfo.AlgorithmIdentifier.Algorithm = asn1.ObjectIdentifier([]int{1, 2, 3, 4})
	pkinfo.EncryptedData = make([]byte, 16)
	asn1Data, err := asn1.Marshal(pkinfo)
	if err != nil {
		t.Fatal(err)
	}
	unsupportedBag := safeBag{Id: oidPKCS8ShroundedKeyBag}
	unsupportedBag.Value.Class = 2
	unsupportedBag.Value.Tag = 0
	unsupportedBag.Value.IsCompound = true
	unsupportedBag.Value.Bytes = asn1Data

	goodBag := makeShroudedKeyBag(t, key, "key-password")
	pfxData := makeMultiPasswordPFX(t, "mac-password", unsupportedBag, goodBag)

	passwordFunc := func(req PasswordRequest) (string, bool) {
		if req.Purpose == PurposeMAC {
			return "mac-password", true
		}
		return "key-password", true
	}

	bags, err := DecodeWithPasswordFunc(pfxData, passwordFunc)
	if err != nil {
		t.Fatal(err)
	}

	if len(bags) != 2 {
		t.Fatalf("expected 2 bags, got %d", len(bags))
	}
	if !bags[0].Opaque || bags[0].Reason != OpaqueUnsupportedAlgorithm {
		t.Errorf("bag 0: opaque=%v reason=%v, want opaque with %v", bags[0].Opaque, bags[0].Reason, OpaqueUnsupportedAlgorithm)
	}
	if bags[1].Opaque {
		t.Fatalf("bag 1 is unexpectedly opaque: %v", bags[1].Reason)
	}
	if !key.Equal(bags[1].PrivateKey) {
		t.Error("bag 1 contains the wrong private key")
	}
}
