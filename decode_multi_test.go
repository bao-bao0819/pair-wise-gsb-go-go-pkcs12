// Copyright 2026 Opsmate, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"
)

func TestDecodeWithPasswordFunc(t *testing.T) {
	pfxData, key, cert := buildMultiPasswordPFX(t, "mac-password", "sc0-password", "sc1-password", "key-password")

	var requests []recordedPasswordRequest
	passwordFn := recordingPasswordFunc(&requests, func(req PasswordRequest) (string, bool) {
		switch req.Purpose {
		case PasswordPurposeMAC:
			return "mac-password", true
		case PasswordPurposeSafeContents:
			if req.SafeContentsIndex == 0 {
				return "sc0-password", true
			}
			return "sc1-password", true
		case PasswordPurposeKeyBag:
			return "key-password", true
		}
		return "", false
	})

	decoded, err := DecodeWithPasswordFunc(pfxData, passwordFn)
	if err != nil {
		t.Fatal(err)
	}

	// The MAC password must be requested first, then each SafeContents in
	// file order, then the shrouded key bag.  Each layer must be requested
	// exactly once.
	expectedRequests := []recordedPasswordRequest{
		{PasswordPurposeMAC, -1, -1, oidSHA1},
		{PasswordPurposeSafeContents, 0, -1, oidPBEWithSHAAnd3KeyTripleDESCBC},
		{PasswordPurposeSafeContents, 1, -1, oidPBEWithSHAAnd3KeyTripleDESCBC},
		{PasswordPurposeKeyBag, 1, 0, oidPBEWithSHAAnd3KeyTripleDESCBC},
	}
	if len(requests) != len(expectedRequests) {
		t.Fatalf("got %d password requests, want %d: %+v", len(requests), len(expectedRequests), requests)
	}
	for i, want := range expectedRequests {
		if requests[i].Purpose != want.Purpose ||
			requests[i].SafeContentsIndex != want.SafeContentsIndex ||
			requests[i].BagIndex != want.BagIndex ||
			!requests[i].Algorithm.Equal(want.Algorithm) {
			t.Errorf("request %d = %+v, want %+v", i, requests[i], want)
		}
	}

	if !decoded.FullyDecrypted() {
		t.Errorf("expected fully decrypted PFX, got %+v", decoded)
	}
	if len(decoded.SafeContents) != 2 {
		t.Fatalf("got %d SafeContents, want 2", len(decoded.SafeContents))
	}

	sc0 := decoded.SafeContents[0]
	if sc0.Opaque || sc0.Err != nil {
		t.Errorf("SafeContents 0 unexpectedly opaque: %v", sc0.Err)
	}
	if len(sc0.Bags) != 1 || len(sc0.Bags[0].Certificates) != 1 {
		t.Fatalf("SafeContents 0 should contain one cert bag, got %+v", sc0.Bags)
	}
	if !sc0.Bags[0].Certificates[0].Equal(cert) {
		t.Errorf("SafeContents 0 contains the wrong certificate")
	}

	sc1 := decoded.SafeContents[1]
	if sc1.Opaque || sc1.Err != nil {
		t.Errorf("SafeContents 1 unexpectedly opaque: %v", sc1.Err)
	}
	if len(sc1.Bags) != 1 || sc1.Bags[0].PrivateKey == nil {
		t.Fatalf("SafeContents 1 should contain one private key bag, got %+v", sc1.Bags)
	}
	decodedKey, ok := sc1.Bags[0].PrivateKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("private key has type %T, want *rsa.PrivateKey", sc1.Bags[0].PrivateKey)
	}
	if !decodedKey.Equal(key) {
		t.Errorf("SafeContents 1 contains the wrong private key")
	}
}

func TestDecodeWithPasswordFuncDeclined(t *testing.T) {
	pfxData, _, cert := buildMultiPasswordPFX(t, "mac-password", "sc0-password", "sc1-password", "key-password")

	var requests []recordedPasswordRequest
	passwordFn := recordingPasswordFunc(&requests, func(req PasswordRequest) (string, bool) {
		switch req.Purpose {
		case PasswordPurposeMAC:
			return "mac-password", true
		case PasswordPurposeSafeContents:
			if req.SafeContentsIndex == 1 {
				return "", false // decline to provide a password
			}
			return "sc0-password", true
		}
		return "", false
	})

	decoded, err := DecodeWithPasswordFunc(pfxData, passwordFn)
	if err != nil {
		t.Fatal(err)
	}

	// The declined SafeContents must remain opaque, and the key bag
	// password inside it must never be requested.
	for _, req := range requests {
		if req.Purpose == PasswordPurposeKeyBag {
			t.Errorf("key bag password was requested even though its SafeContents was locked")
		}
	}

	if decoded.FullyDecrypted() {
		t.Errorf("PFX with a declined password must not report itself fully decrypted")
	}
	if len(decoded.SafeContents) != 2 {
		t.Fatalf("got %d SafeContents, want 2", len(decoded.SafeContents))
	}

	sc0 := decoded.SafeContents[0]
	if sc0.Opaque || sc0.Err != nil {
		t.Errorf("SafeContents 0 should still be decoded, got opaque: %v", sc0.Err)
	}
	if len(sc0.Bags) != 1 || len(sc0.Bags[0].Certificates) != 1 || !sc0.Bags[0].Certificates[0].Equal(cert) {
		t.Errorf("SafeContents 0 should still deliver its certificate")
	}

	sc1 := decoded.SafeContents[1]
	if !sc1.Opaque {
		t.Errorf("SafeContents 1 should be opaque after its password was declined")
	}
	if !errors.Is(sc1.Err, ErrPasswordMissing) {
		t.Errorf("SafeContents 1 error = %v, want ErrPasswordMissing", sc1.Err)
	}
	if len(sc1.Bags) != 0 {
		t.Errorf("opaque SafeContents 1 should not deliver any bags")
	}
}

func TestDecodeWithPasswordFuncMACFailure(t *testing.T) {
	pfxData, _, _ := buildMultiPasswordPFX(t, "mac-password", "sc0-password", "sc1-password", "key-password")

	var requests []recordedPasswordRequest
	passwordFn := recordingPasswordFunc(&requests, func(req PasswordRequest) (string, bool) {
		return "wrong-password", true
	})

	_, err := DecodeWithPasswordFunc(pfxData, passwordFn)
	if !errors.Is(err, ErrIncorrectPassword) {
		t.Fatalf("error = %v, want ErrIncorrectPassword", err)
	}

	// When the integrity check fails, no decryption password may be
	// requested.
	if len(requests) != 1 || requests[0].Purpose != PasswordPurposeMAC {
		t.Errorf("after MAC failure, requests = %+v, want a single MAC request", requests)
	}
}

func TestDecodeWithPasswordFuncWrongLayerPassword(t *testing.T) {
	pfxData, _, cert := buildMultiPasswordPFX(t, "mac-password", "sc0-password", "sc1-password", "key-password")

	var requests []recordedPasswordRequest
	passwordFn := recordingPasswordFunc(&requests, func(req PasswordRequest) (string, bool) {
		switch req.Purpose {
		case PasswordPurposeMAC:
			return "mac-password", true
		case PasswordPurposeSafeContents:
			if req.SafeContentsIndex == 1 {
				return "wrong-password", true
			}
			return "sc0-password", true
		case PasswordPurposeKeyBag:
			return "key-password", true
		}
		return "", false
	})

	decoded, err := DecodeWithPasswordFunc(pfxData, passwordFn)
	if err != nil {
		t.Fatal(err)
	}

	// The failing layer must be requested exactly once; a decryption
	// failure must not trigger retries with other candidate passwords.
	count := 0
	for _, req := range requests {
		if req.Purpose == PasswordPurposeSafeContents && req.SafeContentsIndex == 1 {
			count++
		}
	}
	if count != 1 {
		t.Errorf("SafeContents 1 password was requested %d times, want exactly 1", count)
	}

	if decoded.FullyDecrypted() {
		t.Errorf("PFX with a failed layer must not report itself fully decrypted")
	}

	sc0 := decoded.SafeContents[0]
	if sc0.Opaque || len(sc0.Bags) != 1 || len(sc0.Bags[0].Certificates) != 1 || !sc0.Bags[0].Certificates[0].Equal(cert) {
		t.Errorf("SafeContents 0 should still deliver its certificate")
	}

	sc1 := decoded.SafeContents[1]
	if !sc1.Opaque {
		t.Errorf("SafeContents 1 should be opaque after decryption failure")
	}
	if !errors.Is(sc1.Err, ErrDecryption) {
		t.Errorf("SafeContents 1 error = %v, want ErrDecryption", sc1.Err)
	}
}

func TestDecodeWithPasswordFuncSinglePassword(t *testing.T) {
	key, cert := makeTestCertificate(t, "single password test")

	pfxData, err := Modern.Encode(key, cert, nil, "the-password")
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := DecodeWithPasswordFunc(pfxData, SinglePassword("the-password"))
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.FullyDecrypted() {
		t.Fatalf("expected fully decrypted PFX, got %+v", decoded)
	}

	var foundCert *x509.Certificate
	var foundKey interface{}
	for _, sc := range decoded.SafeContents {
		for _, bag := range sc.Bags {
			if len(bag.Certificates) > 0 {
				foundCert = bag.Certificates[0]
			}
			if bag.PrivateKey != nil {
				foundKey = bag.PrivateKey
			}
		}
	}
	if foundCert == nil || !foundCert.Equal(cert) {
		t.Errorf("certificate not found in decoded PFX")
	}
	decodedKey, ok := foundKey.(*rsa.PrivateKey)
	if !ok || !decodedKey.Equal(key) {
		t.Errorf("private key not found in decoded PFX")
	}
}
