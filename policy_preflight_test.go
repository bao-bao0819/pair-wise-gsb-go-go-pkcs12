// Copyright 2026 Opsmate, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
)

// testPbkdf2ParamsRaw is used to hand-craft PBKDF2 parameters whose
// iteration count is an arbitrary INTEGER (including negative or
// platform-overflowing values) without the encoder ever running the KDF.
type testPbkdf2ParamsRaw struct {
	Salt       asn1.RawValue
	Iterations *big.Int
	KeyLength  int                      `asn1:"optional"`
	Prf        pkix.AlgorithmIdentifier `asn1:"optional"`
}

func testPBES2Algorithm(t *testing.T, iterations *big.Int, prf asn1.ObjectIdentifier, keyLenOptional ...int) pkix.AlgorithmIdentifier {
	t.Helper()
	kdfParams := testPbkdf2ParamsRaw{
		Salt:       asn1.RawValue{Tag: asn1.TagOctetString, Bytes: make([]byte, 16)},
		Iterations: iterations,
	}
	if len(keyLenOptional) > 0 {
		kdfParams.KeyLength = keyLenOptional[0]
	}
	if prf != nil {
		kdfParams.Prf.Algorithm = prf
	}
	kdfBytes, err := asn1.Marshal(kdfParams)
	if err != nil {
		t.Fatalf("marshal kdf params: %v", err)
	}

	pbes2 := pbes2Params{
		Kdf: pkix.AlgorithmIdentifier{
			Algorithm:  oidPBKDF2,
			Parameters: asn1.RawValue{FullBytes: kdfBytes},
		},
		EncryptionScheme: pkix.AlgorithmIdentifier{
			Algorithm: oidAES256CBC,
		},
	}
	ivBytes, err := asn1.Marshal(make([]byte, 16))
	if err != nil {
		t.Fatalf("marshal iv: %v", err)
	}
	pbes2.EncryptionScheme.Parameters = asn1.RawValue{FullBytes: ivBytes}
	pbes2Bytes, err := asn1.Marshal(pbes2)
	if err != nil {
		t.Fatalf("marshal pbes2 params: %v", err)
	}
	return pkix.AlgorithmIdentifier{
		Algorithm:  oidPBES2,
		Parameters: asn1.RawValue{FullBytes: pbes2Bytes},
	}
}

// wrapExplicitData wraps inner DER as [0] EXPLICIT OCTET STRING, the shape
// of a data ContentInfo and of the outer AuthSafe.
func wrapExplicitData(t *testing.T, inner []byte) ([]byte, error) {
	t.Helper()
	octet, err := asn1.Marshal(inner)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(asn1.RawValue{
		Class:      2,
		Tag:        0,
		IsCompound: true,
		Bytes:      octet,
	})
}

// wrapExplicit wraps inner DER directly as [0] EXPLICIT, the shape of an
// encryptedData ContentInfo.
func wrapExplicit(t *testing.T, inner []byte) []byte {
	t.Helper()
	b, err := asn1.Marshal(asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: inner})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// testEncryptedSafePFX builds a PFX with no MAC and a single encrypted-data
// ContentInfo using the given algorithm.  Nothing is decrypted because the
// policy preflight must reject before any KDF is attempted.
func testEncryptedSafePFX(t *testing.T, algorithm pkix.AlgorithmIdentifier) []byte {
	t.Helper()
	ed := encryptedData{
		Version: 0,
		EncryptedContentInfo: encryptedContentInfo{
			ContentType:                oidDataContentType,
			ContentEncryptionAlgorithm: algorithm,
			EncryptedContent:           make([]byte, 32),
		},
	}
	edBytes, err := asn1.Marshal(ed)
	if err != nil {
		t.Fatalf("marshal encryptedData: %v", err)
	}
	safe := []contentInfo{{
		ContentType: oidEncryptedDataContentType,
		Content:     asn1.RawValue{FullBytes: wrapExplicit(t, edBytes)},
	}}
	safeBytes, err := asn1.Marshal(safe)
	if err != nil {
		t.Fatalf("marshal authenticatedSafe: %v", err)
	}
	authExplicit, err := wrapExplicitData(t, safeBytes)
	if err != nil {
		t.Fatalf("marshal authsafe wrapper: %v", err)
	}
	pfx := pfxPdu{
		Version: 3,
		AuthSafe: contentInfo{
			ContentType: oidDataContentType,
			Content:     asn1.RawValue{FullBytes: authExplicit},
		},
	}
	pfxBytes, err := asn1.Marshal(pfx)
	if err != nil {
		t.Fatalf("marshal pfx: %v", err)
	}
	return pfxBytes
}

func TestPreflightNegativeIterations(t *testing.T) {
	algorithm := testPBES2Algorithm(t, big.NewInt(-1), oidHmacWithSHA256)
	pfxData := testEncryptedSafePFX(t, algorithm)

	obs := &kdfObserver{}
	obs.install(t)
	_, _, _, err := DecodeChainWithPolicy(pfxData, "", DefaultPolicy())
	if !errors.Is(err, ErrNegativeValue) {
		t.Fatalf("expected ErrNegativeValue, got %v", err)
	}
	if obs.calls != 0 {
		t.Errorf("expected 0 KDF invocations, got %d", obs.calls)
	}
}

func TestPreflightOverflowIterations(t *testing.T) {
	// Larger than MaxInt64; the value is constructed but never iterated.
	huge, ok := new(big.Int).SetString("99999999999999999999999999999", 10)
	if !ok {
		t.Fatal("failed to build huge integer")
	}
	algorithm := testPBES2Algorithm(t, huge, oidHmacWithSHA256)
	pfxData := testEncryptedSafePFX(t, algorithm)

	obs := &kdfObserver{}
	obs.install(t)
	_, _, _, err := DecodeChainWithPolicy(pfxData, "", DefaultPolicy())
	if !errors.Is(err, ErrIntegerOverflow) {
		t.Fatalf("expected ErrIntegerOverflow, got %v", err)
	}
	if obs.calls != 0 {
		t.Errorf("expected 0 KDF invocations, got %d", obs.calls)
	}
}

func TestPreflightZeroIterations(t *testing.T) {
	algorithm := testPBES2Algorithm(t, big.NewInt(0), oidHmacWithSHA256)
	pfxData := testEncryptedSafePFX(t, algorithm)

	obs := &kdfObserver{}
	obs.install(t)
	_, _, _, err := DecodeChainWithPolicy(pfxData, "", DefaultPolicy())
	if !errors.Is(err, ErrMalformedParameters) {
		t.Fatalf("expected ErrMalformedParameters, got %v", err)
	}
	if obs.calls != 0 {
		t.Errorf("expected 0 KDF invocations, got %d", obs.calls)
	}
}

func TestPreflightUnknownPRF(t *testing.T) {
	unknownPRF := asn1.ObjectIdentifier([]int{1, 2, 3, 4, 5})
	algorithm := testPBES2Algorithm(t, big.NewInt(4), unknownPRF)
	pfxData := testEncryptedSafePFX(t, algorithm)

	obs := &kdfObserver{}
	obs.install(t)
	_, _, _, err := DecodeChainWithPolicy(pfxData, "", DefaultPolicy())
	if _, ok := err.(NotImplementedError); !ok {
		t.Fatalf("expected NotImplementedError, got %T: %v", err, err)
	}
	if obs.calls != 0 {
		t.Errorf("expected 0 KDF invocations, got %d", obs.calls)
	}
}

func TestPreflightUnknownEncryptionOID(t *testing.T) {
	algorithm := pkix.AlgorithmIdentifier{
		Algorithm:  asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 5, 999}),
		Parameters: asn1.RawValue{FullBytes: []byte{asn1.TagNull, 0}},
	}
	pfxData := testEncryptedSafePFX(t, algorithm)

	obs := &kdfObserver{}
	obs.install(t)
	_, _, _, err := DecodeChainWithPolicy(pfxData, "", DefaultPolicy())
	if _, ok := err.(NotImplementedError); !ok {
		t.Fatalf("expected NotImplementedError, got %T: %v", err, err)
	}
	if obs.calls != 0 {
		t.Errorf("expected 0 KDF invocations, got %d", obs.calls)
	}
}

func TestPreflightHugeCostRejectedWithoutDerivation(t *testing.T) {
	// 2^40 iterations: far too expensive to actually run.  The parameter is
	// merely encoded and must be rejected by the policy preflight.
	huge := new(big.Int).Lsh(big.NewInt(1), 40)
	algorithm := testPBES2Algorithm(t, huge, oidHmacWithSHA256)
	pfxData := testEncryptedSafePFX(t, algorithm)

	obs := &kdfObserver{}
	obs.install(t)
	start := obs.iterations
	_, _, _, err := DecodeChainWithPolicy(pfxData, "", DefaultPolicy())
	if !errors.Is(err, ErrPolicyRejected) {
		t.Fatalf("expected ErrPolicyRejected, got %v", err)
	}
	if obs.calls != 0 {
		t.Errorf("expected 0 KDF invocations, got %d", obs.calls)
	}
	if obs.iterations != start {
		t.Errorf("expected no KDF iterations, got %d", obs.iterations)
	}
}

func TestPreflightSaltLengthRejected(t *testing.T) {
	algorithm := testPBES2Algorithm(t, big.NewInt(4), oidHmacWithSHA256)
	pfxData := testEncryptedSafePFX(t, algorithm)

	p := DefaultPolicy()
	p.MinSaltLength = 32
	obs := &kdfObserver{}
	obs.install(t)
	_, _, _, err := DecodeChainWithPolicy(pfxData, "", p)
	if !errors.Is(err, ErrPolicyRejected) {
		t.Fatalf("expected ErrPolicyRejected, got %v", err)
	}
	if obs.calls != 0 {
		t.Errorf("expected 0 KDF invocations, got %d", obs.calls)
	}
}

func TestPreflightTooManyAuthenticatedSafe(t *testing.T) {
	dataCI := func() contentInfo {
		inner, err := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true})
		if err != nil {
			t.Fatal(err)
		}
		explicit, err := wrapExplicitData(t, inner)
		if err != nil {
			t.Fatal(err)
		}
		return contentInfo{
			ContentType: oidDataContentType,
			Content:     asn1.RawValue{FullBytes: explicit},
		}
	}
	safe := []contentInfo{
		dataCI(),
		dataCI(),
	}
	safeBytes, err := asn1.Marshal(safe)
	if err != nil {
		t.Fatal(err)
	}
	authExplicit, err := wrapExplicitData(t, safeBytes)
	if err != nil {
		t.Fatal(err)
	}
	pfxBytes, err := asn1.Marshal(pfxPdu{
		Version:  3,
		AuthSafe: contentInfo{ContentType: oidDataContentType, Content: asn1.RawValue{FullBytes: authExplicit}},
	})
	if err != nil {
		t.Fatal(err)
	}

	p := DefaultPolicy()
	p.MaxAuthenticatedSafe = 1
	_, _, _, err = DecodeChainWithPolicy(pfxBytes, "", p)
	if !errors.Is(err, ErrPolicyRejected) {
		t.Fatalf("expected ErrPolicyRejected, got %v", err)
	}
}

func TestDecodePositiveInt64(t *testing.T) {
	marshalInt := func(v int64) asn1.RawValue {
		b, err := asn1.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var raw asn1.RawValue
		if _, err := asn1.Unmarshal(b, &raw); err != nil {
			t.Fatal(err)
		}
		return raw
	}

	if v, err := decodePositiveInt64(marshalInt(0)); err != nil || v != 0 {
		t.Errorf("zero: got %d, %v", v, err)
	}
	if v, err := decodePositiveInt64(marshalInt(2048)); err != nil || v != 2048 {
		t.Errorf("2048: got %d, %v", v, err)
	}
	if _, err := decodePositiveInt64(marshalInt(-5)); !errors.Is(err, ErrNegativeValue) {
		t.Errorf("negative: got %v", err)
	}

	// Manually encode a positive value larger than MaxInt64.
	overflow, ok := new(big.Int).SetString("9223372036854775808", 10) // 2^63
	if !ok {
		t.Fatal("big int")
	}
	b, err := asn1.Marshal(overflow)
	if err != nil {
		t.Fatal(err)
	}
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	if _, err := decodePositiveInt64(raw); !errors.Is(err, ErrIntegerOverflow) {
		t.Errorf("overflow: got %v", err)
	}
}
