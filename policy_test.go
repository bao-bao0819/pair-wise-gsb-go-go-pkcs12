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
	"errors"
	"hash"
	"math/big"
	"strings"
	"testing"
)

// modern2023Policy accepts exactly the algorithms used by the Modern2023
// encoder with tight, but sufficient, KDF and salt limits.
var modern2023Policy = &Policy{
	MacAlgorithms:        []asn1.ObjectIdentifier{oidSHA256},
	EncryptionAlgorithms: []asn1.ObjectIdentifier{oidPBES2, oidAES128CBC, oidAES192CBC, oidAES256CBC},
	MaxKDFIterations:     10,
	MaxTotalKDFWork:      100,
	MinSaltLength:        16,
	MaxSaltLength:        16,
	MaxSafeContents:      4,
	MaxSafeBags:          8,
}

var modern2026Policy = &Policy{
	MacAlgorithms:        []asn1.ObjectIdentifier{oidPBMAC1},
	EncryptionAlgorithms: []asn1.ObjectIdentifier{oidPBES2, oidAES128CBC, oidAES192CBC, oidAES256CBC},
	MaxKDFIterations:     10,
	MaxTotalKDFWork:      100,
	MinSaltLength:        16,
	MaxSaltLength:        16,
}

var legacyDESPolicy = &Policy{
	MacAlgorithms:        []asn1.ObjectIdentifier{oidSHA1},
	EncryptionAlgorithms: []asn1.ObjectIdentifier{oidPBEWithSHAAnd3KeyTripleDESCBC},
	MaxKDFIterations:     10,
	MaxTotalKDFWork:      100,
	MinSaltLength:        8,
	MaxSaltLength:        16,
}

func testKeyAndCert(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "policy-test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return key, cert
}

func mustEncode(t *testing.T, enc *Encoder, key *rsa.PrivateKey, cert *x509.Certificate) []byte {
	t.Helper()
	pfxData, err := enc.Encode(key, cert, nil, "passw0rd")
	if err != nil {
		t.Fatalf("failed to encode PFX: %v", err)
	}
	return pfxData
}

// kdfCounters observes KDF invocations without running their iteration loops,
// so large iteration counts can be supplied without doing expensive work.
type kdfCounters struct {
	legacyCalls int
	legacyIters []int
	pbkdf2Calls int
	pbkdf2Iters []int

	origLegacy func(func([]byte) []byte, int, int, []byte, []byte, int, byte, int) []byte
	origPBKDF2 func([]byte, []byte, int, int, func() hash.Hash) []byte
}

func installKDFCounters() *kdfCounters {
	c := &kdfCounters{}
	c.origLegacy = kdfLegacyHook
	c.origPBKDF2 = kdfPBKDF2Hook
	kdfLegacyHook = func(hashFn func([]byte) []byte, u, v int, salt, password []byte, iterations int, id byte, size int) []byte {
		c.legacyCalls++
		c.legacyIters = append(c.legacyIters, iterations)
		return c.origLegacy(hashFn, u, v, salt, password, iterations, id, size)
	}
	kdfPBKDF2Hook = func(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
		c.pbkdf2Calls++
		c.pbkdf2Iters = append(c.pbkdf2Iters, iter)
		return c.origPBKDF2(password, salt, iter, keyLen, h)
	}
	return c
}

func (c *kdfCounters) restore() {
	kdfLegacyHook = c.origLegacy
	kdfPBKDF2Hook = c.origPBKDF2
}

func (c *kdfCounters) totalCalls() int { return c.legacyCalls + c.pbkdf2Calls }

func assertErrorIs(t *testing.T, err error, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("expected error wrapping %v, got %T: %v", target, err, err)
	}
}

// --- PFX mutation helpers -------------------------------------------------

type mutablePfx struct {
	Version  int
	AuthSafe contentInfo
	MacData  macData `asn1:"optional"`
}

// reparsePFX decodes a PFX into mutable internal structures.
func reparsePFX(t *testing.T, pfxData []byte) *mutablePfx {
	t.Helper()
	pfx := new(mutablePfx)
	if _, err := asn1.Unmarshal(pfxData, pfx); err != nil {
		t.Fatalf("failed to unmarshal PFX for mutation: %v", err)
	}
	return pfx
}

func marshalPFX(t *testing.T, pfx *mutablePfx) []byte {
	t.Helper()
	out, err := asn1.Marshal(*pfx)
	if err != nil {
		t.Fatalf("failed to re-marshal PFX: %v", err)
	}
	return out
}

// authenticatedSafeContents returns the parsed authenticated safe.
func authenticatedSafeContents(t *testing.T, pfx *mutablePfx) []contentInfo {
	t.Helper()
	var authSafe []byte
	if err := unmarshal(pfx.AuthSafe.Content.Bytes, &authSafe); err != nil {
		t.Fatalf("failed to parse outer authSafe content: %v", err)
	}
	var contents []contentInfo
	if err := unmarshal(authSafe, &contents); err != nil {
		t.Fatalf("failed to parse authenticated safe: %v", err)
	}
	return contents
}

func setAuthenticatedSafe(t *testing.T, pfx *mutablePfx, contents []contentInfo) {
	t.Helper()
	raw, err := asn1.Marshal(contents)
	if err != nil {
		t.Fatalf("failed to marshal authenticated safe: %v", err)
	}
	wrapped, err := asn1.Marshal(raw)
	if err != nil {
		t.Fatalf("failed to wrap authenticated safe: %v", err)
	}
	pfx.AuthSafe.Content.Bytes = wrapped
	pfx.AuthSafe.Content.FullBytes = nil
}

// encryptedCI mutators -----------------------------------------------------

type mutableEncryptedData struct {
	Version              int
	EncryptedContentInfo encryptedContentInfo
}

func parseEncryptedCI(t *testing.T, ci contentInfo) mutableEncryptedData {
	t.Helper()
	var ed mutableEncryptedData
	// ci.Content is the raw [0] EXPLICIT wrapper; its Bytes contains the
	// tagged OCTET STRING whose Bytes is the encryptedData SEQUENCE.
	var inner asn1.RawValue
	if err := unmarshal(ci.Content.Bytes, &inner); err != nil {
		t.Fatalf("failed to unwrap explicit encryptedData content: %v", err)
	}
	if rest, err := asn1.Unmarshal(inner.FullBytes, &ed); err != nil {
		t.Fatalf("failed to parse encryptedData: %v", err)
	} else if len(rest) != 0 {
		t.Fatalf("trailing data after encryptedData (%d bytes)", len(rest))
	}
	return ed
}

func marshalEncryptedCI(t *testing.T, ci contentInfo, ed mutableEncryptedData) contentInfo {
	t.Helper()
	b, err := asn1.Marshal(ed)
	if err != nil {
		t.Fatalf("failed to marshal encryptedData: %v", err)
	}

	// Mirror the encoder: the explicit [0] content carries the encryptedData
	// SEQUENCE directly.
	ci.Content = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: b}
	ci.Content.FullBytes = nil
	return ci
}

func setPBES2Iterations(t *testing.T, alg pkix.AlgorithmIdentifier, iterations int) pkix.AlgorithmIdentifier {
	t.Helper()
	var params pbes2Params
	if err := unmarshal(alg.Parameters.FullBytes, &params); err != nil {
		t.Fatalf("failed to parse PBES2 params: %v", err)
	}
	var kdfParams pbkdf2Params
	if err := unmarshal(params.Kdf.Parameters.FullBytes, &kdfParams); err != nil {
		t.Fatalf("failed to parse PBKDF2 params: %v", err)
	}
	kdfParams.Iterations = iterations
	kb, err := asn1.Marshal(kdfParams)
	if err != nil {
		t.Fatalf("failed to marshal PBKDF2 params: %v", err)
	}
	params.Kdf.Parameters.FullBytes = kb
	pb, err := asn1.Marshal(params)
	if err != nil {
		t.Fatalf("failed to marshal PBES2 params: %v", err)
	}
	alg.Parameters.FullBytes = pb
	return alg
}

func setPBES2Prf(t *testing.T, alg pkix.AlgorithmIdentifier, prf asn1.ObjectIdentifier) pkix.AlgorithmIdentifier {
	t.Helper()
	var params pbes2Params
	if err := unmarshal(alg.Parameters.FullBytes, &params); err != nil {
		t.Fatalf("failed to parse PBES2 params: %v", err)
	}
	var kdfParams pbkdf2Params
	if err := unmarshal(params.Kdf.Parameters.FullBytes, &kdfParams); err != nil {
		t.Fatalf("failed to parse PBKDF2 params: %v", err)
	}
	kdfParams.Prf.Algorithm = prf
	kb, err := asn1.Marshal(kdfParams)
	if err != nil {
		t.Fatalf("failed to marshal PBKDF2 params: %v", err)
	}
	params.Kdf.Parameters.FullBytes = kb
	pb, err := asn1.Marshal(params)
	if err != nil {
		t.Fatalf("failed to marshal PBES2 params: %v", err)
	}
	alg.Parameters.FullBytes = pb
	return alg
}

func setPBEIterations(t *testing.T, alg pkix.AlgorithmIdentifier, iterations int) pkix.AlgorithmIdentifier {
	t.Helper()
	var params pbeParams
	if err := unmarshal(alg.Parameters.FullBytes, &params); err != nil {
		t.Fatalf("failed to parse PBE params: %v", err)
	}
	params.Iterations = iterations
	b, err := asn1.Marshal(params)
	if err != nil {
		t.Fatalf("failed to marshal PBE params: %v", err)
	}
	alg.Parameters.FullBytes = b
	return alg
}

// mutateShroudedKeys walks the plaintext (unencrypted) safe contents and
// applies f to every shrouded key bag's algorithm.
func mutateShroudedKeys(t *testing.T, contents []contentInfo, f func(pkix.AlgorithmIdentifier) pkix.AlgorithmIdentifier) []contentInfo {
	t.Helper()
	for i, ci := range contents {
		if !ci.ContentType.Equal(oidDataContentType) {
			continue
		}
		var bags []safeBag
		var inner asn1.RawValue
		if err := unmarshal(ci.Content.Bytes, &inner); err != nil {
			t.Fatalf("failed to unwrap data content: %v", err)
		}
		if rest, err := asn1.Unmarshal(inner.Bytes, &bags); err != nil {
			t.Fatalf("failed to parse safe contents: %v", err)
		} else if len(rest) != 0 {
			t.Fatalf("trailing data after safe contents (%d bytes)", len(rest))
		}
		changed := false
		for j := range bags {
			if !bags[j].Id.Equal(oidPKCS8ShroundedKeyBag) {
				continue
			}
			var pkinfo encryptedPrivateKeyInfo
			if err := unmarshal(bags[j].Value.Bytes, &pkinfo); err != nil {
				t.Fatalf("failed to parse EPI: %v", err)
			}
			pkinfo.AlgorithmIdentifier = f(pkinfo.AlgorithmIdentifier)
			nb, err := asn1.Marshal(pkinfo)
			if err != nil {
				t.Fatalf("failed to marshal EPI: %v", err)
			}
			bags[j].Value.Bytes = nb
			bags[j].Value.FullBytes = nil
			changed = true
		}
		if changed {
			sb, err := asn1.Marshal(bags)
			if err != nil {
				t.Fatalf("failed to marshal safe contents: %v", err)
			}
			octet, err := asn1.Marshal(sb)
			if err != nil {
				t.Fatalf("failed to wrap safe contents: %v", err)
			}
			contents[i].Content = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: octet}
			contents[i].Content.FullBytes = nil
		}
	}
	return contents
}

// rawSetPBKDF2Int re-encodes the iterations or keyLength INTEGER inside a
// PBES2/PBKDF2 AlgorithmIdentifier using *big.Int, allowing the tests to
// construct negative or overflowing values that encoding/asn1 rejects when
// unmarshaled into an int.
func injectExtraVisibleBag(t *testing.T, contents []contentInfo) []contentInfo {
	t.Helper()
	for i, ci := range contents {
		if !ci.ContentType.Equal(oidDataContentType) {
			continue
		}
		var inner asn1.RawValue
		if err := unmarshal(ci.Content.Bytes, &inner); err != nil {
			t.Fatalf("failed to unwrap data content: %v", err)
		}
		var bags []safeBag
		if rest, err := asn1.Unmarshal(inner.Bytes, &bags); err != nil {
			t.Fatalf("failed to parse visible bags: %v", err)
		} else if len(rest) != 0 {
			t.Fatalf("trailing data after visible bags (%d bytes)", len(rest))
		}
		extra := safeBag{Id: oidKeyBag, Value: asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: []byte{0x30, 0x00}}}
		bags = append(bags, extra)
		sb, err := asn1.Marshal(bags)
		if err != nil {
			t.Fatalf("failed to marshal visible bags: %v", err)
		}
		octet, err := asn1.Marshal(sb)
		if err != nil {
			t.Fatalf("failed to wrap visible bags in OCTET STRING: %v", err)
		}
		contents[i].Content = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: octet}
		return contents
	}
	t.Fatal("no data content found to inject bag")
	return contents
}

func rawSetPBKDF2Int(t *testing.T, alg pkix.AlgorithmIdentifier, field string, value *big.Int) pkix.AlgorithmIdentifier {
	t.Helper()
	var params pbes2Params
	if err := unmarshal(alg.Parameters.FullBytes, &params); err != nil {
		t.Fatalf("failed to parse PBES2 params: %v", err)
	}

	var rawKdf asn1.RawValue
	if _, err := asn1.Unmarshal(params.Kdf.Parameters.FullBytes, &rawKdf); err != nil {
		t.Fatalf("failed to parse raw PBKDF2 params: %v", err)
	}

	var seqItems []asn1.RawValue
	rest := rawKdf.Bytes
	for len(rest) > 0 {
		var item asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &item)
		if err != nil {
			t.Fatalf("failed to parse PBKDF2 sequence item: %v", err)
		}
		seqItems = append(seqItems, item)
	}

	// PBKDF2-params ::= SEQUENCE { salt, iterationCount INTEGER, keyLength INTEGER OPTIONAL, prf ... }
	intBytes, err := asn1.Marshal(value)
	if err != nil {
		t.Fatalf("failed to marshal big int: %v", err)
	}
	var intValue asn1.RawValue
	if _, err := asn1.Unmarshal(intBytes, &intValue); err != nil {
		t.Fatalf("failed to parse marshaled big int: %v", err)
	}

	switch field {
	case "iterations":
		if len(seqItems) < 2 {
			t.Fatalf("PBKDF2 params have no iteration field")
		}
		seqItems[1] = intValue
	case "keylength":
		// Ensure a keyLength field exists as element index 2.
		for len(seqItems) < 3 {
			seqItems = append(seqItems, asn1.RawValue{})
		}
		seqItems[2] = intValue
	default:
		t.Fatalf("unknown field %q", field)
	}

	var body []byte
	for _, item := range seqItems {
		b := item.FullBytes
		if len(b) == 0 {
			var err error
			b, err = asn1.Marshal(item)
			if err != nil {
				t.Fatalf("failed to marshal PBKDF2 item: %v", err)
			}
		}
		body = append(body, b...)
	}
	newKdfBytes, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
	if err != nil {
		t.Fatalf("failed to marshal PBKDF2 sequence: %v", err)
	}
	params.Kdf.Parameters.FullBytes = newKdfBytes

	pb, err := asn1.Marshal(params)
	if err != nil {
		t.Fatalf("failed to marshal PBES2 params: %v", err)
	}
	alg.Parameters.FullBytes = pb
	return alg
}

// --- Tests ----------------------------------------------------------------

// A conforming PFX decodes successfully with the matching policy.  With the
// Modern2023 encoder (iterations=2), there are exactly three PBKDF2
// invocations: one for the MAC, one for the encrypted cert safe content, and
// one for the shrouded key.
func TestPolicyAcceptModern2023(t *testing.T) {
	key, cert := testKeyAndCert(t)
	pfxData := mustEncode(t, Modern2023.WithIterations(2), key, cert)

	counters := installKDFCounters()
	defer counters.restore()

	pk, leaf, caCerts, err := DecodeChainWithPolicy(modern2023Policy, pfxData, "passw0rd")
	if err != nil {
		t.Fatalf("expected successful decode, got %v", err)
	}
	if len(caCerts) != 0 {
		t.Errorf("expected no CA certs, got %d", len(caCerts))
	}
	if !leaf.Equal(cert) {
		t.Error("decoded certificate does not match")
	}
	rsaKey, ok := pk.(*rsa.PrivateKey)
	if !ok || !rsaKey.PublicKey.Equal(&key.PublicKey) {
		t.Error("decoded key does not match")
	}
	if counters.pbkdf2Calls != 2 || counters.legacyCalls != 1 {
		t.Errorf("expected 2 PBKDF2 and 1 legacy MAC KDF calls, got pbkdf2=%d legacy=%d", counters.pbkdf2Calls, counters.legacyCalls)
	}
	for _, n := range append(counters.pbkdf2Iters, counters.legacyIters...) {
		if n != 2 {
			t.Errorf("expected 2 iterations per KDF call, got %d", n)
		}
	}
}

// A conforming Modern2026 (PBMAC1) PFX decodes with the matching policy.
func TestPolicyAcceptModern2026(t *testing.T) {
	key, cert := testKeyAndCert(t)
	pfxData := mustEncode(t, Modern2026.WithIterations(2), key, cert)

	counters := installKDFCounters()
	defer counters.restore()

	if _, _, _, err := DecodeChainWithPolicy(modern2026Policy, pfxData, "passw0rd"); err != nil {
		t.Fatalf("expected successful decode, got %v", err)
	}
	if counters.pbkdf2Calls != 3 {
		t.Errorf("expected 3 PBKDF2 calls, got %d", counters.pbkdf2Calls)
	}
}

// A conforming LegacyDES PFX decodes with the matching policy and charges
// legacy PBE work: MAC=2 + cert safe content=2*2 + shrouded key=2*2 = 10.
func TestPolicyAcceptLegacyDES(t *testing.T) {
	key, cert := testKeyAndCert(t)
	pfxData := mustEncode(t, LegacyDES.WithIterations(2), key, cert)

	counters := installKDFCounters()
	defer counters.restore()

	if _, _, _, err := DecodeChainWithPolicy(legacyDESPolicy, pfxData, "passw0rd"); err != nil {
		t.Fatalf("expected successful decode, got %v", err)
	}
	if counters.legacyCalls != 5 {
		t.Errorf("expected 5 legacy KDF calls (MAC + key + IV twice), got %d", counters.legacyCalls)
	}
}

// Rejection must happen before any expensive KDF computation: every rejected
// case below performs zero KDF invocations.
func TestPolicyRejectionsBeforeKDF(t *testing.T) {
	key, cert := testKeyAndCert(t)

	type testCase struct {
		name      string
		pfxData   []byte
		policy    *Policy
		wantError error
	}

	// Base Modern2023 PFX (iterations=2): total PBKDF2 work = 6.
	modernPFX := mustEncode(t, Modern2023.WithIterations(2), key, cert)

	// Base LegacyDES PFX (iterations=2): total legacy work = 10.
	legacyPFX := mustEncode(t, LegacyDES.WithIterations(2), key, cert)

	// PBES2 safe content with a large iteration count: parameters only, the
	// KDF must never run.
	bigIterPFX := func() []byte {
		pfx := reparsePFX(t, modernPFX)
		contents := authenticatedSafeContents(t, pfx)
		for i, ci := range contents {
			if ci.ContentType.Equal(oidEncryptedDataContentType) {
				ed := parseEncryptedCI(t, ci)
				ed.EncryptedContentInfo.ContentEncryptionAlgorithm =
					setPBES2Iterations(t, ed.EncryptedContentInfo.ContentEncryptionAlgorithm, 10_000_000)
				contents[i] = marshalEncryptedCI(t, ci, ed)
			}
		}
		setAuthenticatedSafe(t, pfx, contents)
		return marshalPFX(t, pfx)
	}()

	// Zero iteration count is malformed.
	zeroIterPFX := func() []byte {
		pfx := reparsePFX(t, modernPFX)
		contents := authenticatedSafeContents(t, pfx)
		for i, ci := range contents {
			if ci.ContentType.Equal(oidEncryptedDataContentType) {
				ed := parseEncryptedCI(t, ci)
				ed.EncryptedContentInfo.ContentEncryptionAlgorithm =
					setPBES2Iterations(t, ed.EncryptedContentInfo.ContentEncryptionAlgorithm, 0)
				contents[i] = marshalEncryptedCI(t, ci, ed)
			}
		}
		setAuthenticatedSafe(t, pfx, contents)
		return marshalPFX(t, pfx)
	}()

	// Unknown PBKDF2 PRF OID.
	unknownPrfPFX := func() []byte {
		pfx := reparsePFX(t, modernPFX)
		contents := authenticatedSafeContents(t, pfx)
		for i, ci := range contents {
			if ci.ContentType.Equal(oidEncryptedDataContentType) {
				ed := parseEncryptedCI(t, ci)
				ed.EncryptedContentInfo.ContentEncryptionAlgorithm =
					setPBES2Prf(t, ed.EncryptedContentInfo.ContentEncryptionAlgorithm, asn1.ObjectIdentifier{1, 2, 3, 4, 5})
				contents[i] = marshalEncryptedCI(t, ci, ed)
			}
		}
		setAuthenticatedSafe(t, pfx, contents)
		return marshalPFX(t, pfx)
	}()

	// Unknown outer content-encryption algorithm OID.
	unknownEncPFX := func() []byte {
		pfx := reparsePFX(t, modernPFX)
		contents := authenticatedSafeContents(t, pfx)
		for i, ci := range contents {
			if ci.ContentType.Equal(oidEncryptedDataContentType) {
				ed := parseEncryptedCI(t, ci)
				ed.EncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 999}
				contents[i] = marshalEncryptedCI(t, ci, ed)
			}
		}
		setAuthenticatedSafe(t, pfx, contents)
		return marshalPFX(t, pfx)
	}()

	// MAC algorithm not in the allowlist.
	macNotAllowed := *modern2023Policy
	macNotAllowed.MacAlgorithms = []asn1.ObjectIdentifier{oidSHA512}

	// Encryption algorithm not in the allowlist.
	encNotAllowed := *modern2023Policy
	encNotAllowed.EncryptionAlgorithms = []asn1.ObjectIdentifier{oidAES256CBC}

	// Cumulative work 6 exceeds a limit of 5.
	totalWorkTooLow := *modern2023Policy
	totalWorkTooLow.MaxTotalKDFWork = 5

	// Per-invocation limit of 1 below the iteration count of 2.
	perCallTooLow := *modern2023Policy
	perCallTooLow.MaxKDFIterations = 1

	// Salt length restriction.
	saltPolicy := *modern2023Policy
	saltPolicy.MinSaltLength = 8
	saltPolicy.MaxSaltLength = 8

	// Container size restrictions.
	contentsPolicy := *modern2023Policy
	contentsPolicy.MaxSafeContents = 1
	// The encoder hides cert bags inside an encrypted safe content, so only
	// the shrouded key is visible; inject a second visible bag to exercise the
	// count (a limit of 1 then rejects).
	bagsPolicy := *modern2023Policy
	bagsPolicy.MaxSafeBags = 1
	extraBagPFX := func() []byte {
		pfx := reparsePFX(t, modernPFX)
		contents := authenticatedSafeContents(t, pfx)
		contents = injectExtraVisibleBag(t, contents)
		setAuthenticatedSafe(t, pfx, contents)
		return marshalPFX(t, pfx)
	}()

	// LegacyDES total work is 10; a limit of 9 must reject it.
	legacyTotalTooLow := *legacyDESPolicy
	legacyTotalTooLow.MaxTotalKDFWork = 9

	cases := []testCase{
		{name: "mac not allowed", pfxData: modernPFX, policy: &macNotAllowed, wantError: ErrPolicyRejected},
		{name: "encryption not allowed", pfxData: modernPFX, policy: &encNotAllowed, wantError: ErrPolicyRejected},
		{name: "cumulative work exceeded", pfxData: modernPFX, policy: &totalWorkTooLow, wantError: ErrPolicyRejected},
		{name: "per-call iterations exceeded", pfxData: modernPFX, policy: &perCallTooLow, wantError: ErrPolicyRejected},
		{name: "salt too short", pfxData: modernPFX, policy: &saltPolicy, wantError: ErrPolicyRejected},
		{name: "too many safe contents", pfxData: modernPFX, policy: &contentsPolicy, wantError: ErrPolicyRejected},
		{name: "too many safe bags", pfxData: extraBagPFX, policy: &bagsPolicy, wantError: ErrPolicyRejected},
		{name: "legacy cumulative work exceeded", pfxData: legacyPFX, policy: &legacyTotalTooLow, wantError: ErrPolicyRejected},
		{name: "large iteration count rejected before KDF", pfxData: bigIterPFX, policy: modern2023Policy, wantError: ErrPolicyRejected},
		{name: "zero iterations malformed", pfxData: zeroIterPFX, policy: modern2023Policy, wantError: ErrMalformedParameter},
		{name: "unknown PRF", pfxData: unknownPrfPFX, policy: modern2023Policy, wantError: ErrUnknownAlgorithm},
		{name: "unknown encryption OID", pfxData: unknownEncPFX, policy: modern2023Policy, wantError: ErrUnknownAlgorithm},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			counters := installKDFCounters()
			defer counters.restore()

			err := tc.policy.CheckPolicy(tc.pfxData, 1, 2)
			assertErrorIs(t, err, tc.wantError)
			if counters.totalCalls() != 0 {
				t.Fatalf("rejection ran %d KDF invocations, want 0", counters.totalCalls())
			}

			// The full entry point must reject identically and still do no KDF.
			_, _, _, derr := DecodeChainWithPolicy(tc.policy, tc.pfxData, "passw0rd")
			assertErrorIs(t, derr, tc.wantError)
			if counters.totalCalls() != 0 {
				t.Fatalf("DecodeChainWithPolicy rejection ran %d KDF invocations, want 0", counters.totalCalls())
			}
		})
	}
}

// Negative and overflowing integer parameters are distinctly classified.
func TestPolicyIntegerValidation(t *testing.T) {
	key, cert := testKeyAndCert(t)
	modernPFX := mustEncode(t, Modern2023.WithIterations(2), key, cert)

	negativePFX := func(pfxData []byte, field string) []byte {
		pfx := reparsePFX(t, pfxData)
		contents := authenticatedSafeContents(t, pfx)
		for i, ci := range contents {
			if ci.ContentType.Equal(oidEncryptedDataContentType) {
				ed := parseEncryptedCI(t, ci)
				ed.EncryptedContentInfo.ContentEncryptionAlgorithm =
					rawSetPBKDF2Int(t, ed.EncryptedContentInfo.ContentEncryptionAlgorithm, field, big.NewInt(-5))
				contents[i] = marshalEncryptedCI(t, ci, ed)
			}
		}
		setAuthenticatedSafe(t, pfx, contents)
		return marshalPFX(t, pfx)
	}

	counters := installKDFCounters()
	defer counters.restore()

	err := (&Policy{}).CheckPolicy(negativePFX(modernPFX, "iterations"), 1, 2)
	assertErrorIs(t, err, ErrNegativeValue)

	err = (&Policy{}).CheckPolicy(negativePFX(modernPFX, "keylength"), 1, 2)
	assertErrorIs(t, err, ErrNegativeValue)

	// An integer that cannot fit in an int64 must be reported as overflow.
	huge := new(big.Int).Lsh(big.NewInt(1), 64)
	overflowPFX := func() []byte {
		pfx := reparsePFX(t, modernPFX)
		contents := authenticatedSafeContents(t, pfx)
		for i, ci := range contents {
			if ci.ContentType.Equal(oidEncryptedDataContentType) {
				ed := parseEncryptedCI(t, ci)
				ed.EncryptedContentInfo.ContentEncryptionAlgorithm =
					rawSetPBKDF2Int(t, ed.EncryptedContentInfo.ContentEncryptionAlgorithm, "iterations", huge)
				contents[i] = marshalEncryptedCI(t, ci, ed)
			}
		}
		setAuthenticatedSafe(t, pfx, contents)
		return marshalPFX(t, pfx)
	}()
	err = (&Policy{}).CheckPolicy(overflowPFX, 1, 2)
	assertErrorIs(t, err, ErrIntegerOverflow)

	if counters.totalCalls() != 0 {
		t.Fatalf("integer validation rejection ran %d KDF invocations, want 0", counters.totalCalls())
	}
}

// Passing the policy does not establish integrity: a tampered MAC must still
// be rejected (with ErrIncorrectPassword) after the real MAC KDF runs once.
func TestPolicyStillVerifiesMac(t *testing.T) {
	key, cert := testKeyAndCert(t)
	pfxData := mustEncode(t, Modern2023.WithIterations(2), key, cert)

	pfx := reparsePFX(t, pfxData)
	if len(pfx.MacData.Mac.Digest) == 0 {
		t.Fatal("expected a MAC digest")
	}
	pfx.MacData.Mac.Digest[0] ^= 0xff
	tampered := marshalPFX(t, pfx)

	counters := installKDFCounters()
	defer counters.restore()

	// The policy itself does not check the digest value.
	if err := modern2023Policy.CheckPolicy(tampered, 1, 2); err != nil {
		t.Fatalf("preflight should not validate the digest value, got %v", err)
	}
	_, _, _, err := DecodeChainWithPolicy(modern2023Policy, tampered, "passw0rd")
	assertErrorIs(t, err, ErrIncorrectPassword)

	// The MAC KDF must have actually run exactly once (no empty-password
	// retry with a non-empty password).
	if counters.totalCalls() != 1 {
		t.Fatalf("expected exactly 1 KDF call during MAC verification, got %d", counters.totalCalls())
	}
}

// The cumulative budget is shared across the MAC, encrypted safe contents, and
// shrouded keys and is never reset between layers.  Modern2023 at 2 iterations
// costs: MAC 2 + encrypted safe content 2 + shrouded key 2 = 6.
func TestPolicyBudgetAccumulates(t *testing.T) {
	key, cert := testKeyAndCert(t)
	pfxData := mustEncode(t, Modern2023.WithIterations(2), key, cert)

	for _, limit := range []int64{6, 7, 100} {
		p := *modern2023Policy
		p.MaxTotalKDFWork = limit
		if err := p.CheckPolicy(pfxData, 1, 2); err != nil {
			t.Fatalf("limit %d unexpectedly rejected conforming PFX: %v", limit, err)
		}
	}
	for _, limit := range []int64{0, 1, 5} {
		p := *modern2023Policy
		p.MaxTotalKDFWork = limit
		if limit == 0 {
			p.MaxTotalKDFWork = 5
		}
		err := p.CheckPolicy(pfxData, 1, 2)
		assertErrorIs(t, err, ErrPolicyRejected)
	}
}

// A large-cost shrouded key (inside a plaintext safe content) must be rejected
// by the policy before its KDF ever runs; only the parameters are constructed.
func TestPolicyLargeShroudedKeyRejectedBeforeKDF(t *testing.T) {
	key, cert := testKeyAndCert(t)
	pfxData := mustEncode(t, Modern2023.WithIterations(2), key, cert)

	pfx := reparsePFX(t, pfxData)
	contents := authenticatedSafeContents(t, pfx)
	contents = mutateShroudedKeys(t, contents,
		func(alg pkix.AlgorithmIdentifier) pkix.AlgorithmIdentifier {
			return setPBES2Iterations(t, alg, 50_000_000)
		})
	setAuthenticatedSafe(t, pfx, contents)
	bigShroudPFX := marshalPFX(t, pfx)

	counters := installKDFCounters()
	defer counters.restore()

	err := modern2023Policy.CheckPolicy(bigShroudPFX, 1, 2)
	assertErrorIs(t, err, ErrPolicyRejected)
	if counters.totalCalls() != 0 {
		t.Fatalf("large shrouded key rejection ran %d KDF invocations, want 0", counters.totalCalls())
	}
}

// DecodeTrustStoreWithPolicy enforces the policy too.
func TestPolicyTrustStore(t *testing.T) {
	_, cert := testKeyAndCert(t)
	pfxData, err := Modern2023.WithIterations(2).EncodeTrustStore([]*x509.Certificate{cert}, "passw0rd")
	if err != nil {
		t.Fatalf("failed to encode trust store: %v", err)
	}

	counters := installKDFCounters()
	defer counters.restore()

	certs, err := DecodeTrustStoreWithPolicy(modern2023Policy, pfxData, "passw0rd")
	if err != nil {
		t.Fatalf("expected successful trust store decode, got %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}

	bad := *modern2023Policy
	bad.MaxKDFIterations = 1
	if _, err := DecodeTrustStoreWithPolicy(&bad, pfxData, "passw0rd"); !errors.Is(err, ErrPolicyRejected) {
		t.Fatalf("expected ErrPolicyRejected, got %v", err)
	}
}

// Invalid policies are rejected up front.
func TestPolicyInvalid(t *testing.T) {
	if err := (&Policy{MaxKDFIterations: -1}).CheckPolicy(nil, 1, 2); err == nil {
		t.Fatal("expected error for negative iteration limit")
	}
	if err := (&Policy{MinSaltLength: 32, MaxSaltLength: 16}).CheckPolicy(nil, 1, 2); err == nil {
		t.Fatal("expected error for inverted salt length range")
	}
}

// Error messages must never contain the password or decrypted material.
func TestPolicyErrorMessagesAreSafe(t *testing.T) {
	key, cert := testKeyAndCert(t)
	secret := "s3cr3t-password"
	pfxData := mustEncode(t, Modern2023.WithIterations(2), key, cert)

	bad := *modern2023Policy
	bad.MacAlgorithms = []asn1.ObjectIdentifier{oidSHA512}
	_, _, _, err := DecodeChainWithPolicy(&bad, pfxData, secret)
	if err == nil {
		t.Fatal("expected rejection")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error message leaks password: %v", err)
	}
}

func TestEdgeGarbage(t *testing.T) {
	cases := map[string][]byte{
		"empty":     {},
		"truncated": {0x30, 0x05, 0x02, 0x01, 0x03},
		"random":    []byte("not an asn.1 pfx at all"),
	}
	p := &Policy{}
	for name, data := range cases {
		err := p.CheckPolicy(data, 1, 2)
		if !errors.Is(err, ErrMalformedParameter) {
			t.Errorf("%s: expected ErrMalformedParameter, got %v", name, err)
		}
	}
}

func TestEdgeNegativeMacIterations(t *testing.T) {
	key, cert := testKeyAndCert(t)
	pfxData := mustEncode(t, LegacyDES.WithIterations(2), key, cert)

	// Rebuild with a negative legacy MAC iteration count using a big.Int
	// mirror structure.
	type md struct {
		Mac        digestInfo
		MacSalt    []byte
		Iterations *big.Int `asn1:"optional"`
	}
	type pf struct {
		Version  int
		AuthSafe contentInfo
		MacData  md `asn1:"optional"`
	}
	var p pf
	if _, err := asn1.Unmarshal(pfxData, &p); err != nil {
		t.Fatal(err)
	}
	p.MacData.Iterations = big.NewInt(-7)
	out, err := asn1.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	err = (&Policy{}).CheckPolicy(out, 1, 2)
	if !errors.Is(err, ErrNegativeValue) {
		t.Fatalf("expected ErrNegativeValue, got %v", err)
	}
}

func TestEdgeUnknownMacOid(t *testing.T) {
	key, cert := testKeyAndCert(t)
	pfxData := mustEncode(t, LegacyDES.WithIterations(2), key, cert)

	pfx := reparsePFX(t, pfxData)
	pfx.MacData.Mac.Algorithm = pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 9, 9, 9, 9}}
	out := marshalPFX(t, pfx)
	err := (&Policy{}).CheckPolicy(out, 1, 2)
	if !errors.Is(err, ErrUnknownAlgorithm) {
		t.Fatalf("expected ErrUnknownAlgorithm, got %v", err)
	}
}
