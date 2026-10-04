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
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

// kdfObserver installs an instrumentation hook that records every KDF
// attempted, with its iteration count.
type kdfObserver struct {
	calls      int
	iterations int
	kinds      []string
}

func (o *kdfObserver) install(t *testing.T) {
	t.Helper()
	previous := kdfHook
	kdfHook = func(kind string, iterations int) {
		o.calls++
		o.iterations += iterations
		o.kinds = append(o.kinds, fmt.Sprintf("%s@%d", kind, iterations))
	}
	t.Cleanup(func() { kdfHook = previous })
}

func mustSelfSignedPFX(t *testing.T, enc *Encoder, iterations int, password string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "policy-test"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	pfxData, err := enc.WithIterations(iterations).Encode(key, cert, nil, password)
	if err != nil {
		t.Fatalf("failed to encode PFX: %v", err)
	}
	return pfxData
}

func TestDecodeChainWithPolicyAccepts(t *testing.T) {
	password := "correct horse battery staple"
	pfxData := mustSelfSignedPFX(t, Modern2023, 4, password)

	obs := &kdfObserver{}
	obs.install(t)

	priv, cert, caCerts, err := DecodeChainWithPolicy(pfxData, password, DefaultPolicy())
	if err != nil {
		t.Fatalf("expected decode to succeed, got %v", err)
	}
	if cert.Subject.CommonName != "policy-test" {
		t.Errorf("unexpected subject %q", cert.Subject.CommonName)
	}
	if len(caCerts) != 0 {
		t.Errorf("unexpected CA certs: %d", len(caCerts))
	}
	if err := priv.(*rsa.PrivateKey).Validate(); err != nil {
		t.Errorf("invalid private key: %v", err)
	}

	// MAC (1 PBKDF) + encrypted cert SafeContents (1 PBKDF2) + shrouded key
	// (1 PBKDF2) = exactly 3 derivations, none of which are reset between
	// layers.
	if obs.calls != 3 {
		t.Errorf("expected 3 KDF invocations, got %d: %v", obs.calls, obs.kinds)
	}
}

func TestDecodeChainWithPolicyCumulativeBudget(t *testing.T) {
	password := "correct horse battery staple"
	pfxData := mustSelfSignedPFX(t, Modern2023, 4, password)

	// MAC (4) + cert safe (4) + shrouded key (4) = 12 total iterations.
	t.Run("budget exactly enough", func(t *testing.T) {
		p := DefaultPolicy()
		p.MaxTotalKDFIterations = 12
		obs := &kdfObserver{}
		obs.install(t)
		if _, _, _, err := DecodeChainWithPolicy(pfxData, password, p); err != nil {
			t.Fatalf("expected success, got %v", err)
		}
		if obs.calls != 3 {
			t.Errorf("expected 3 KDF invocations, got %d", obs.calls)
		}
	})

	t.Run("budget one short rejects before any KDF", func(t *testing.T) {
		p := DefaultPolicy()
		p.MaxTotalKDFIterations = 11
		obs := &kdfObserver{}
		obs.install(t)
		_, _, _, err := DecodeChainWithPolicy(pfxData, password, p)
		if !errors.Is(err, ErrPolicyRejected) {
			t.Fatalf("expected ErrPolicyRejected, got %v", err)
		}
		// The MAC (4) and the cert safe (4) are budgeted in preflight and
		// then derived; the shrouded key (4) is what overflows and must be
		// refused before its own derivation.
		if obs.calls != 2 {
			t.Errorf("expected 2 KDF invocations before rejection, got %d (%d iterations): %v", obs.calls, obs.iterations, obs.kinds)
		}
	})

	t.Run("budget survives MAC but rejects shrouded key before its KDF", func(t *testing.T) {
		p := DefaultPolicy()
		// Allow the MAC (4) and the cert safe (4) = 8, shrouded key (4)
		// would make 12.
		p.MaxTotalKDFIterations = 8
		obs := &kdfObserver{}
		obs.install(t)
		_, _, _, err := DecodeChainWithPolicy(pfxData, password, p)
		if !errors.Is(err, ErrPolicyRejected) {
			t.Fatalf("expected ErrPolicyRejected, got %v", err)
		}
		// Only the MAC and the cert-safe derivations may have happened; the
		// shrouded-key derivation must have been refused before running.
		if obs.calls != 2 {
			t.Errorf("expected 2 KDF invocations before rejection, got %d (%d iterations)", obs.calls, obs.iterations)
		}
	})

	t.Run("budget is not reset entering the shrouded key layer", func(t *testing.T) {
		// A generous per-derivation cap but a cumulative cap consumed by the
		// outer two derivations still rejects the shrouded key, even though
		// its own iteration count (4) is under the per-derivation cap.
		p := DefaultPolicy()
		p.MaxKDFIterations = 4
		p.MaxTotalKDFIterations = 8
		obs := &kdfObserver{}
		obs.install(t)
		_, _, _, err := DecodeChainWithPolicy(pfxData, password, p)
		if !errors.Is(err, ErrPolicyRejected) {
			t.Fatalf("expected ErrPolicyRejected, got %v", err)
		}
		if obs.calls != 2 {
			t.Errorf("expected 2 KDF invocations before rejection, got %d (%d iterations): %v", obs.calls, obs.iterations, obs.kinds)
		}
	})
}

func TestDecodeChainWithPolicyPerDerivationLimit(t *testing.T) {
	password := "correct horse battery staple"
	pfxData := mustSelfSignedPFX(t, Modern2023, 4, password)

	p := DefaultPolicy()
	p.MaxTotalKDFIterations = 0
	p.MaxKDFIterations = 3
	obs := &kdfObserver{}
	obs.install(t)
	_, _, _, err := DecodeChainWithPolicy(pfxData, password, p)
	if !errors.Is(err, ErrPolicyRejected) {
		t.Fatalf("expected ErrPolicyRejected, got %v", err)
	}
	if obs.calls != 0 {
		t.Errorf("expected 0 KDF invocations, got %d", obs.calls)
	}
}

func TestDecodeChainWithPolicyRejectsMACAlgorithm(t *testing.T) {
	password := "correct horse battery staple"
	pfxData := mustSelfSignedPFX(t, Modern2023, 4, password)

	p := DefaultPolicy()
	// Permit the PBES2/HMAC/AES machinery but not the MAC digest itself.
	p.AllowedMACAlgorithms = []asn1.ObjectIdentifier{oidPBMAC1, oidHmacWithSHA256, oidHmacWithSHA512}
	obs := &kdfObserver{}
	obs.install(t)
	_, _, _, err := DecodeChainWithPolicy(pfxData, password, p)
	if !errors.Is(err, ErrPolicyRejected) {
		t.Fatalf("expected ErrPolicyRejected, got %v", err)
	}
	if obs.calls != 0 {
		t.Errorf("expected 0 KDF invocations, got %d", obs.calls)
	}
}

func TestDecodeChainWithPolicyRejectsEncryptionAlgorithm(t *testing.T) {
	password := "correct horse battery staple"
	pfxData := mustSelfSignedPFX(t, Modern2023, 4, password)

	p := DefaultPolicy()
	// Drop PBES2 from the encryption allow list.
	allowed := make([]asn1.ObjectIdentifier, 0, len(p.AllowedEncryptionAlgorithms)-1)
	for _, oid := range p.AllowedEncryptionAlgorithms {
		if !oid.Equal(oidPBES2) {
			allowed = append(allowed, oid)
		}
	}
	p.AllowedEncryptionAlgorithms = allowed
	p.MaxTotalKDFIterations = 0

	obs := &kdfObserver{}
	obs.install(t)
	_, _, _, err := DecodeChainWithPolicy(pfxData, password, p)
	if !errors.Is(err, ErrPolicyRejected) {
		t.Fatalf("expected ErrPolicyRejected, got %v", err)
	}
	// All encrypted algorithms are preflighted before the MAC is verified, so
	// no derivation may run at all.
	if obs.calls != 0 {
		t.Errorf("expected 0 KDF invocations, got %d: %v", obs.calls, obs.kinds)
	}
}

func TestDefaultPolicyRejectsLegacyDES(t *testing.T) {
	password := "correct horse battery staple"
	pfxData := mustSelfSignedPFX(t, LegacyDES, 4, password)

	obs := &kdfObserver{}
	obs.install(t)
	_, _, _, err := DecodeChainWithPolicy(pfxData, password, DefaultPolicy())
	if !errors.Is(err, ErrPolicyRejected) {
		t.Fatalf("expected ErrPolicyRejected, got %v", err)
	}
	// The legacy MAC is HMAC-SHA-1, which the default policy also rejects,
	// so nothing may derive.
	if obs.calls != 0 {
		t.Errorf("expected 0 KDF invocations, got %d", obs.calls)
	}
}

func TestDefaultPolicyAcceptsModern2026(t *testing.T) {
	password := "correct horse battery staple"
	pfxData := mustSelfSignedPFX(t, Modern2026, 4, password)

	obs := &kdfObserver{}
	obs.install(t)
	if _, _, _, err := DecodeChainWithPolicy(pfxData, password, DefaultPolicy()); err != nil {
		t.Fatalf("expected Modern2026 PFX to decode under DefaultPolicy, got %v", err)
	}
	// PBMAC1 PBKDF2 (1) + cert safe PBKDF2 (1) + shrouded key PBKDF2 (1).
	if obs.calls != 3 {
		t.Errorf("expected 3 KDF invocations, got %d: %v", obs.calls, obs.kinds)
	}
}

func TestPolicyRejectsPBMAC1BeforeDerivation(t *testing.T) {
	password := "correct horse battery staple"
	pfxData := mustSelfSignedPFX(t, Modern2026, 4, password)

	p := DefaultPolicy()
	// Allow PBES2 but not PBMAC1 at all.
	p.AllowedMACAlgorithms = []asn1.ObjectIdentifier{oidSHA256, oidSHA512}
	obs := &kdfObserver{}
	obs.install(t)
	_, _, _, err := DecodeChainWithPolicy(pfxData, password, p)
	if !errors.Is(err, ErrPolicyRejected) {
		t.Fatalf("expected ErrPolicyRejected, got %v", err)
	}
	if obs.calls != 0 {
		t.Errorf("expected 0 KDF invocations, got %d: %v", obs.calls, obs.kinds)
	}
}

func TestToPEMWithPolicy(t *testing.T) {
	password := "correct horse battery staple"
	pfxData := mustSelfSignedPFX(t, Modern2023, 4, password)

	t.Run("accepts", func(t *testing.T) {
		obs := &kdfObserver{}
		obs.install(t)
		blocks, err := ToPEMWithPolicy(pfxData, password, DefaultPolicy())
		if err != nil {
			t.Fatalf("expected success, got %v", err)
		}
		if len(blocks) != 2 {
			t.Fatalf("expected 2 PEM blocks, got %d", len(blocks))
		}
		if obs.calls != 3 {
			t.Errorf("expected 3 KDF invocations, got %d: %v", obs.calls, obs.kinds)
		}
	})

	t.Run("rejects by policy before derivation", func(t *testing.T) {
		p := DefaultPolicy()
		p.MaxKDFIterations = 1
		obs := &kdfObserver{}
		obs.install(t)
		_, err := ToPEMWithPolicy(pfxData, password, p)
		if !errors.Is(err, ErrPolicyRejected) {
			t.Fatalf("expected ErrPolicyRejected, got %v", err)
		}
		if obs.calls != 0 {
			t.Errorf("expected 0 KDF invocations, got %d: %v", obs.calls, obs.kinds)
		}
	})
}

func TestDecodeWithPolicy(t *testing.T) {
	password := "correct horse battery staple"
	pfxData := mustSelfSignedPFX(t, Modern2023, 4, password)

	priv, cert, err := DecodeWithPolicy(pfxData, password, DefaultPolicy())
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if priv == nil || cert == nil {
		t.Fatal("expected key and certificate")
	}
}

func TestPolicyDoesNotAffectMACVerification(t *testing.T) {
	password := "correct horse battery staple"
	pfxData := mustSelfSignedPFX(t, Modern2023, 4, password)

	t.Run("wrong password still rejected", func(t *testing.T) {
		p := DefaultPolicy()
		p.MaxTotalKDFIterations = 0
		p.MaxKDFIterations = 0
		if _, _, _, err := DecodeChainWithPolicy(pfxData, "wrong password", p); !errors.Is(err, ErrIncorrectPassword) {
			t.Fatalf("expected ErrIncorrectPassword, got %v", err)
		}
	})

	t.Run("permissive policy behaves like DecodeChain", func(t *testing.T) {
		legacy := mustSelfSignedPFX(t, LegacyDES, 4, password)
		if _, _, _, err := DecodeChainWithPolicy(legacy, password, nil); err != nil {
			t.Fatalf("expected permissive decode to succeed, got %v", err)
		}
		if _, _, _, err := DecodeChainWithPolicy(legacy, password, &Policy{}); err != nil {
			t.Fatalf("expected zero-value policy to be permissive, got %v", err)
		}
	})
}

func TestPolicyErrorsContainNoSecrets(t *testing.T) {
	password := "super-secret-password"
	pfxData := mustSelfSignedPFX(t, Modern2023, 4, password)

	p := DefaultPolicy()
	p.MaxKDFIterations = 1
	_, _, _, err := DecodeChainWithPolicy(pfxData, password, p)
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if strings.Contains(msg, password) {
		t.Errorf("error message leaks password: %s", msg)
	}
}

func TestDecodeTrustStoreWithPolicyContainerLimits(t *testing.T) {
	password := "ts-password"
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "trust"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pfxData, err := Modern2023.WithIterations(4).EncodeTrustStore([]*x509.Certificate{cert}, password)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("size limit", func(t *testing.T) {
		p := DefaultPolicy()
		p.MaxPFXSize = 10
		obs := &kdfObserver{}
		obs.install(t)
		_, err := DecodeTrustStoreWithPolicy(pfxData, password, p)
		if !errors.Is(err, ErrPolicyRejected) {
			t.Fatalf("expected ErrPolicyRejected, got %v", err)
		}
		if obs.calls != 0 {
			t.Errorf("expected 0 KDF invocations, got %d", obs.calls)
		}
	})

	t.Run("happy path", func(t *testing.T) {
		certs, err := DecodeTrustStoreWithPolicy(pfxData, password, DefaultPolicy())
		if err != nil {
			t.Fatalf("expected success, got %v", err)
		}
		if len(certs) != 1 {
			t.Fatalf("expected 1 cert, got %d", len(certs))
		}
	})
}
