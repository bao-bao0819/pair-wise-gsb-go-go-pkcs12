// Copyright 2026 Opsmate, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"sort"
)

// Attributes contains the attributes associated with a safe bag.
//
// The friendlyName attribute is not a unique identifier: multiple safe bags
// (including bags belonging to different identities) may share the same
// friendly name, or have no friendly name at all.
type Attributes struct {
	// FriendlyName is the value of the friendlyName attribute (OID
	// 1.2.840.113549.1.9.20), or an empty string if the bag has no such
	// attribute.
	FriendlyName string

	// LocalKeyId is the raw bytes of the localKeyId attribute (OID
	// 1.2.840.113549.1.9.21), or nil if the bag has no such attribute.
	//
	// The localKeyId is only a hint used to associate safe bags: the same
	// value may appear on more than one private key or certificate bag, and
	// a value on a certificate bag need not match any private key bag (or
	// vice versa).  Association is always confirmed by comparing public keys.
	LocalKeyId []byte
}

// Certificate is a certificate bag decoded from a PFX.
type Certificate struct {
	// Certificate is the parsed X.509 certificate.
	Certificate *x509.Certificate

	// Attributes contains the safe bag attributes, such as friendlyName and
	// localKeyId.
	Attributes Attributes
}

// Identity is a private key together with the certificates associated with
// it.  One private key may correspond to several certificates: for example,
// when a renewed certificate is placed alongside the old one, or when the
// same key is certified under different subjects.
type Identity struct {
	// PrivateKey is the private key.
	PrivateKey crypto.PrivateKey

	// KeyAttributes contains the attributes of the private key bag.
	KeyAttributes Attributes

	// Certificates contains all the end-entity certificates whose public key
	// matches PrivateKey, including duplicates and renewed or otherwise
	// distinct certificates for the same key.  The order is deterministic and
	// independent of bag order: duplicates sort adjacently.
	Certificates []Certificate

	// ChainCertificates contains the certificates (typically CA certificates)
	// associated with this private key via the localKeyId hint.  A
	// certificate which hints at more than one distinct private key is
	// reported in an [AmbiguityError] instead.
	ChainCertificates []Certificate
}

// Pfx is the result of decoding a PFX containing any number of identities.
type Pfx struct {
	// Identities contains one Identity per distinct private key found in the
	// PFX, sorted deterministically by the public key.  An Identity may have
	// no Certificates if the PFX contained an orphan private key bag.
	Identities []Identity

	// UnassociatedCertificates contains the certificate bags that could not
	// be associated with any private key.  This includes orphan end-entity
	// certificates, trust anchors, and CA certificates without a usable
	// localKeyId hint.
	UnassociatedCertificates []Certificate
}

// AmbiguityCandidate describes one private key bag that a certificate could
// be associated with.
type AmbiguityCandidate struct {
	// FriendlyName is the friendlyName attribute of the candidate key bag,
	// if any.
	FriendlyName string

	// LocalKeyId is the localKeyId attribute of the candidate key bag, if
	// any.
	LocalKeyId []byte
}

// AmbiguityError is returned when a certificate can be associated with more
// than one private key and the association cannot be resolved by comparing
// public keys.  A hint (localKeyId) that points at several distinct private
// keys, or a public-key match with several candidate key bags, are both
// reported this way rather than resolved by arbitrary tie-breaking such as
// bag order.
//
// The error never contains private key material or the PFX password.
type AmbiguityError struct {
	// Subject is the subject of the ambiguously associated certificate.
	Subject string

	// LocalKeyId is the localKeyId hint on the certificate bag, if any.
	LocalKeyId []byte

	// Candidates are the private key bags that the certificate could be
	// associated with.
	Candidates []AmbiguityCandidate
}

func (e *AmbiguityError) Error() string {
	msg := "pkcs12: certificate can be associated with multiple private keys"
	if e.LocalKeyId != nil {
		msg += " (localKeyId=" + hex.EncodeToString(e.LocalKeyId) + ")"
	}
	if e.Subject != "" {
		msg += ": " + e.Subject
	}
	return msg
}

type parsedKeyBag struct {
	privateKey crypto.PrivateKey
	attributes Attributes
}

type parsedCertBag struct {
	certificate *x509.Certificate
	attributes  Attributes
}

func parseBagAttributes(attributes []pkcs12Attribute) Attributes {
	var attrs Attributes
	for _, attribute := range attributes {
		switch {
		case attrs.FriendlyName == "" && attribute.Id.Equal(oidFriendlyName):
			var value asn1.RawValue
			if rest, err := asn1.Unmarshal(attribute.Value.Bytes, &value); err == nil && len(rest) == 0 {
				if name, err := decodeBMPString(value.Bytes); err == nil {
					attrs.FriendlyName = name
				}
			}
		case attrs.LocalKeyId == nil && attribute.Id.Equal(oidLocalKeyID):
			var id []byte
			if rest, err := asn1.Unmarshal(attribute.Value.Bytes, &id); err == nil && len(rest) == 0 {
				attrs.LocalKeyId = id
			}
		}
	}
	return attrs
}

func publicKeyFingerprint(publicKey crypto.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return string(sum[:])
}

func certFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return string(sum[:])
}

func sortCertificates(certs []Certificate) {
	sort.SliceStable(certs, func(i, j int) bool {
		return certFingerprint(certs[i].Certificate) < certFingerprint(certs[j].Certificate)
	})
}

func sortCandidates(candidates []AmbiguityCandidate) {
	sort.SliceStable(candidates, func(i, j int) bool {
		li := hex.EncodeToString(candidates[i].LocalKeyId)
		lj := hex.EncodeToString(candidates[j].LocalKeyId)
		if li != lj {
			return li < lj
		}
		return candidates[i].FriendlyName < candidates[j].FriendlyName
	})
}

// DecodeAll extracts every identity from pfxData, which must be a
// DER-encoded PKCS#12 file.  Unlike [DecodeChain], it supports PFX files
// containing any number of private keys and certificates.
//
// Each private key becomes one [Identity].  End-entity certificates are
// associated with an identity by comparing the certificate's public key with
// the private key's public key; this is the authoritative association.  The
// localKeyId safe bag attribute is used only as a hint to associate the
// remaining certificates (typically CA certificates) with an identity, and a
// hint that matches several distinct private keys results in an
// [AmbiguityError] instead of an arbitrary choice.  The friendlyName
// attribute is never used as a key.  Certificates that cannot be associated
// with any private key are returned in Pfx.UnassociatedCertificates.
//
// Distinct certificates for the same key (including renewed certificates) and
// duplicate copies of a certificate are all retained in
// Identity.Certificates.
//
// The order of the returned identities and certificates is deterministic and
// independent of the order of the safe bags in the input.
func DecodeAll(pfxData []byte, password string) (*Pfx, error) {
	encodedPassword, err := bmpStringZeroTerminated(password)
	if err != nil {
		return nil, err
	}

	bags, encodedPassword, err := getSafeContents(pfxData, encodedPassword, 1, 0)
	if err != nil {
		return nil, err
	}

	var keyBags []parsedKeyBag
	var certBags []parsedCertBag
	for _, bag := range bags {
		switch {
		case bag.Id.Equal(oidKeyBag):
			privateKey, err := x509.ParsePKCS8PrivateKey(bag.Value.Bytes)
			if err != nil {
				return nil, err
			}
			keyBags = append(keyBags, parsedKeyBag{
				privateKey: privateKey,
				attributes: parseBagAttributes(bag.Attributes),
			})
		case bag.Id.Equal(oidPKCS8ShroundedKeyBag):
			privateKey, err := decodePkcs8ShroudedKeyBag(bag.Value.Bytes, encodedPassword)
			if err != nil {
				return nil, err
			}
			keyBags = append(keyBags, parsedKeyBag{
				privateKey: privateKey,
				attributes: parseBagAttributes(bag.Attributes),
			})
		case bag.Id.Equal(oidCertBag):
			certsData, err := decodeCertBag(bag.Value.Bytes)
			if err != nil {
				return nil, err
			}
			certs, err := x509.ParseCertificates(certsData)
			if err != nil {
				return nil, err
			}
			if len(certs) != 1 {
				return nil, errors.New("pkcs12: expected exactly one certificate in the certBag")
			}
			certBags = append(certBags, parsedCertBag{
				certificate: certs[0],
				attributes:  parseBagAttributes(bag.Attributes),
			})
		}
	}

	sort.SliceStable(keyBags, func(i, j int) bool {
		fpi := publicKeyFingerprint(keyBags[i].privateKey.(interface{ Public() crypto.PublicKey }).Public())
		fpj := publicKeyFingerprint(keyBags[j].privateKey.(interface{ Public() crypto.PublicKey }).Public())
		if fpi != fpj {
			return fpi < fpj
		}
		idi := hex.EncodeToString(keyBags[i].attributes.LocalKeyId)
		idj := hex.EncodeToString(keyBags[j].attributes.LocalKeyId)
		if idi != idj {
			return idi < idj
		}
		return keyBags[i].attributes.FriendlyName < keyBags[j].attributes.FriendlyName
	})

	identitiesByFingerprint := make(map[string]*Identity)
	var keyFingerprints []string
	for _, keyBag := range keyBags {
		fingerprint := publicKeyFingerprint(keyBag.privateKey.(interface{ Public() crypto.PublicKey }).Public())
		identity, ok := identitiesByFingerprint[fingerprint]
		if !ok {
			identity = &Identity{
				PrivateKey:   keyBag.privateKey,
				KeyAttributes: keyBag.attributes,
			}
			identitiesByFingerprint[fingerprint] = identity
			keyFingerprints = append(keyFingerprints, fingerprint)
		}
	}

	keysByLocalKeyId := make(map[string][]string)
	for fingerprint, identity := range identitiesByFingerprint {
		if id := identity.KeyAttributes.LocalKeyId; id != nil {
			hint := string(id)
			keysByLocalKeyId[hint] = append(keysByLocalKeyId[hint], fingerprint)
		}
	}

	var unassociated []Certificate
	for _, certBag := range certBags {
		cert := certBag.certificate
		fingerprint := publicKeyFingerprint(cert.PublicKey)
		certificate := Certificate{Certificate: cert, Attributes: certBag.attributes}

		if identity, ok := identitiesByFingerprint[fingerprint]; ok {
			identity.Certificates = append(identity.Certificates, certificate)
			continue
		}

		if certBag.attributes.LocalKeyId != nil {
			candidates := keysByLocalKeyId[string(certBag.attributes.LocalKeyId)]
			if len(candidates) == 1 {
				identity := identitiesByFingerprint[candidates[0]]
				identity.ChainCertificates = append(identity.ChainCertificates, certificate)
				continue
			}
			if len(candidates) > 1 {
				seen := make(map[string]bool)
				var ambiguousCandidates []AmbiguityCandidate
				for _, candidateFingerprint := range candidates {
					if seen[candidateFingerprint] {
						continue
					}
					seen[candidateFingerprint] = true
					identity := identitiesByFingerprint[candidateFingerprint]
					ambiguousCandidates = append(ambiguousCandidates, AmbiguityCandidate{
						FriendlyName: identity.KeyAttributes.FriendlyName,
						LocalKeyId:   identity.KeyAttributes.LocalKeyId,
					})
				}
				sortCandidates(ambiguousCandidates)
				return nil, &AmbiguityError{
					Subject:    cert.Subject.String(),
					LocalKeyId: certBag.attributes.LocalKeyId,
					Candidates: ambiguousCandidates,
				}
			}
		}

		unassociated = append(unassociated, certificate)
	}

	pfx := new(Pfx)
	sort.Strings(keyFingerprints)
	for _, fingerprint := range keyFingerprints {
		identity := identitiesByFingerprint[fingerprint]
		sortCertificates(identity.Certificates)
		sortCertificates(identity.ChainCertificates)
		pfx.Identities = append(pfx.Identities, *identity)
	}
	sortCertificates(unassociated)
	pfx.UnassociatedCertificates = unassociated

	return pfx, nil
}
