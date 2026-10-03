// Copyright 2026 Opsmate, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
)

// A BagAttribute is a decoded attribute of a safe bag, such as a
// friendlyName or localKeyId.
type BagAttribute struct {
	// Name is "friendlyName", "localKeyId", or "Microsoft CSP Name" for
	// well-known attributes, or the dotted-decimal OID for unrecognized
	// attributes.
	Name string
	// Value is the decoded attribute value.  Binary values (such as
	// localKeyId and unrecognized attributes) are hex-encoded.
	Value string
}

// An Identity associates a single private key found in a PKCS#12 file with
// the certificates that belong to it.
type Identity struct {
	// PrivateKey is the private key, as returned by
	// [x509.ParsePKCS8PrivateKey].
	PrivateKey interface{}

	// LeafCertificates are the certificates whose public key equals
	// PrivateKey's public key.  A key may have more than one leaf
	// certificate (for example, a renewed certificate for the same key),
	// and duplicate certificates are preserved, so the relationships
	// present in the file remain explainable.  The slice is sorted by the
	// certificates' DER encoding so that the result does not depend on
	// the order of the safe bags in the file.
	LeafCertificates []*x509.Certificate

	// Certificates are certificates that are associated with this
	// identity via the localKeyId attribute but whose public key does
	// not match PrivateKey (for example, CA certificates or stale
	// certificates sharing the key's localKeyId).  The slice is sorted
	// by the certificates' DER encoding.
	Certificates []*x509.Certificate

	// Attributes are the attributes of the private key's safe bag, in
	// the order in which they appear in the bag.  Note that friendlyName
	// is not a unique identifier: multiple identities may share the same
	// friendlyName.
	Attributes []BagAttribute
}

// FriendlyName returns the value of the identity's friendlyName attribute,
// or the empty string if the key bag has no such attribute.  If the bag
// contains several friendlyName attributes, the first one is returned.
//
// Note that friendlyName is not a unique identifier and must not be used
// to distinguish identities.
func (id *Identity) FriendlyName() string {
	for _, attr := range id.Attributes {
		if attr.Name == "friendlyName" {
			return attr.Value
		}
	}
	return ""
}

// AmbiguousAssociationError is returned by [DecodeIdentities] when a
// certificate cannot be unambiguously associated with a single private
// key.  This happens when the certificate's public key matches more than
// one private key in the file (for example, when the same key is stored
// in multiple key bags), or when its localKeyId attribute matches the
// localKeyId of more than one private key.  Rather than picking a
// candidate based on the order of the safe bags, DecodeIdentities
// reports the ambiguity.
//
// The error deliberately contains only public information: certificate
// details and public key fingerprints.  It never contains private key
// material or the password.
type AmbiguousAssociationError struct {
	// Certificate is the certificate that could not be associated.
	Certificate *x509.Certificate

	// CandidateKeyFingerprints are the SHA-256 fingerprints of the DER
	// encodings of the public keys of the candidate private keys.
	CandidateKeyFingerprints [][]byte
}

func (e *AmbiguousAssociationError) Error() string {
	fps := make([]string, len(e.CandidateKeyFingerprints))
	for i, fp := range e.CandidateKeyFingerprints {
		fps[i] = hex.EncodeToString(fp)
	}
	return fmt.Sprintf("pkcs12: certificate %q (sha256 %x) ambiguously matches %d private keys (public key sha256: %v)",
		e.Certificate.Subject.String(), sha256.Sum256(e.Certificate.Raw), len(e.CandidateKeyFingerprints), fps)
}

// DecodeIdentities decodes a DER-encoded PKCS#12 file that may contain
// multiple private keys ("identities").  For every private key in the
// file it returns an [Identity] containing the key, the certificates
// belonging to it, and the attributes of its safe bag.  Certificates
// that cannot be associated with any private key are returned separately
// as unassociatedCerts.
//
// Certificates are associated with private keys as follows: a
// certificate whose public key equals a private key's public key is a
// leaf certificate of that key.  The localKeyId attribute is only used
// as a hint: it can associate a certificate whose public key does not
// match any key in the file (for example a CA certificate) with the
// identity carrying the same localKeyId, but the final decision about
// which key a certificate belongs to is always made by comparing public
// keys.  friendlyName is never used for association, since it is not
// unique.
//
// If a certificate matches more than one private key, an
// [*AmbiguousAssociationError] is returned instead of guessing based on
// the order of the safe bags.
//
// The returned identities and certificate slices are sorted
// deterministically, so the result does not depend on the order of the
// safe bags in the file.
func DecodeIdentities(pfxData []byte, password string) (identities []*Identity, unassociatedCerts []*x509.Certificate, err error) {
	encodedPassword, err := bmpStringZeroTerminated(password)
	if err != nil {
		return nil, nil, err
	}

	bags, encodedPassword, err := getSafeContents(pfxData, encodedPassword, 1, 0)
	if err != nil {
		return nil, nil, err
	}

	type keyEntry struct {
		identity    *Identity
		publicKey   []byte // DER encoding of the public key
		localKeyIDs map[string]bool
	}
	type certEntry struct {
		cert        *x509.Certificate
		publicKey   []byte // DER encoding of the certificate's public key
		localKeyIDs map[string]bool
	}

	var keys []*keyEntry
	var certs []*certEntry

	for i := range bags {
		bag := &bags[i]
		switch {
		case bag.Id.Equal(oidCertBag):
			certsData, err := decodeCertBag(bag.Value.Bytes)
			if err != nil {
				return nil, nil, err
			}
			parsedCerts, err := x509.ParseCertificates(certsData)
			if err != nil {
				return nil, nil, err
			}
			if len(parsedCerts) != 1 {
				return nil, nil, errors.New("pkcs12: expected exactly one certificate in the certBag")
			}
			_, localKeyIDs, err := decodeBagAttributes(bag)
			if err != nil {
				return nil, nil, err
			}
			publicKey, err := x509.MarshalPKIXPublicKey(parsedCerts[0].PublicKey)
			if err != nil {
				return nil, nil, errors.New("pkcs12: error marshaling certificate public key: " + err.Error())
			}
			certs = append(certs, &certEntry{
				cert:        parsedCerts[0],
				publicKey:   publicKey,
				localKeyIDs: localKeyIDs,
			})

		case bag.Id.Equal(oidKeyBag), bag.Id.Equal(oidPKCS8ShroundedKeyBag):
			var privateKey interface{}
			if bag.Id.Equal(oidKeyBag) {
				if privateKey, err = x509.ParsePKCS8PrivateKey(bag.Value.Bytes); err != nil {
					return nil, nil, err
				}
			} else {
				if privateKey, err = decodePkcs8ShroudedKeyBag(bag.Value.Bytes, encodedPassword); err != nil {
					return nil, nil, err
				}
			}
			signer, ok := privateKey.(crypto.Signer)
			if !ok {
				return nil, nil, fmt.Errorf("pkcs12: private key of type %T does not expose a public key", privateKey)
			}
			publicKey, err := x509.MarshalPKIXPublicKey(signer.Public())
			if err != nil {
				return nil, nil, errors.New("pkcs12: error marshaling public key: " + err.Error())
			}
			attributes, localKeyIDs, err := decodeBagAttributes(bag)
			if err != nil {
				return nil, nil, err
			}
			keys = append(keys, &keyEntry{
				identity: &Identity{
					PrivateKey: privateKey,
					Attributes: attributes,
				},
				publicKey:   publicKey,
				localKeyIDs: localKeyIDs,
			})
		}
	}

	for _, c := range certs {
		// The public key decides which key a certificate belongs to.
		var matches []*keyEntry
		for _, k := range keys {
			if bytes.Equal(c.publicKey, k.publicKey) {
				matches = append(matches, k)
			}
		}
		leaf := true
		if len(matches) == 0 {
			// Fall back to the localKeyId hint for certificates
			// whose public key doesn't match any key in the file.
			leaf = false
			for _, k := range keys {
				if intersectsLocalKeyIDs(c.localKeyIDs, k.localKeyIDs) {
					matches = append(matches, k)
				}
			}
		}
		if len(matches) > 1 {
			fingerprints := make([][]byte, len(matches))
			for i, k := range matches {
				fp := sha256.Sum256(k.publicKey)
				fingerprints[i] = fp[:]
			}
			return nil, nil, &AmbiguousAssociationError{
				Certificate:              c.cert,
				CandidateKeyFingerprints: fingerprints,
			}
		}
		if len(matches) == 0 {
			unassociatedCerts = append(unassociatedCerts, c.cert)
			continue
		}
		if leaf {
			matches[0].identity.LeafCertificates = append(matches[0].identity.LeafCertificates, c.cert)
		} else {
			matches[0].identity.Certificates = append(matches[0].identity.Certificates, c.cert)
		}
	}

	// Sort the results so that they don't depend on the order of the
	// safe bags in the file.
	sort.SliceStable(keys, func(i, j int) bool {
		return bytes.Compare(keys[i].publicKey, keys[j].publicKey) < 0
	})
	identities = make([]*Identity, 0, len(keys))
	for _, k := range keys {
		sortCerts(k.identity.LeafCertificates)
		sortCerts(k.identity.Certificates)
		identities = append(identities, k.identity)
	}
	sortCerts(unassociatedCerts)

	return identities, unassociatedCerts, nil
}

func sortCerts(certs []*x509.Certificate) {
	sort.SliceStable(certs, func(i, j int) bool {
		return bytes.Compare(certs[i].Raw, certs[j].Raw) < 0
	})
}

func intersectsLocalKeyIDs(a, b map[string]bool) bool {
	for id := range a {
		if b[id] {
			return true
		}
	}
	return false
}

// decodeBagAttributes decodes the attributes of a safe bag.  In addition
// to the decoded attributes, it returns the set of localKeyId values
// found in the bag, which are used to associate certificates with
// private keys.
func decodeBagAttributes(bag *safeBag) (attributes []BagAttribute, localKeyIDs map[string]bool, err error) {
	for _, attr := range bag.Attributes {
		attribute := attr
		switch {
		case attribute.Id.Equal(oidFriendlyName):
			value, err := decodeBMPStringAttribute(&attribute)
			if err != nil {
				return nil, nil, errors.New("pkcs12: error decoding friendlyName attribute: " + err.Error())
			}
			attributes = append(attributes, BagAttribute{Name: "friendlyName", Value: value})

		case attribute.Id.Equal(oidLocalKeyID):
			rest := attribute.Value.Bytes
			for len(rest) > 0 {
				var id []byte
				rest, err = asn1.Unmarshal(rest, &id)
				if err != nil {
					return nil, nil, errors.New("pkcs12: error decoding localKeyId attribute: " + err.Error())
				}
				if localKeyIDs == nil {
					localKeyIDs = make(map[string]bool)
				}
				localKeyIDs[string(id)] = true
				attributes = append(attributes, BagAttribute{Name: "localKeyId", Value: hex.EncodeToString(id)})
			}

		case attribute.Id.Equal(oidMicrosoftCSPName):
			value, err := decodeBMPStringAttribute(&attribute)
			if err != nil {
				return nil, nil, errors.New("pkcs12: error decoding Microsoft CSP Name attribute: " + err.Error())
			}
			attributes = append(attributes, BagAttribute{Name: "Microsoft CSP Name", Value: value})

		default:
			attributes = append(attributes, BagAttribute{
				Name:  attribute.Id.String(),
				Value: hex.EncodeToString(attribute.Value.Bytes),
			})
		}
	}
	return attributes, localKeyIDs, nil
}

func decodeBMPStringAttribute(attribute *pkcs12Attribute) (string, error) {
	var value asn1.RawValue
	if err := unmarshal(attribute.Value.Bytes, &value); err != nil {
		return "", err
	}
	return decodeBMPString(value.Bytes)
}
