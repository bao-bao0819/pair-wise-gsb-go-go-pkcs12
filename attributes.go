// Copyright 2026 Opsmate, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"encoding/asn1"
	"errors"
	"fmt"
)

var (
	// ErrDuplicateAttribute is returned when an attribute OID appears more
	// than once in an attribute list where at most one occurrence is
	// expected.  The first occurrence is never silently overwritten by a
	// later one.
	ErrDuplicateAttribute = errors.New("pkcs12: duplicate attribute")

	// ErrMultipleAttributeValues is returned when an attribute contains
	// more than one value where exactly one is expected.
	ErrMultipleAttributeValues = errors.New("pkcs12: attribute has multiple values")

	// ErrNoAttributeValues is returned when an attribute's value SET is
	// empty where exactly one value is expected.
	ErrNoAttributeValues = errors.New("pkcs12: attribute has no values")
)

// An Attribute is a single PKCS#12 attribute, as found in the Attributes SET
// of a SafeBag (RFC 7292, section 4.2).  Attributes are self-describing
// metadata attached to a bag: the OID identifies the attribute type and
// Values holds the raw values of the attribute's SET OF AttributeValue.
//
// Attributes such as friendlyName and localKeyId are display and correlation
// hints only.  They are not authenticated beyond the PFX MAC (which anyone
// with the password can recompute), and they MUST NOT be treated as proof of
// private key ownership or of certificate trustworthiness.
type Attribute struct {
	// OID identifies the attribute type.  Unknown OIDs are preserved
	// as-is; no semantics are guessed for them.
	OID asn1.ObjectIdentifier

	// Values holds every value of the attribute's SET, in the order in
	// which they appeared in the input.  Duplicate values are preserved.
	Values []AttributeValue
}

// An AttributeValue is a single value of an [Attribute].  It preserves the
// value's ASN.1 type (class, tag, and constructed bit) along with its raw
// DER encoding, so values with unknown or uncommon tags round-trip without
// loss.
type AttributeValue struct {
	asn1.RawValue
}

// Attributes is an ordered list of bag attributes.  Duplicate OIDs are
// preserved, as is the original order of the attributes.
type Attributes []Attribute

// cloneRawValue deep-copies a RawValue so that the returned Attributes do
// not alias the caller's input buffer.
func cloneRawValue(rv asn1.RawValue) asn1.RawValue {
	rv.Bytes = append([]byte(nil), rv.Bytes...)
	rv.FullBytes = append([]byte(nil), rv.FullBytes...)
	return rv
}

// ParseAttributes parses der, which must be the DER encoding of a SET OF
// Attribute as found in a SafeBag, and returns the attributes in their
// original order, preserving duplicate OIDs.
//
// Every returned byte slice is a private copy: mutating der or the returned
// slices does not affect the result of any past or future parse.
func ParseAttributes(der []byte) (Attributes, error) {
	var set asn1.RawValue
	rest, err := asn1.Unmarshal(der, &set)
	if err != nil {
		return nil, fmt.Errorf("pkcs12: error parsing attributes: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("pkcs12: trailing data after attributes SET")
	}
	if set.Class != 0 || set.Tag != 17 || !set.IsCompound {
		return nil, errors.New("pkcs12: attributes are not a SET")
	}

	var attrs Attributes
	data := set.Bytes
	for len(data) > 0 {
		var raw asn1.RawValue
		var err error
		data, err = asn1.Unmarshal(data, &raw)
		if err != nil {
			return nil, fmt.Errorf("pkcs12: error parsing attribute: %w", err)
		}
		attr, err := parseAttribute(raw)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, attr)
	}
	return attrs, nil
}

func parseAttribute(raw asn1.RawValue) (Attribute, error) {
	if raw.Class != 0 || raw.Tag != 16 || !raw.IsCompound {
		return Attribute{}, errors.New("pkcs12: attribute is not a SEQUENCE")
	}

	rest := raw.Bytes
	var oidRaw asn1.RawValue
	rest, err := asn1.Unmarshal(rest, &oidRaw)
	if err != nil {
		return Attribute{}, fmt.Errorf("pkcs12: error parsing attribute OID: %w", err)
	}
	if oidRaw.Class != 0 || oidRaw.Tag != 6 || oidRaw.IsCompound {
		return Attribute{}, errors.New("pkcs12: attribute type is not an OBJECT IDENTIFIER")
	}
	var attr Attribute
	if _, err := asn1.Unmarshal(oidRaw.FullBytes, &attr.OID); err != nil {
		return Attribute{}, fmt.Errorf("pkcs12: error parsing attribute OID: %w", err)
	}

	var valuesSet asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &valuesSet)
	if err != nil {
		return Attribute{}, fmt.Errorf("pkcs12: error parsing attribute values: %w", err)
	}
	if len(rest) != 0 {
		return Attribute{}, fmt.Errorf("pkcs12: trailing data in attribute with OID %s", attr.OID)
	}
	if valuesSet.Class != 0 || valuesSet.Tag != 17 || !valuesSet.IsCompound {
		return Attribute{}, fmt.Errorf("pkcs12: values of attribute with OID %s are not a SET", attr.OID)
	}

	values := valuesSet.Bytes
	for len(values) > 0 {
		var value asn1.RawValue
		var err error
		values, err = asn1.Unmarshal(values, &value)
		if err != nil {
			return Attribute{}, fmt.Errorf("pkcs12: error parsing value of attribute with OID %s: %w", attr.OID, err)
		}
		attr.Values = append(attr.Values, AttributeValue{cloneRawValue(value)})
	}
	return attr, nil
}

// Encode returns the DER encoding of attrs as a SET OF Attribute, suitable
// for placing back into a SafeBag.  Attributes and values are emitted in
// slice order; no canonical reordering is applied.  Values that were parsed
// from existing data and left untouched are emitted using their original
// raw DER encoding, so attributes with unknown OIDs or uncommon tags
// round-trip without loss.
//
// Note: when changing a parsed [AttributeValue], replace the whole
// RawValue (or clear FullBytes); if FullBytes is set it takes precedence
// over the other fields when encoding.
func (attrs Attributes) Encode() ([]byte, error) {
	var body []byte
	for _, attr := range attrs {
		encoded, err := attr.encode()
		if err != nil {
			return nil, err
		}
		body = append(body, encoded...)
	}
	return asn1.Marshal(asn1.RawValue{Class: 0, Tag: 17, IsCompound: true, Bytes: body})
}

func (attr Attribute) encode() ([]byte, error) {
	if len(attr.OID) == 0 {
		return nil, errors.New("pkcs12: attribute has no OID")
	}
	oidDER, err := asn1.Marshal(attr.OID)
	if err != nil {
		return nil, fmt.Errorf("pkcs12: error encoding attribute OID: %w", err)
	}
	var valuesBody []byte
	for _, value := range attr.Values {
		valueDER, err := asn1.Marshal(value.RawValue)
		if err != nil {
			return nil, fmt.Errorf("pkcs12: error encoding value of attribute with OID %s: %w", attr.OID, err)
		}
		valuesBody = append(valuesBody, valueDER...)
	}
	valuesDER, err := asn1.Marshal(asn1.RawValue{Class: 0, Tag: 17, IsCompound: true, Bytes: valuesBody})
	if err != nil {
		return nil, err
	}
	body := append(oidDER, valuesDER...)
	return asn1.Marshal(asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: body})
}

// find returns every attribute with the given OID, in order.
func (attrs Attributes) find(oid asn1.ObjectIdentifier) []Attribute {
	var matches []Attribute
	for _, attr := range attrs {
		if attr.OID.Equal(oid) {
			matches = append(matches, attr)
		}
	}
	return matches
}

// singleValue returns the sole value of attr, or a descriptive error if the
// attribute has zero or multiple values.
func singleValue(attr Attribute, name string) (AttributeValue, error) {
	switch len(attr.Values) {
	case 0:
		return AttributeValue{}, fmt.Errorf("pkcs12: %w: %s (OID %s)", ErrNoAttributeValues, name, attr.OID)
	case 1:
		return attr.Values[0], nil
	default:
		return AttributeValue{}, fmt.Errorf("pkcs12: %w: %s (OID %s) has %d values", ErrMultipleAttributeValues, name, attr.OID, len(attr.Values))
	}
}

// describeType returns a human-readable description of a value's ASN.1 type.
func describeType(rv asn1.RawValue) string {
	constructed := "primitive"
	if rv.IsCompound {
		constructed = "constructed"
	}
	return fmt.Sprintf("class %d, tag %d (%s)", rv.Class, rv.Tag, constructed)
}

// FriendlyName returns the value of the friendlyName attribute
// (OID 1.2.840.113549.1.9.20) decoded as a BMPString.  The boolean result
// reports whether the attribute is present.
//
// An error is returned, rather than a guess, if the attribute is present but
// cannot be unambiguously interpreted: it appears more than once
// ([ErrDuplicateAttribute]), has zero values ([ErrNoAttributeValues]) or
// multiple values ([ErrMultipleAttributeValues]), is not a BMPString, or
// contains invalid BMPString data.  When an error is returned, the raw
// attribute values remain available in attrs for manual inspection.
//
// friendlyName is a display hint only; it MUST NOT be treated as proof of
// private key ownership or of certificate trustworthiness.
func (attrs Attributes) FriendlyName() (name string, present bool, err error) {
	matches := attrs.find(oidFriendlyName)
	if len(matches) == 0 {
		return "", false, nil
	}
	if len(matches) > 1 {
		return "", false, fmt.Errorf("pkcs12: %w: friendlyName (OID %s) appears %d times", ErrDuplicateAttribute, oidFriendlyName, len(matches))
	}
	value, err := singleValue(matches[0], "friendlyName")
	if err != nil {
		return "", false, err
	}
	if value.Class != 0 || value.Tag != 30 || value.IsCompound {
		return "", false, fmt.Errorf("pkcs12: friendlyName value is %s, not a BMPString", describeType(value.RawValue))
	}
	name, err = decodeBMPString(value.Bytes)
	if err != nil {
		return "", false, fmt.Errorf("pkcs12: error decoding friendlyName: %w", err)
	}
	return name, true, nil
}

// LocalKeyID returns the value of the localKeyId attribute
// (OID 1.2.840.113549.1.9.21) as raw bytes.  The boolean result reports
// whether the attribute is present.  The returned slice is a copy; mutating
// it does not affect attrs.
//
// An error is returned, rather than a guess, if the attribute is present but
// cannot be unambiguously interpreted: it appears more than once
// ([ErrDuplicateAttribute]), has zero values ([ErrNoAttributeValues]) or
// multiple values ([ErrMultipleAttributeValues]), or is not an OCTET STRING.
// When an error is returned, the raw attribute values remain available in
// attrs for manual inspection.
//
// localKeyId is a correlation hint only; it MUST NOT be treated as proof of
// private key ownership or of certificate trustworthiness.
func (attrs Attributes) LocalKeyID() (id []byte, present bool, err error) {
	matches := attrs.find(oidLocalKeyID)
	if len(matches) == 0 {
		return nil, false, nil
	}
	if len(matches) > 1 {
		return nil, false, fmt.Errorf("pkcs12: %w: localKeyId (OID %s) appears %d times", ErrDuplicateAttribute, oidLocalKeyID, len(matches))
	}
	value, err := singleValue(matches[0], "localKeyId")
	if err != nil {
		return nil, false, err
	}
	if value.Class != 0 || value.Tag != 4 || value.IsCompound {
		return nil, false, fmt.Errorf("pkcs12: localKeyId value is %s, not an OCTET STRING", describeType(value.RawValue))
	}
	return append([]byte(nil), value.Bytes...), true, nil
}

// NewFriendlyNameAttribute returns an Attribute with the friendlyName OID
// and a single BMPString value holding name.
func NewFriendlyNameAttribute(name string) (Attribute, error) {
	encoded, err := bmpString(name)
	if err != nil {
		return Attribute{}, err
	}
	return Attribute{
		OID:    oidFriendlyName,
		Values: []AttributeValue{{asn1.RawValue{Class: 0, Tag: 30, Bytes: encoded}}},
	}, nil
}

// NewLocalKeyIDAttribute returns an Attribute with the localKeyId OID and a
// single OCTET STRING value holding a copy of id.
func NewLocalKeyIDAttribute(id []byte) Attribute {
	return Attribute{
		OID:    oidLocalKeyID,
		Values: []AttributeValue{{asn1.RawValue{Class: 0, Tag: 4, Bytes: append([]byte(nil), id...)}}},
	}
}
