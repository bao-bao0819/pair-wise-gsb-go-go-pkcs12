package pkcs12

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"fmt"
	"sort"
)

// Attribute is a single PKCS#12 bag attribute as it appears in a SafeBag's
// SET OF Attribute.  Unlike the flat string headers produced by ToPEM,
// Attribute preserves the attribute's OID, every value in the attribute's
// SET (including duplicates), and the original order in which attributes
// appeared on the wire.
//
// Bag attributes such as friendlyName and localKeyId are unauthenticated
// display and correlation hints.  They MUST NOT be treated as proof of
// private key ownership or as a reason to trust a certificate.
type Attribute struct {
	// OID identifies the attribute type.  Unknown OIDs are preserved
	// verbatim; this package does not guess their meaning.
	OID asn1.ObjectIdentifier
	// Values holds every value of the attribute's SET OF AttributeValue,
	// in the order they were encoded.  A SET may be empty or contain
	// multiple values.
	Values []AttributeValue
}

// AttributeValue is a single value of a PKCS#12 attribute.  It records the
// ASN.1 class and tag of the value along with its complete original DER
// encoding, so values of unknown or unsupported types round-trip without
// loss.
type AttributeValue struct {
	// Class is the ASN.1 class of the value's tag: 0 (universal),
	// 1 (application), 2 (context-specific) or 3 (private).
	Class int
	// Tag is the ASN.1 tag number of the value, e.g. 30 for BMPString
	// or 4 for OCTET STRING.
	Tag int
	// DER is the complete DER encoding of the value, including its tag
	// and length bytes.  It is a private copy: mutating it does not
	// affect the data ParseAttributes was called with, and vice versa.
	DER []byte
}

// Attributes is an ordered list of bag attributes.  Duplicate OIDs are
// preserved in their original order rather than being merged or
// overwritten.
type Attributes []Attribute

var (
	// ErrDuplicateAttribute indicates that an attribute OID appeared more
	// than once where a single attribute was expected.
	ErrDuplicateAttribute = errors.New("pkcs12: duplicate attribute")
	// ErrNoAttributeValues indicates that an attribute's value SET is
	// empty where exactly one value was expected.
	ErrNoAttributeValues = errors.New("pkcs12: attribute has no values")
	// ErrMultipleAttributeValues indicates that an attribute's value SET
	// contains more than one value where exactly one was expected.
	ErrMultipleAttributeValues = errors.New("pkcs12: attribute has multiple values")
	// ErrUnexpectedValueType indicates that an attribute value has an
	// ASN.1 type other than the one required for the attribute.
	ErrUnexpectedValueType = errors.New("pkcs12: attribute value has unexpected ASN.1 type")
)

// An AttributeError describes a problem with the attribute identified by
// OID.  Unwrap returns the underlying cause, which may be one of
// ErrDuplicateAttribute, ErrNoAttributeValues, ErrMultipleAttributeValues,
// ErrUnexpectedValueType, or a string decoding error.
type AttributeError struct {
	OID asn1.ObjectIdentifier
	Err error
}

func (e *AttributeError) Error() string {
	return fmt.Sprintf("pkcs12: attribute %s: %s", e.OID, e.Err)
}

func (e *AttributeError) Unwrap() error { return e.Err }

// NewAttributeValue returns an AttributeValue holding a universal-class
// primitive value with the given tag (which must be less than 31) and
// content bytes.  It is a convenience for replacing the values of
// supported attributes before re-encoding; unknown attributes should be
// left untouched so their original DER is preserved.
func NewAttributeValue(tag int, contents []byte) AttributeValue {
	der := append([]byte{byte(tag)}, appendDERLength(nil, len(contents))...)
	der = append(der, contents...)
	return AttributeValue{Class: 0, Tag: tag, DER: der}
}

// ParseAttributes decodes a DER-encoded SET OF Attribute, as found in the
// attributes field of a PKCS#12 SafeBag.  Every attribute, including
// duplicates and unknown OIDs, is preserved in wire order, and every value
// retains its original DER encoding.  The returned slices are private
// copies: mutating them does not affect der, and re-parsing der is
// unaffected by any mutation of a previously returned Attributes.
func ParseAttributes(der []byte) (Attributes, error) {
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil {
		return nil, fmt.Errorf("pkcs12: error decoding attributes: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("pkcs12: trailing data after attributes")
	}
	if outer.Class != 0 || outer.Tag != asn1.TagSet || !outer.IsCompound {
		return nil, errors.New("pkcs12: attributes are not encoded as a SET")
	}

	var attrs Attributes
	body := outer.Bytes
	for len(body) > 0 {
		var raw asn1.RawValue
		body, err = asn1.Unmarshal(body, &raw)
		if err != nil {
			return nil, fmt.Errorf("pkcs12: error decoding attribute: %w", err)
		}
		if raw.Class != 0 || raw.Tag != asn1.TagSequence || !raw.IsCompound {
			return nil, errors.New("pkcs12: attribute is not encoded as a SEQUENCE")
		}
		attr, err := parseAttribute(raw.Bytes)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, attr)
	}
	return attrs, nil
}

func parseAttribute(body []byte) (Attribute, error) {
	var attr Attribute
	rest, err := asn1.Unmarshal(body, &attr.OID)
	if err != nil {
		return attr, fmt.Errorf("pkcs12: error decoding attribute OID: %w", err)
	}
	attr.OID = append(asn1.ObjectIdentifier(nil), attr.OID...)

	var valueSet asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &valueSet)
	if err != nil {
		return attr, fmt.Errorf("pkcs12: error decoding attribute %s values: %w", attr.OID, err)
	}
	if len(rest) != 0 {
		return attr, fmt.Errorf("pkcs12: trailing data in attribute %s", attr.OID)
	}
	if valueSet.Class != 0 || valueSet.Tag != asn1.TagSet || !valueSet.IsCompound {
		return attr, fmt.Errorf("pkcs12: attribute %s values are not encoded as a SET", attr.OID)
	}

	values := valueSet.Bytes
	for len(values) > 0 {
		var raw asn1.RawValue
		values, err = asn1.Unmarshal(values, &raw)
		if err != nil {
			return attr, fmt.Errorf("pkcs12: error decoding attribute %s value: %w", attr.OID, err)
		}
		attr.Values = append(attr.Values, AttributeValue{
			Class: raw.Class,
			Tag:   raw.Tag,
			DER:   append([]byte(nil), raw.FullBytes...),
		})
	}
	return attr, nil
}

// Encode re-encodes attrs as a DER SET OF Attribute.  Every value is
// emitted from its stored DER encoding, so unknown OIDs and values that
// were not modified are preserved byte-for-byte.  Attributes and values
// are sorted as required by DER, which makes Encode(ParseAttributes(der))
// an identity function for valid DER input.
func (attrs Attributes) Encode() ([]byte, error) {
	encodedAttrs := make([][]byte, 0, len(attrs))
	for i := range attrs {
		attr := &attrs[i]
		if len(attr.OID) == 0 {
			return nil, fmt.Errorf("pkcs12: attribute %d has an empty OID", i)
		}
		oidDER, err := asn1.Marshal(attr.OID)
		if err != nil {
			return nil, fmt.Errorf("pkcs12: error encoding attribute %d OID: %w", i, err)
		}

		values := make([][]byte, len(attr.Values))
		for j, value := range attr.Values {
			if len(value.DER) == 0 {
				return nil, fmt.Errorf("pkcs12: attribute %s value %d has no DER encoding", attr.OID, j)
			}
			values[j] = value.DER
		}
		sort.Slice(values, func(a, b int) bool { return bytes.Compare(values[a], values[b]) < 0 })

		content := append(oidDER, derWrap(0x31, bytes.Join(values, nil))...)
		encodedAttrs = append(encodedAttrs, derWrap(0x30, content))
	}
	sort.Slice(encodedAttrs, func(a, b int) bool { return bytes.Compare(encodedAttrs[a], encodedAttrs[b]) < 0 })
	return derWrap(0x31, bytes.Join(encodedAttrs, nil)), nil
}

// FriendlyName returns the value of the bag's friendlyName attribute
// (OID 1.2.840.113549.1.9.20), or "" if the attribute is absent.
//
// Unlike ToPEM's headers, FriendlyName never silently keeps the last
// value: a duplicated attribute, an empty or multi-valued SET, a value
// that is not a BMPString, or an invalid string encoding all produce a
// specific error (wrapping ErrDuplicateAttribute, ErrNoAttributeValues,
// ErrMultipleAttributeValues, ErrUnexpectedValueType, or the decoding
// error).  Even when an error is returned, the raw attributes remain
// available in attrs.
//
// friendlyName is an unauthenticated display hint; it MUST NOT be used as
// proof of private key ownership or certificate trust.
func (attrs Attributes) FriendlyName() (string, error) {
	value, err := attrs.singleValue(oidFriendlyName)
	if err != nil || value == nil {
		return "", err
	}
	raw, err := value.decode()
	if err != nil {
		return "", &AttributeError{OID: oidFriendlyName, Err: err}
	}
	if raw.Class != 0 || raw.Tag != asn1.TagBMPString {
		return "", &AttributeError{OID: oidFriendlyName, Err: fmt.Errorf("%w: expected BMPString, got class %d tag %d", ErrUnexpectedValueType, raw.Class, raw.Tag)}
	}
	name, err := decodeBMPString(raw.Bytes)
	if err != nil {
		return "", &AttributeError{OID: oidFriendlyName, Err: err}
	}
	return name, nil
}

// LocalKeyID returns the value of the bag's localKeyId attribute
// (OID 1.2.840.113549.1.9.21), or nil if the attribute is absent.  The
// returned slice is a copy; mutating it does not affect attrs.
//
// As with FriendlyName, duplicates, empty or multi-valued SETs, and values
// that are not an OCTET STRING produce a specific error instead of being
// silently resolved in favor of the last value, and the raw attributes
// remain available in attrs regardless.
//
// localKeyId is an unauthenticated correlation hint; it MUST NOT be used
// as proof of private key ownership or certificate trust.
func (attrs Attributes) LocalKeyID() ([]byte, error) {
	value, err := attrs.singleValue(oidLocalKeyID)
	if err != nil || value == nil {
		return nil, err
	}
	raw, err := value.decode()
	if err != nil {
		return nil, &AttributeError{OID: oidLocalKeyID, Err: err}
	}
	if raw.Class != 0 || raw.Tag != asn1.TagOctetString {
		return nil, &AttributeError{OID: oidLocalKeyID, Err: fmt.Errorf("%w: expected OCTET STRING, got class %d tag %d", ErrUnexpectedValueType, raw.Class, raw.Tag)}
	}
	return append([]byte(nil), raw.Bytes...), nil
}

// singleValue returns the sole value of the sole attribute with the given
// OID, or nil if no such attribute is present.
func (attrs Attributes) singleValue(oid asn1.ObjectIdentifier) (*AttributeValue, error) {
	found := -1
	for i := range attrs {
		if attrs[i].OID.Equal(oid) {
			if found >= 0 {
				return nil, &AttributeError{OID: oid, Err: ErrDuplicateAttribute}
			}
			found = i
		}
	}
	if found < 0 {
		return nil, nil
	}
	switch len(attrs[found].Values) {
	case 0:
		return nil, &AttributeError{OID: oid, Err: ErrNoAttributeValues}
	case 1:
		return &attrs[found].Values[0], nil
	default:
		return nil, &AttributeError{OID: oid, Err: ErrMultipleAttributeValues}
	}
}

func (value *AttributeValue) decode() (asn1.RawValue, error) {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(value.DER, &raw)
	if err != nil {
		return raw, fmt.Errorf("pkcs12: error decoding attribute value: %w", err)
	}
	if len(rest) != 0 {
		return raw, errors.New("pkcs12: trailing data in attribute value")
	}
	return raw, nil
}

func derWrap(tag byte, content []byte) []byte {
	out := append([]byte{tag}, appendDERLength(nil, len(content))...)
	return append(out, content...)
}

func appendDERLength(dst []byte, n int) []byte {
	if n < 128 {
		return append(dst, byte(n))
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte(n)
		n >>= 8
	}
	dst = append(dst, byte(0x80|(len(buf)-i)))
	return append(dst, buf[i:]...)
}
