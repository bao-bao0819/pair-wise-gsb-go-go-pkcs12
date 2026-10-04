package pkcs12

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// goldenAttributesDER is a hand-crafted DER SET OF Attribute containing,
// in wire (DER-sorted) order:
//
//	SEQUENCE { OID 1.2.3.4,                    SET { [0] AA BB } }      (unknown OID, unknown tag)
//	SEQUENCE { OID friendlyName,               SET { BMPString "密钥" } } (non-ASCII name)
//	SEQUENCE { OID localKeyId,                 SET { OCTET STRING 01 02 03 04 } }
const goldenAttributesDER = "3137" +
	"300b06032a030431048002aabb" +
	"301306092a864886f70d01091431061e045bc694a5" +
	"301306092a864886f70d0109153106040401020304"

var oidUnknownTest = asn1.ObjectIdentifier([]int{1, 2, 3, 4})

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	der, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad test hex: %v", err)
	}
	return der
}

func mustBMP(t *testing.T, s string) []byte {
	t.Helper()
	b, err := bmpString(s)
	if err != nil {
		t.Fatalf("bmpString(%q): %v", s, err)
	}
	return b
}

func TestParseAttributesGolden(t *testing.T) {
	der := mustDecodeHex(t, goldenAttributesDER)
	attrs, err := ParseAttributes(der)
	if err != nil {
		t.Fatalf("ParseAttributes: %v", err)
	}
	if len(attrs) != 3 {
		t.Fatalf("expected 3 attributes, got %d", len(attrs))
	}

	// Wire order and duplicates are preserved, unknown OIDs are kept raw.
	if !attrs[0].OID.Equal(oidUnknownTest) {
		t.Errorf("attrs[0].OID = %v, want %v", attrs[0].OID, oidUnknownTest)
	}
	if !attrs[1].OID.Equal(oidFriendlyName) {
		t.Errorf("attrs[1].OID = %v, want %v", attrs[1].OID, oidFriendlyName)
	}
	if !attrs[2].OID.Equal(oidLocalKeyID) {
		t.Errorf("attrs[2].OID = %v, want %v", attrs[2].OID, oidLocalKeyID)
	}

	unknown := attrs[0].Values[0]
	if unknown.Class != 2 || unknown.Tag != 0 {
		t.Errorf("unknown value class/tag = %d/%d, want 2/0", unknown.Class, unknown.Tag)
	}
	if got := hex.EncodeToString(unknown.DER); got != "8002aabb" {
		t.Errorf("unknown value DER = %s, want 8002aabb", got)
	}

	name, err := attrs.FriendlyName()
	if err != nil {
		t.Fatalf("FriendlyName: %v", err)
	}
	if name != "密钥" {
		t.Errorf("FriendlyName = %q, want %q", name, "密钥")
	}

	id, err := attrs.LocalKeyID()
	if err != nil {
		t.Fatalf("LocalKeyID: %v", err)
	}
	if !bytes.Equal(id, []byte{1, 2, 3, 4}) {
		t.Errorf("LocalKeyID = %x, want 01020304", id)
	}

	// Lossless round-trip.
	encoded, err := attrs.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(encoded, der) {
		t.Errorf("round-trip mismatch:\n got %x\nwant %x", encoded, der)
	}
}

func TestAttributesMutationIsolation(t *testing.T) {
	der := mustDecodeHex(t, goldenAttributesDER)
	attrs, err := ParseAttributes(der)
	if err != nil {
		t.Fatalf("ParseAttributes: %v", err)
	}

	// Mutating the caller's input buffer must not affect parsed attributes.
	saved := append([]byte(nil), der...)
	for i := range der {
		der[i] ^= 0xff
	}
	encoded, err := attrs.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(encoded, saved) {
		t.Errorf("Encode after input mutation = %x, want %x", encoded, saved)
	}

	// Mutating returned slices must not affect subsequent decodes.
	attrs[0].Values[0].DER[0] ^= 0xff
	attrs[1].OID[0] = 99
	attrs[2].Values[0].DER[3] ^= 0xff
	fresh, err := ParseAttributes(saved)
	if err != nil {
		t.Fatalf("re-ParseAttributes: %v", err)
	}
	if name, err := fresh.FriendlyName(); err != nil || name != "密钥" {
		t.Errorf("FriendlyName after mutation = %q, %v", name, err)
	}
	if got := hex.EncodeToString(fresh[0].Values[0].DER); got != "8002aabb" {
		t.Errorf("unknown DER after mutation = %s, want 8002aabb", got)
	}

	// LocalKeyID returns a copy.
	id, err := fresh.LocalKeyID()
	if err != nil {
		t.Fatalf("LocalKeyID: %v", err)
	}
	id[0] = 0xff
	id2, err := fresh.LocalKeyID()
	if err != nil {
		t.Fatalf("LocalKeyID: %v", err)
	}
	if id2[0] != 0x01 {
		t.Errorf("LocalKeyID affected by caller mutation: %x", id2)
	}
}

func mustRoundTrip(t *testing.T, attrs Attributes) Attributes {
	t.Helper()
	der, err := attrs.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	parsed, err := ParseAttributes(der)
	if err != nil {
		t.Fatalf("ParseAttributes: %v", err)
	}
	again, err := parsed.Encode()
	if err != nil {
		t.Fatalf("re-Encode: %v", err)
	}
	if !bytes.Equal(again, der) {
		t.Fatalf("round-trip mismatch:\n got %x\nwant %x", again, der)
	}
	return parsed
}

func TestAttributesDuplicateOID(t *testing.T) {
	attrs := Attributes{
		{OID: oidFriendlyName, Values: []AttributeValue{NewAttributeValue(asn1.TagBMPString, mustBMP(t, "first"))}},
		{OID: oidFriendlyName, Values: []AttributeValue{NewAttributeValue(asn1.TagBMPString, mustBMP(t, "second"))}},
	}
	parsed := mustRoundTrip(t, attrs)
	if len(parsed) != 2 {
		t.Fatalf("duplicates not preserved: got %d attributes", len(parsed))
	}

	_, err := parsed.FriendlyName()
	if !errors.Is(err, ErrDuplicateAttribute) {
		t.Errorf("FriendlyName error = %v, want ErrDuplicateAttribute", err)
	}
	var attrErr *AttributeError
	if !errors.As(err, &attrErr) || !attrErr.OID.Equal(oidFriendlyName) {
		t.Errorf("FriendlyName error = %v, want AttributeError for %v", err, oidFriendlyName)
	}

	// The raw values are still readable even though the accessor failed.
	for i, want := range []string{"first", "second"} {
		raw, err := parsed[i].Values[0].decode()
		if err != nil {
			t.Fatalf("decode value %d: %v", i, err)
		}
		got, err := decodeBMPString(raw.Bytes)
		if err != nil {
			t.Fatalf("decodeBMPString value %d: %v", i, err)
		}
		if got != want {
			t.Errorf("value %d = %q, want %q", i, got, want)
		}
	}
}

func TestAttributesEmptyValueSet(t *testing.T) {
	attrs := Attributes{
		{OID: oidFriendlyName},
		{OID: oidLocalKeyID, Values: []AttributeValue{NewAttributeValue(asn1.TagOctetString, []byte{0x42})}},
	}
	parsed := mustRoundTrip(t, attrs)
	if len(parsed) != 2 || len(parsed[0].Values) != 0 {
		t.Fatalf("empty value set not preserved: %+v", parsed)
	}
	if _, err := parsed.FriendlyName(); !errors.Is(err, ErrNoAttributeValues) {
		t.Errorf("FriendlyName error = %v, want ErrNoAttributeValues", err)
	}
	if id, err := parsed.LocalKeyID(); err != nil || !bytes.Equal(id, []byte{0x42}) {
		t.Errorf("LocalKeyID = %x, %v", id, err)
	}
}

func TestAttributesMultipleValues(t *testing.T) {
	attrs := Attributes{
		{OID: oidLocalKeyID, Values: []AttributeValue{
			NewAttributeValue(asn1.TagOctetString, []byte{1}),
			NewAttributeValue(asn1.TagOctetString, []byte{2}),
		}},
	}
	parsed := mustRoundTrip(t, attrs)
	if len(parsed) != 1 || len(parsed[0].Values) != 2 {
		t.Fatalf("multiple values not preserved: %+v", parsed)
	}
	if _, err := parsed.LocalKeyID(); !errors.Is(err, ErrMultipleAttributeValues) {
		t.Errorf("LocalKeyID error = %v, want ErrMultipleAttributeValues", err)
	}
}

func TestAttributesBadValueType(t *testing.T) {
	attrs := Attributes{
		{OID: oidFriendlyName, Values: []AttributeValue{NewAttributeValue(asn1.TagUTF8String, []byte("hi"))}},
	}
	parsed := mustRoundTrip(t, attrs)
	_, err := parsed.FriendlyName()
	if !errors.Is(err, ErrUnexpectedValueType) {
		t.Errorf("FriendlyName error = %v, want ErrUnexpectedValueType", err)
	}
	// Raw value is still readable.
	if parsed[0].Values[0].Tag != asn1.TagUTF8String {
		t.Errorf("raw tag = %d, want %d", parsed[0].Values[0].Tag, asn1.TagUTF8String)
	}
}

func TestAttributesBadStringEncoding(t *testing.T) {
	attrs := Attributes{
		{OID: oidFriendlyName, Values: []AttributeValue{NewAttributeValue(asn1.TagBMPString, []byte{0x00})}},
	}
	parsed := mustRoundTrip(t, attrs)
	_, err := parsed.FriendlyName()
	if err == nil || !strings.Contains(err.Error(), "odd-length") {
		t.Errorf("FriendlyName error = %v, want odd-length BMP string error", err)
	}
	var attrErr *AttributeError
	if !errors.As(err, &attrErr) || !attrErr.OID.Equal(oidFriendlyName) {
		t.Errorf("FriendlyName error = %v, want AttributeError for %v", err, oidFriendlyName)
	}
}

func TestAttributesAbsent(t *testing.T) {
	var attrs Attributes
	if name, err := attrs.FriendlyName(); err != nil || name != "" {
		t.Errorf("FriendlyName = %q, %v, want \"\", nil", name, err)
	}
	if id, err := attrs.LocalKeyID(); err != nil || id != nil {
		t.Errorf("LocalKeyID = %x, %v, want nil, nil", id, err)
	}

	// An empty SET round-trips.
	parsed, err := ParseAttributes(mustDecodeHex(t, "3100"))
	if err != nil {
		t.Fatalf("ParseAttributes: %v", err)
	}
	if len(parsed) != 0 {
		t.Fatalf("expected 0 attributes, got %d", len(parsed))
	}
	encoded, err := parsed.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if hex.EncodeToString(encoded) != "3100" {
		t.Errorf("empty SET round-trip = %x, want 3100", encoded)
	}
}

func TestAttributesReencodePreservesUnknown(t *testing.T) {
	der := mustDecodeHex(t, goldenAttributesDER)
	attrs, err := ParseAttributes(der)
	if err != nil {
		t.Fatalf("ParseAttributes: %v", err)
	}

	// Replace the supported friendlyName attribute; leave the unknown
	// attribute untouched.
	for i := range attrs {
		if attrs[i].OID.Equal(oidFriendlyName) {
			attrs[i].Values = []AttributeValue{NewAttributeValue(asn1.TagBMPString, mustBMP(t, "新"))}
		}
	}
	encoded, err := attrs.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// The unknown attribute's DER survives verbatim.
	if !bytes.Contains(encoded, mustDecodeHex(t, "300b06032a030431048002aabb")) {
		t.Errorf("unknown attribute DER not preserved in %x", encoded)
	}

	reparsed, err := ParseAttributes(encoded)
	if err != nil {
		t.Fatalf("re-ParseAttributes: %v", err)
	}
	if name, err := reparsed.FriendlyName(); err != nil || name != "新" {
		t.Errorf("FriendlyName = %q, %v, want 新", name, err)
	}
	if id, err := reparsed.LocalKeyID(); err != nil || !bytes.Equal(id, []byte{1, 2, 3, 4}) {
		t.Errorf("LocalKeyID = %x, %v", id, err)
	}
	if got := hex.EncodeToString(reparsed[0].Values[0].DER); got != "8002aabb" {
		t.Errorf("unknown value DER = %s, want 8002aabb", got)
	}
}

func TestParseAttributesErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		der  string
	}{
		{"not a set", "3000"},
		{"trailing data", "310000"},
		{"attribute not a sequence", "31020400"},
		{"truncated", "31373013"},
	} {
		if _, err := ParseAttributes(mustDecodeHex(t, tc.der)); err == nil {
			t.Errorf("%s: expected error", tc.name)
		}
	}
}
