// Copyright 2026 Opsmate, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex in test fixture: %v", err)
	}
	return b
}

// testAttributesDER is a hand-crafted SET OF Attribute containing, in order:
//
//   - friendlyName "café 密钥" (non-ASCII BMPString)
//   - localKeyId 01020304
//   - unknown OID 1.2.3.4 with an empty value SET
//   - unknown OID 1.2.3.4 again (duplicate OID) with an INTEGER value
//   - unknown OID 1.2.3.5 with a context-specific [3] primitive value
//
// Note that the attributes are deliberately not sorted, to prove that the
// original order is preserved.
var testAttributesDER = "3156" +
	"301D06092A864886F70D01091431101E0E00630061006600E900205BC694A5" +
	"301306092A864886F70D0109153106040401020304" +
	"300706032A03043100" +
	"300A06032A03043103020105" +
	"300B06032A030531048302AABB"

func TestAttributesRoundTrip(t *testing.T) {
	der := mustHex(t, testAttributesDER)
	attrs, err := ParseAttributes(der)
	if err != nil {
		t.Fatalf("ParseAttributes: %v", err)
	}

	if len(attrs) != 5 {
		t.Fatalf("expected 5 attributes, got %d", len(attrs))
	}

	wantOIDs := []asn1.ObjectIdentifier{
		oidFriendlyName,
		oidLocalKeyID,
		{1, 2, 3, 4},
		{1, 2, 3, 4},
		{1, 2, 3, 5},
	}
	for i, want := range wantOIDs {
		if !attrs[i].OID.Equal(want) {
			t.Errorf("attribute %d: expected OID %v, got %v", i, want, attrs[i].OID)
		}
	}

	// The empty value SET is preserved as an attribute with zero values.
	if len(attrs[2].Values) != 0 {
		t.Errorf("expected empty value SET, got %d values", len(attrs[2].Values))
	}

	// The unknown context-specific tag is preserved with its raw DER.
	unknown := attrs[4].Values[0]
	if unknown.Class != 2 || unknown.Tag != 3 || unknown.IsCompound {
		t.Errorf("unexpected type for unknown value: %v", describeType(unknown.RawValue))
	}
	if !bytes.Equal(unknown.Bytes, []byte{0xAA, 0xBB}) {
		t.Errorf("unexpected content for unknown value: %x", unknown.Bytes)
	}
	if !bytes.Equal(unknown.FullBytes, []byte{0x83, 0x02, 0xAA, 0xBB}) {
		t.Errorf("raw DER not preserved for unknown value: %x", unknown.FullBytes)
	}

	encoded, err := attrs.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(encoded, der) {
		t.Errorf("round-trip mismatch:\n got %x\nwant %x", encoded, der)
	}
}

func TestAttributesFriendlyName(t *testing.T) {
	attrs, err := ParseAttributes(mustHex(t, testAttributesDER))
	if err != nil {
		t.Fatalf("ParseAttributes: %v", err)
	}
	name, present, err := attrs.FriendlyName()
	if err != nil {
		t.Fatalf("FriendlyName: %v", err)
	}
	if !present {
		t.Fatal("friendlyName not present")
	}
	if name != "café 密钥" {
		t.Errorf("expected %q, got %q", "café 密钥", name)
	}
}

func TestAttributesLocalKeyID(t *testing.T) {
	der := mustHex(t, testAttributesDER)
	attrs, err := ParseAttributes(der)
	if err != nil {
		t.Fatalf("ParseAttributes: %v", err)
	}
	id, present, err := attrs.LocalKeyID()
	if err != nil {
		t.Fatalf("LocalKeyID: %v", err)
	}
	if !present {
		t.Fatal("localKeyId not present")
	}
	if !bytes.Equal(id, []byte{1, 2, 3, 4}) {
		t.Errorf("expected 01020304, got %x", id)
	}

	// Mutating the returned slice must not affect the attributes.
	id[0] = 0xFF
	encoded, err := attrs.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(encoded, der) {
		t.Errorf("mutating LocalKeyID result changed the attributes:\n got %x\nwant %x", encoded, der)
	}
}

func TestAttributesAbsent(t *testing.T) {
	var attrs Attributes
	if _, present, err := attrs.FriendlyName(); present || err != nil {
		t.Errorf("FriendlyName on empty attributes: present=%v err=%v", present, err)
	}
	if _, present, err := attrs.LocalKeyID(); present || err != nil {
		t.Errorf("LocalKeyID on empty attributes: present=%v err=%v", present, err)
	}
}

func bmpStringValue(t *testing.T, s string) AttributeValue {
	t.Helper()
	encoded, err := bmpString(s)
	if err != nil {
		t.Fatalf("bmpString: %v", err)
	}
	return AttributeValue{asn1.RawValue{Class: 0, Tag: 30, Bytes: encoded}}
}

func mustReparse(t *testing.T, attrs Attributes) Attributes {
	t.Helper()
	der, err := attrs.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	parsed, err := ParseAttributes(der)
	if err != nil {
		t.Fatalf("ParseAttributes: %v", err)
	}
	return parsed
}

func TestFriendlyNameErrors(t *testing.T) {
	good := bmpStringValue(t, "good")

	tests := []struct {
		name    string
		attrs   Attributes
		wantErr error // sentinel to check with errors.Is; nil means any non-nil error
	}{
		{
			name: "duplicate OID",
			attrs: Attributes{
				{OID: oidFriendlyName, Values: []AttributeValue{bmpStringValue(t, "first")}},
				{OID: oidFriendlyName, Values: []AttributeValue{bmpStringValue(t, "second")}},
			},
			wantErr: ErrDuplicateAttribute,
		},
		{
			name:    "multiple values",
			attrs:   Attributes{{OID: oidFriendlyName, Values: []AttributeValue{good, bmpStringValue(t, "other")}}},
			wantErr: ErrMultipleAttributeValues,
		},
		{
			name:    "empty value set",
			attrs:   Attributes{{OID: oidFriendlyName}},
			wantErr: ErrNoAttributeValues,
		},
		{
			name:    "not a BMPString",
			attrs:   Attributes{{OID: oidFriendlyName, Values: []AttributeValue{{asn1.RawValue{Class: 0, Tag: 12, Bytes: []byte("utf8")}}}}},
			wantErr: nil,
		},
		{
			name:    "invalid BMPString",
			attrs:   Attributes{{OID: oidFriendlyName, Values: []AttributeValue{{asn1.RawValue{Class: 0, Tag: 30, Bytes: []byte{0x00, 0x61, 0x00}}}}}},
			wantErr: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			attrs := mustReparse(t, test.attrs)
			_, _, err := attrs.FriendlyName()
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if test.wantErr != nil && !errors.Is(err, test.wantErr) {
				t.Errorf("expected error wrapping %v, got %v", test.wantErr, err)
			}

			// The raw attributes are still readable after the
			// convenience accessor fails.
			if len(attrs) == 0 {
				t.Fatal("raw attributes not available after accessor failure")
			}
			if !attrs[0].OID.Equal(oidFriendlyName) {
				t.Errorf("unexpected raw attribute OID %v", attrs[0].OID)
			}
			if len(attrs[0].Values) > 0 && attrs[0].Values[0].Tag != 30 && attrs[0].Values[0].Tag != 12 {
				t.Errorf("unexpected raw value tag %d", attrs[0].Values[0].Tag)
			}
		})
	}
}

func TestLocalKeyIDErrors(t *testing.T) {
	octets := AttributeValue{asn1.RawValue{Class: 0, Tag: 4, Bytes: []byte{1, 2, 3, 4}}}

	tests := []struct {
		name    string
		attrs   Attributes
		wantErr error
	}{
		{
			name: "duplicate OID",
			attrs: Attributes{
				{OID: oidLocalKeyID, Values: []AttributeValue{octets}},
				{OID: oidLocalKeyID, Values: []AttributeValue{octets}},
			},
			wantErr: ErrDuplicateAttribute,
		},
		{
			name:    "multiple values",
			attrs:   Attributes{{OID: oidLocalKeyID, Values: []AttributeValue{octets, octets}}},
			wantErr: ErrMultipleAttributeValues,
		},
		{
			name:    "empty value set",
			attrs:   Attributes{{OID: oidLocalKeyID}},
			wantErr: ErrNoAttributeValues,
		},
		{
			name:    "not an OCTET STRING",
			attrs:   Attributes{{OID: oidLocalKeyID, Values: []AttributeValue{bmpStringValue(t, "not-octets")}}},
			wantErr: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			attrs := mustReparse(t, test.attrs)
			_, _, err := attrs.LocalKeyID()
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if test.wantErr != nil && !errors.Is(err, test.wantErr) {
				t.Errorf("expected error wrapping %v, got %v", test.wantErr, err)
			}
			if len(attrs) == 0 {
				t.Fatal("raw attributes not available after accessor failure")
			}
		})
	}
}

func TestParseAttributesInputIsolation(t *testing.T) {
	der := mustHex(t, testAttributesDER)
	original := append([]byte(nil), der...)

	attrs, err := ParseAttributes(der)
	if err != nil {
		t.Fatalf("ParseAttributes: %v", err)
	}

	// Corrupting the caller's input buffer must not affect the parsed
	// attributes.
	for i := range der {
		der[i] = 0
	}
	encoded, err := attrs.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(encoded, original) {
		t.Errorf("attributes changed after input buffer was mutated:\n got %x\nwant %x", encoded, original)
	}

	// Mutating the returned slices must not affect subsequent decodes of
	// the same input.
	attrs[0].Values[0].FullBytes[0] = 0xFF
	attrs[0].Values[0].Bytes[0] = 0xFF
	reparsed, err := ParseAttributes(original)
	if err != nil {
		t.Fatalf("ParseAttributes: %v", err)
	}
	reencoded, err := reparsed.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(reencoded, original) {
		t.Errorf("mutating returned slices affected a subsequent decode:\n got %x\nwant %x", reencoded, original)
	}
}

func TestAttributesModifyKeepsUnknown(t *testing.T) {
	der := mustHex(t, testAttributesDER)
	attrs, err := ParseAttributes(der)
	if err != nil {
		t.Fatalf("ParseAttributes: %v", err)
	}

	// Replace the friendlyName with a new supported attribute, leaving the
	// unknown attributes untouched.
	replacement, err := NewFriendlyNameAttribute("renamed")
	if err != nil {
		t.Fatalf("NewFriendlyNameAttribute: %v", err)
	}
	attrs[0] = replacement

	encoded, err := attrs.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	reparsed, err := ParseAttributes(encoded)
	if err != nil {
		t.Fatalf("ParseAttributes: %v", err)
	}
	name, present, err := reparsed.FriendlyName()
	if err != nil {
		t.Fatalf("FriendlyName: %v", err)
	}
	if !present || name != "renamed" {
		t.Errorf("expected friendlyName %q, got %q (present=%v)", "renamed", name, present)
	}

	// The unknown attributes must be byte-for-byte identical to the
	// original encoding.
	original, err := ParseAttributes(der)
	if err != nil {
		t.Fatalf("ParseAttributes: %v", err)
	}
	for _, i := range []int{2, 3, 4} {
		gotDER, err := Attributes{reparsed[i]}.Encode()
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		wantDER, err := Attributes{original[i]}.Encode()
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		if !bytes.Equal(gotDER, wantDER) {
			t.Errorf("unknown attribute %d changed:\n got %x\nwant %x", i, gotDER, wantDER)
		}
	}
}

func TestParseAttributesRejectsInvalid(t *testing.T) {
	tests := []struct {
		name string
		der  string
	}{
		{"trailing data", "31003100"},
		{"not a SET", "3000"},
		{"attribute not a SEQUENCE", "31020402"},
		{"missing values SET", "310506032A0304"},
		{"values not a SET", "310906032A030402020000"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseAttributes(mustHex(t, test.der)); err == nil {
				t.Error("expected an error, got nil")
			}
		})
	}
}
