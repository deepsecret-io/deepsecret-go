// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package canon

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// strictDoc is a small message: one map, one array.
type strictDoc struct {
	Name  string   `cbor:"name"`
	Items []string `cbor:"items"`
}

// text is the CBOR text string s, which must be shorter than 24 bytes.
func text(s string) []byte {
	return append([]byte{0x60 | byte(len(s))}, s...)
}

// join is the CBOR items in parts, end to end.
func join(parts ...[]byte) []byte {
	return bytes.Join(parts, nil)
}

func errorAs[T error](err error) bool {
	var target T
	return errors.As(err, &target)
}

// The strict decoder reads what Marshal writes and refuses what it never
// writes: bytes that say the same thing another way, or that another parser
// could read differently.
func TestStrictDecMode(t *testing.T) {
	const maxArrayElements, maxMapPairs = 16, 16
	dm, err := StrictDecMode(maxArrayElements, maxMapPairs)
	if err != nil {
		t.Fatal(err)
	}

	want := strictDoc{Name: "a", Items: []string{"b"}}
	canonical, err := Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	name, items := join(text("name"), text("a")), join(text("items"), []byte{0x81}, text("b"))
	if !bytes.Equal(canonical, join([]byte{0xa2}, name, items)) {
		t.Fatalf("canonical bytes are %x", canonical)
	}
	var got strictDoc
	if err := dm.Unmarshal(canonical, &got); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("canonical bytes: %+v, %v", got, err)
	}

	seventeen := []byte{0x91} // an array of 17 text strings
	for range 17 {
		seventeen = append(seventeen, text("b")...)
	}
	cases := map[string]struct {
		data    []byte
		refused func(error) bool
	}{
		"the same key twice":             {join([]byte{0xa3}, name, items, text("name"), text("z")), errorAs[*cbor.DupMapKeyError]},
		"the same key twice, same value": {join([]byte{0xa3}, name, items, name), errorAs[*cbor.DupMapKeyError]},
		"a key with no field":            {join([]byte{0xa3}, name, items, text("extra"), []byte{0x01}), errorAs[*cbor.UnknownFieldError]},
		"a key in another case":          {join([]byte{0xa2}, text("Name"), text("a"), items), errorAs[*cbor.UnknownFieldError]},
		"a map of indefinite length":     {join([]byte{0xbf}, name, items, []byte{0xff}), errorAs[*cbor.IndefiniteLengthError]},
		"an array of indefinite length":  {join([]byte{0xa2}, name, text("items"), []byte{0x9f}, text("b"), []byte{0xff}), errorAs[*cbor.IndefiniteLengthError]},
		"a text of indefinite length":    {join([]byte{0xa2}, text("name"), []byte{0x7f}, text("a"), []byte{0xff}, items), errorAs[*cbor.IndefiniteLengthError]},
		"an array over the bound":        {join([]byte{0xa2}, name, text("items"), seventeen), errorAs[*cbor.MaxArrayElementsError]},
		"a map over the bound":           {[]byte{0xb1}, errorAs[*cbor.MaxMapPairsError]},
		"five levels deep":               {join([]byte{0xa2}, name, text("items"), []byte{0x81, 0x81, 0x81, 0x81}, text("b")), errorAs[*cbor.MaxNestedLevelError]},
		"data after the message":         {join(canonical, []byte{0x00}), errorAs[*cbor.ExtraneousDataError]},
	}
	for name, c := range cases {
		var got strictDoc
		if err := dm.Unmarshal(c.data, &got); err == nil || !c.refused(err) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}
