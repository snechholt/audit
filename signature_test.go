package audit

import (
	"fmt"
	"testing"
	"time"
)

func TestSignatureEqual(t *testing.T) {
	var (
		t0 = time.Time{}
		t1 = time.Date(2010, 1, 1, 12, 0, 0, 0, time.UTC)
		t2 = time.Now()
		auditor = NewAuditor("kind", "id")
	)
	tests := []Signature{
		{},
		NewSignature(auditor, t0),
		NewSignature(auditor, t1),
		NewSignature(auditor, t2),
	}
	for i, a1 := range tests {
		for j, a2 := range tests {
			want := i == j
			if got := a1.Equal(a2); want != got {
				t.Errorf("%s.Equal(%s) == %v, want %v", a1, a2, got, want)
			}
			if got := a2.Equal(a1); want != got {
				t.Errorf("%s.Equal(%s) == %v, want %v", a1, a2, got, want)
			}
		}
	}
}

// func TestSignatureEncodeDecode(t *testing.T) {
// 	var (
// 		t0 = time.Time{}
// 		t1 = time.Date(2010, 1, 1, 12, 0, 0, 0, time.UTC)
// 		t2 = time.Date(2010, 1, 1, 12, 13, 14, 15, time.UTC)
// 		auditor = NewAuditor("kind", "id")
// 	)
// 	tests := []Signature{
// 		// Test zero values
// 		{},
// 		NewSignature(auditor, t0),
// 		NewSignature(Auditor{}, t1),
// 		// Test different auditor kind+id combinations
// 		NewSignature(NewAuditor("kind1", ""), t1),
// 		NewSignature(NewAuditor("", "id1"), t1),
// 		NewSignature(NewAuditor("kind1", "id1"), t1),
// 		// Test nanosecond precision
// 		NewSignature(auditor, t2),
// 	}
// 	for _, auditor := range tests {
// 		encoded := auditor.Encode()
// 		var got Signature
// 		if err := got.Decode(encoded); err != nil {
// 			t.Fatalf("Decode() error on zero value: %v", err)
// 		}
// 		if !got.Equal(auditor) {
// 			t.Errorf("Decode(%s) = %v, want %v", encoded, got, auditor)
// 		}
// 	}
// }

func TestSignatureSerialization(t *testing.T) {
	auditors := []Auditor{
		{},
		NewAuditor("kind", ""),
		NewAuditor("", "id"),
		NewAuditor("kind", "id"),
	}
	timestamps := []time.Time{
		{},
		time.Date(2010, 1, 1, 12, 0, 0, 0, time.UTC),
		time.Date(2010, 1, 2, 3, 4, 5, 123456789, time.UTC),
		// Edge boundaries
		time.Date(1970, 1, 1, 0, 0, 0, 1, time.UTC),
		time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	for _, auditor := range auditors {
		for _, timestamp := range timestamps {
			sig := NewSignature(auditor, timestamp)
			b, err := sig.Serialize()
			if err != nil {
				t.Fatalf("%s.Serialize() error: %v", sig, err)
			}
			var got Signature
			if err := got.Deserialize(b); err != nil{
				t.Fatalf("Deserialize(%s.Serialize()) error: %v", sig, err)
			}
			if !got.Equal(sig) {
				t.Errorf("%s -> %s", sig, got)
			}
		}
	}

	invalidTimestamps := []time.Time{
		time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2200, 1, 1, 0, 0, 0, 1, time.UTC),
	}
	for _, timestamp := range invalidTimestamps {
		sig := NewSignature(Auditor{}, timestamp)
		_, err := sig.Serialize()
		want := fmt.Errorf("signature timestamp %s is out of bounds", timestamp)
		if !gotError(want, err) {
			t.Errorf("Wrong error returned when serializing out-of-bounds timestamp: %v", err)
		}
	}
}

func gotError(want, got error) bool {
	if want == nil {
		return got == nil
	}
	return got != nil && got.Error() == want.Error()
}