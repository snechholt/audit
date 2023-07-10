package audit

import (
	"testing"
)

func TestAuditorEqual(t *testing.T) {
	tests := []Auditor{
		{},
		NewAuditor("kind1", ""),
		NewAuditor("", "id1"),
		NewAuditor("kind1", "id1"),
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

func TestAuditorEncodeDecode(t *testing.T) {
	tests := []Auditor{
		{},
		NewAuditor("kind1", ""),
		NewAuditor("", "id1"),
		NewAuditor("kind1", "id1"),
	}
	for _, auditor := range tests {
		encoded := auditor.Encode()
		var got Auditor
		if err := got.Decode(encoded); err != nil {
			t.Fatalf("Decode() error on zero value: %v", err)
		}
		if !got.Equal(auditor) {
			t.Errorf("Decode(%s) = %v, want %v", encoded, got, auditor)
		}
	}
}