package audit

import (
	"bytes"
	"fmt"
	"github.com/snechholt/bufrw"
	"io"
	"time"
)

type Signature struct {
	auditor   Auditor
	timestamp time.Time
}

func NewSignature(auditor Auditor, timestamp time.Time) Signature {
	return Signature{auditor: auditor, timestamp: timestamp}
}

func (sig Signature) Auditor() Auditor {
	return sig.auditor
}

func (sig Signature) Timestamp() time.Time {
	return sig.timestamp
}

func (sig Signature) IsZero() bool {
	return sig == Signature{}
}

func (sig Signature) Equal(other Signature) bool {
	return sig.auditor.Equal(other.auditor) && sig.timestamp.Equal(other.timestamp)
}

// func (sig Signature) Encode() string {
// 	return fmt.Sprintf("%s@%s", sig.auditor, sig.timestamp.Format("2006-01-02T15_04_05.999999999Z07:00"))
// }
//
// func (sig *Signature) Decode(src string) error {
// 	panic("Not implemented")
// }

func (sig Signature) Serialize() ([]byte, error) {
	var b bytes.Buffer
	var buf bufrw.Buffer
	if err := sig.SerializeToBufRW(&b, &buf); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (sig Signature) SerializeToBufRW(w io.Writer, buf *bufrw.Buffer) error {
	if loc, offset := sig.timestamp.Zone(); offset != 0 {
		return fmt.Errorf("invalid signature timestamp: must be in zone with offset = 0, was %s (%d)", loc, offset)
	}

	// Write version number
	if err := buf.WriteInt(w, 1); err != nil {
		return err
	}

	// Write auditor
	if err := buf.WriteString(w, sig.auditor.Encode()); err != nil {
		return err
	}

	// Write timestamp

	// Serialization of Signature encodes the timestamp using UnixNano(), which as some
	// limitations in the range of possible values. The min and max values are described
	// below.
	var (
		// While UnixNano() supports dates before the unix epoch, there is no practical
		// need for this. We cap it at 1 nanosecond after epoch. This leaves 0 = zero time
		minAllowed = time.Date(1970, 1, 1, 0, 0, 0, 1, time.UTC)
		// UnixNano() supports dates up to year 2262, but let's cap it at 2200. If this
		// becomes a problem, then good job at keeping this system running for 200 years.
		maxAllowed = time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC)
	)
	t := sig.timestamp
	if !t.IsZero() && (t.Before(minAllowed) || t.After(maxAllowed)) {
		return fmt.Errorf("signature timestamp %s is out of bounds", sig.timestamp)
	}
	var unixNano int64
	if !t.IsZero() {
		unixNano = t.UnixNano()
	}

	return buf.WriteInt64(w, unixNano)
}

func (sig *Signature) Deserialize(b []byte) error {
	var buf bufrw.Buffer
	return sig.DeserializeFromBufRW(bytes.NewReader(b), &buf)
}

func (sig *Signature) DeserializeFromBufRW(r io.Reader, buf *bufrw.Buffer) error {
	version, err := buf.ReadInt(r)
	if err != nil {
		return err
	}
	if version != 1 {
		return fmt.Errorf("unsupported version number: %d", version)
	}

	auditorString, err := buf.ReadString(r)
	if err != nil {
		return err
	}
	var auditor Auditor
	if err := auditor.Decode(auditorString); err != nil {
		return err
	}

	var timestamp time.Time
	unixNano, err := buf.ReadInt64(r)
	if err != nil {
		return err
	}
	if unixNano < 0 {
		return fmt.Errorf("invalid unix nano value found: %d", unixNano)
	}
	if unixNano > 0 {
		timestamp = time.Unix(0, unixNano).In(time.UTC) // .In(time.UTC) is because of local timezone screwing up tests
	}

	sig.auditor = auditor
	sig.timestamp = timestamp

	return nil
}

func (sig Signature) String() string {
	if sig.timestamp.Nanosecond() > 0 {
		return fmt.Sprintf("%s@%s", sig.auditor, sig.timestamp.Format(time.RFC3339Nano))
	}
	return fmt.Sprintf("%s@%s", sig.auditor, sig.timestamp.Format(time.RFC3339))
}

type SignatureSlice []Signature

func (s SignatureSlice) Reversed() SignatureSlice {
	if s == nil {
		return nil
	}
	n := len(s)
	reversed := make(SignatureSlice, n)
	for i := range s {
		reversed[i] = s[n-1-i]
	}
	return reversed
}

func (s SignatureSlice) Timestamps() []time.Time {
	timestamps := make([]time.Time, len(s))
	for i, sig := range s {
		timestamps[i] = sig.timestamp
	}
	return timestamps
}
