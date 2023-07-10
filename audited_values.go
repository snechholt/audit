package audit

import (
	"bytes"
	"fmt"
	"github.com/snechholt/bufrw"
	"strings"
	"time"
)

// ErrDidNotExist is the error returned when rolling back an object to before its creation time.
var ErrDidNotExist = fmt.Errorf("the object did not exist at the given time")

type magicValue int8

const (
	magicValueHistoryCreation magicValue = 0
	magicValueFieldRemoved    magicValue = 1
)

func (v magicValue) String() string {
	switch v {
	case magicValueHistoryCreation:
		return "<created>"
	case magicValueFieldRemoved:
		return "<field removed>"
	default:
		return fmt.Sprintf("<invalid magic value (%d)>", v)
	}
}

type auditHistory struct {
	fields    fieldSlice
	signature Signature
}

type AuditableValues struct {
	history []auditHistory
}

func (values *AuditableValues) addHistory(sig Signature, fields ...Field) {
	values.history = append(values.history, auditHistory{
		fields:    fields,
		signature: sig,
	})
}

// IsZero returns whether or not the values object represents the zero
// audit history, and empty history.
func (values *AuditableValues) IsZero() bool {
	return len(values.history) == 0
}

// CreationSignature returns the first signature of the audit history, the
// entry that signifies the creation of the history.
func (values *AuditableValues) CreationSignature() Signature {
	if values.IsZero() {
		return Signature{}
	}
	return values.history[0].signature
}

// LatestSignature returns the latest signature of the audit history, the
// entry that updated the audit history to its current state.
func (values *AuditableValues) LatestSignature() Signature {
	n := len(values.history)
	if n == 0 {
		return Signature{}
	}
	return values.history[n-1].signature
}

// Signatures returns the signatures of all audits performed on values ordered ascending
// by timestamp.
func (values *AuditableValues) Signatures() SignatureSlice {
	signatures := make(SignatureSlice, len(values.history))
	for i, history := range values.history {
		signatures[i] = history.signature
	}
	return signatures
}

// LatestSignatureForField returns the signature of the last update that changed
// the specified field value. If the field has not been changed since the creation
// of the audit history, the creation signature is returned.
func (values *AuditableValues) LatestSignatureForField(fieldName string) Signature {
	for i := len(values.history) - 1; i > 0; i-- {
		for _, field := range values.history[i].fields {
			if field.Name == fieldName {
				return values.history[i].signature
			}
		}
	}
	return values.CreationSignature()
}

// SignaturesForField returns the signatures of all updates that affected the
// specified field.
func (values *AuditableValues) SignaturesForField(fieldName string) SignatureSlice {
	signatures := SignatureSlice{values.CreationSignature()}
	for _, h := range values.history {
		for _, field := range h.fields {
			if field.Name == fieldName {
				signatures = append(signatures, h.signature)
				break
			}
		}
	}
	return signatures
}

func (values *AuditableValues) String() string {
	var sb strings.Builder
	sb.WriteString("{\n")
	for _, h := range values.history {
		sb.WriteString("\t" + h.signature.String() + "\n")
		for _, field := range h.fields {
			sb.WriteString(fmt.Sprintf("\t\t%v\n", field))
		}
	}
	sb.WriteString("}")
	return sb.String()
}

type Field struct {
	Name  string
	Value interface{}
}

func (field Field) String() string {
	if field.Value == magicValueHistoryCreation {
		return "{ <created> }"
	}
	return fmt.Sprintf("{ %s: %T %v }", field.Name, field.Value, field.Value)
}

type AuditableObject interface {
	GetFields() (fields []Field, tRollback time.Time, err error)
	SetFields(fields []Field, tRollback time.Time) error
}

func (values *AuditableValues) Audit(oldObj, newObj AuditableObject, sig Signature) (changed bool, err error) {
	if n := len(values.history); n > 0 {
		if oldObj == nil {
			return false, fmt.Errorf("oldObj cannot be nil when there is an audit history. Only allowed on initial audit")
		}
		tLatestAudit := values.history[n-1].signature.timestamp
		if !sig.timestamp.After(tLatestAudit) {
			return false, fmt.Errorf("invalid signature timestamp: must be after latest audit timestamp "+
				"(signature: %v, latest audit: %v)", sig.timestamp, tLatestAudit,
			)
		}
	}
	var oldFields fieldSlice
	if oldObj != nil {
		fields, tRollback, err := oldObj.GetFields()
		if err != nil {
			return false, err
		}
		if !tRollback.IsZero() {
			return false, fmt.Errorf("cannot audit based on a rolled back object")
		}
		oldFields = fields
	}
	newFields, tRollback, err := newObj.GetFields()
	if err != nil {
		return false, err
	}
	if !tRollback.IsZero() {
		return false, fmt.Errorf("cannot audit based on a rolled back object")
	}
	changedFields, err := values.getHistoryFields(oldFields, newFields)
	if err != nil {
		return false, err
	}
	n := len(changedFields)
	if n == 0 {
		return false, nil
	}
	values.addHistory(sig, changedFields...)
	return true, nil
}

func (_ *AuditableValues) getHistoryFields(oldFields, newFields fieldSlice) (fieldSlice, error) {
	if oldFields == nil {
		return fieldSlice{{"", magicValueHistoryCreation}}, nil
	}
	var history fieldSlice
	// Add keys that have been removed (keys that are present in old fields but not in new)
	for _, field := range oldFields {
		if !newFields.Contains(field.Name) {
			history = append(history, field)
		}
	}
	// Add keys that have been added or updated
	for _, newField := range newFields {
		oldField, hasOldField := oldFields.TryGet(newField.Name)
		if hasOldField {
			if !equals(oldField.Value, newField.Value) {
				history = append(history, oldField)
			}
		} else {
			history = append(history, Field{Name: newField.Name, Value: magicValueFieldRemoved})
		}
	}
	return history, nil
}

func (values *AuditableValues) RollbackTo(obj AuditableObject, t time.Time) error {
	if len(values.history) == 0 {
		return fmt.Errorf("invalid state: empty history")
	}
	if tCreation := values.history[0].signature.timestamp; t.Before(tCreation) {
		return ErrDidNotExist
	}
	_currentFields, tRollback, err := obj.GetFields()
	if err != nil {
		return fmt.Errorf("error rolling back object: %w", err)
	}
	currentFields := fieldSlice(_currentFields)
	isRolledBack := !tRollback.IsZero()
	if isRolledBack && tRollback.Before(t) {
		return fmt.Errorf("object is already rolled back to a timestamp earlier than t (tRollback: %s, t: %s)",
			tRollback, t)
	}
	// Go through the history in descending order and apply (or rather, "undo") the changes
	// Note that we don't include values.history[0], since this is the creation entry
	for i := len(values.history) - 1; i > 0; i-- {
		history := values.history[i]
		tHistory := history.signature.timestamp
		if isRolledBack && tHistory.After(tRollback) {
			continue
		}
		if !tHistory.After(t) {
			continue
		}
		for _, field := range history.fields {
			switch field.Value {
			case magicValueFieldRemoved:
				currentFields.Remove(field.Name)
			default:
				currentFields.Set(field.Name, field.Value)
			}
		}
	}
	return obj.SetFields(currentFields, t)
}

func (values *AuditableValues) Serialize() ([]byte, error) {
	var b bytes.Buffer
	var buf bufrw.Buffer
	if err := values.SerializeTo(buf.Writer(&b)); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (values *AuditableValues) SerializeTo(w *bufrw.Writer) error {
	// Write version number
	if err := w.WriteByteValue(1); err != nil {
		return err
	}

	// Write out all field names. When writing fields later, we will use the indexes
	// of the names instead of the actual name to prevent repeating strings
	fieldNames := make(stringSlice, 0, 2*len(values.history))
	for _, obj := range values.history {
		for _, field := range obj.fields {
			if !fieldNames.Contains(field.Name) {
				fieldNames = append(fieldNames, field.Name)
			}
		}
	}
	if err := w.WriteInt(len(fieldNames)); err != nil {
		return err
	}
	for _, key := range fieldNames {
		if err := w.WriteString(key); err != nil {
			return err
		}
	}

	// Write the history
	if err := w.WriteInt(len(values.history)); err != nil {
		return err
	}
	for _, obj := range values.history {
		if err := w.WriteSerializable(&obj.signature); err != nil {
			return err
		}

		nFields := len(obj.fields)
		if err := w.WriteInt(nFields); err != nil {
			return err
		}
		for _, field := range obj.fields {
			nameIndex := fieldNames.IndexOf(field.Name)
			if err := w.WriteInt(nameIndex); err != nil {
				return err
			}
			var err error
			switch v := field.Value.(type) {
			case magicValue:
				if err = w.WriteByteValue(0); err == nil {
					err = w.WriteByteValue(byte(v))
				}
			case string:
				if err = w.WriteByteValue(1); err == nil {
					err = w.WriteString(v)
				}
			case bool:
				if err := w.WriteByteValue(2); err == nil {
					err = w.WriteBool(v)
				}
			case int:
				if err = w.WriteByteValue(3); err == nil {
					err = w.WriteInt(v)
				}
			case int64:
				if err = w.WriteByteValue(4); err == nil {
					err = w.WriteInt64(v)
				}
			case float64:
				if err = w.WriteByteValue(5); err == nil {
					err = w.WriteFloat64(v)
				}
			case []string:
				if err := w.WriteByteValue(6); err == nil {
					err = w.WriteStrings(v...)
				}
			case []bool:
				if err := w.WriteByteValue(7); err == nil {
					err = w.WriteBools(v...)
				}
			case []int:
				if err := w.WriteByteValue(8); err == nil {
					err = w.WriteInts(v...)
				}
			case []int64:
				if err := w.WriteByteValue(9); err == nil {
					err = w.WriteInt64s(v...)
				}
			case []float64:
				if err := w.WriteByteValue(10); err == nil {
					err = w.WriteFloat64s(v...)
				}
			case []byte:
				if err := w.WriteByteValue(11); err == nil {
					err = w.WriteByteValues(v...)
				}
			default:
				err = fmt.Errorf("cannot serialize value of type %T", field.Value)
			}
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (values *AuditableValues) Deserialize(b []byte) error {
	var buf bufrw.Buffer
	return values.DeserializeFrom(buf.Reader(bytes.NewReader(b)))
}

func (values *AuditableValues) DeserializeFrom(r *bufrw.Reader) error {
	version, err := r.ReadByteValue()
	if err != nil {
		return err
	}
	if version != 1 {
		return fmt.Errorf("invalid version number: %d", version)
	}

	nFieldNames, err := r.ReadInt()
	if err != nil {
		return err
	}
	fieldNames := make([]string, nFieldNames)
	for i := 0; i < nFieldNames; i++ {
		key, err := r.ReadString()
		if err != nil {
			return err
		}
		fieldNames[i] = key
	}

	nHistory, err := r.ReadInt()
	if err != nil {
		return err
	}
	values.history = make([]auditHistory, nHistory)
	for i := 0; i < nHistory; i++ {
		var sig Signature
		if err := r.ReadSerializable(&sig); err != nil {
			return err
		}
		nFields, err := r.ReadInt()
		if err != nil {
			return err
		}
		fields := make(fieldSlice, nFields)
		for i := 0; i < nFields; i++ {
			nameIndex, err := r.ReadInt()
			if err != nil {
				return err
			}
			name := fieldNames[nameIndex]

			var value interface{}
			valueType, err := r.ReadByteValue()
			switch valueType {
			case 0:
				v, err := r.ReadByteValue()
				if err != nil {
					return err
				}
				value = magicValue(v)
			case 1:
				value, err = r.ReadString()
			case 2:
				value, err = r.ReadBool()
			case 3:
				value, err = r.ReadInt()
			case 4:
				value, err = r.ReadInt64()
			case 5:
				value, err = r.ReadFloat64()
			case 6:
				value, err = r.ReadStrings()
			case 7:
				value, err = r.ReadBools()
			case 8:
				value, err = r.ReadInts()
			case 9:
				value, err = r.ReadInt64s()
			case 10:
				value, err = r.ReadFloat64s()
			case 11:
				value, err = r.ReadByteValues()
			default:
				err = fmt.Errorf("invalid value type: %d", valueType)
			}
			if err != nil {
				return err
			}
			fields[i] = Field{name, value}
		}
		values.history[i].signature = sig
		values.history[i].fields = fields
	}
	return nil
}

type fieldSlice []Field

func (s fieldSlice) IndexOf(name string) int {
	for i, field := range s {
		if field.Name == name {
			return i
		}
	}
	return -1
}

func (s fieldSlice) Contains(name string) bool {
	return s.IndexOf(name) != -1
}

func (s fieldSlice) TryGet(name string) (Field, bool) {
	for _, field := range s {
		if field.Name == name {
			return field, true
		}
	}
	return Field{}, false
}

func (s *fieldSlice) Remove(name string) {
	index := s.IndexOf(name)
	if index == -1 {
		return
	}
	n := len(*s)
	_s := *s
	_s[n-1], _s[index] = _s[index], _s[n-1]
	*s = _s[:n-1]
}

func (s *fieldSlice) Set(name string, value interface{}) {
	field := Field{name, value}
	index := s.IndexOf(name)
	if index == -1 {
		*s = append(*s, field)
	} else {
		(*s)[index] = field
	}
}
