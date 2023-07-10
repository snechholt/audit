package audit

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestAuditableValuesGetHistoryFields(t *testing.T) {
	var v AuditableValues

	// When passing in nil as the old fields, a "creation" field is returned
	{
		var oldFields []Field = nil
		newFields := []Field{
			{"something", "new"},
		}
		got, err := v.getHistoryFields(oldFields, newFields)
		if err != nil {
			t.Fatal(err)
		}
		want := fieldSlice{
			{"", magicValueHistoryCreation},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Wrong fields returned for creation event\nWant %v\nGot  %v", want, got)
		}
	}

	// Return nil when there are no changes
	{
		fields := []Field{
			{"string", "1"},
		}
		// Pass in the same fields as both arguments
		got, err := v.getHistoryFields(fields, fields)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) > 0 {
			t.Errorf("Wrong fields returned when the inputs are equal\nWant nil\nGot  %v", got)
		}
	}

	// Basic types: Return the fields from oldFields that do not match with the values in newFields
	{
		// Fields contains one key for each type we support
		oldFields := []Field{
			{"string", "1"},
			{"int", int(1)},
			{"int64", int64(1)},
			{"float64", float64(1)},
			{"bool", true},
		}
		newFields := []Field{
			{"string", "2"},
			{"int", int(2)},
			{"int64", int64(2)},
			{"float64", float64(2)},
			{"bool", false},
		}

		for _, newField := range newFields {
			// Create a copy of the old fields and then override a single key with the new value
			newFields := make([]Field, len(oldFields))
			var wantField Field
			for i, oldField := range oldFields {
				if oldField.Name == newField.Name {
					newFields[i] = newField
					wantField = oldField
				} else {
					newFields[i] = oldField
				}
			}

			got, err := v.getHistoryFields(oldFields, newFields)
			if err != nil {
				t.Fatal(err)
			}
			want := fieldSlice{wantField}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("Wrong fields returned when changing key '%s'\nWant %v\nGot  %v", newField.Name, want, got)
			}
		}
	}

	// Slices
	{
		// Map contains one key for each type we support
		oldFields := []Field{
			{"[]string", []string{"1"}},
			{"[]int", []int{1}},
			{"[]int64", []int64{1}},
			{"[]float64", []float64{1}},
			{"[]bool", []bool{true}},
		}
		newFields := []Field{
			{"[]string", []string{"2"}},
			{"[]int", []int{2}},
			{"[]int64", []int64{2}},
			{"[]float64", []float64{2}},
			{"[]bool", []bool{false}},
		}

		for _, newField := range newFields {
			// Create a copy of the old fields and then override a single key with the new value
			newFields := make([]Field, len(oldFields))
			var wantField Field
			for i, oldField := range oldFields {
				if oldField.Name == newField.Name {
					newFields[i] = newField
					wantField = oldField
				} else {
					newFields[i] = oldField
				}
			}

			got, err := v.getHistoryFields(oldFields, newFields)
			if err != nil {
				t.Fatal(err)
			}
			want := fieldSlice{wantField}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("Wrong map returned when changing key '%s'\nWant %v\nGot  %v", newField.Name, want, got)
			}
		}
	}

	// Return magic key "removed" when key is present in new fields and not in old fields
	{
		oldFields := []Field{}
		newFields := []Field{
			{"key1", 1},
		}
		got, err := v.getHistoryFields(oldFields, newFields)
		if err != nil {
			t.Fatal(err)
		}
		want := fieldSlice{
			{"key1", magicValueFieldRemoved},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Wrong map returned when key is removed \nWant %v\nGot  %v", want, got)
		}
	}

	// Return old value when key is present in old fields and not in new fields
	{
		oldFields := []Field{
			{"key1", 1},
		}
		newFields := []Field{}
		got, err := v.getHistoryFields(oldFields, newFields)
		if err != nil {
			t.Fatal(err)
		}
		want := fieldSlice{
			{"key1", 1},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Wrong map returned when key is removed \nWant %v\nGot  %v", want, got)
		}
	}
}

// Tests that we audit and roll back basic fields (string, bool, int, int64 and float64)
func TestAuditableValuesAuditAndRollbackBasicTypes(t *testing.T) {
	getSig := new(signatureGenerator).Next

	// TODO: use auditableObject instead
	obj := &auditableBasicObject{
		StringValue:  "1",
		BoolValue:    true,
		IntValue:     1,
		Int64Value:   100,
		Float64Value: 1,
		StaticValue:  "should not change",
	}

	var av AuditableValues

	// Creation
	creationSignature := getSig()
	if changed, err := av.Audit(nil, obj, creationSignature); err != nil {
		t.Fatal(err)
	} else if !changed {
		t.Errorf("Audit() returned false on creation event")
	}

	tCreation := creationSignature.Timestamp()
	stateAtCreation := obj.Copy()

	// Update all values (except for the static one)
	updateSignature1 := getSig()
	{
		cpy := obj.Copy() // "Memento". Save the current state of the object
		obj.StringValue = "2"
		obj.BoolValue = !obj.BoolValue
		obj.IntValue = 2
		obj.Int64Value = 2
		obj.Float64Value = 2
		changed, err := av.Audit(cpy, obj, updateSignature1)
		if err != nil {
			t.Fatal(err)
		}
		if !changed {
			t.Errorf("Audit() returned false on IntValue = 2")
		}
	}

	tUpdate1 := updateSignature1.Timestamp()
	stateAfterUpdate1 := obj.Copy()

	// Update IntValue and StringValue but not the others
	updateSignature2 := getSig()
	{
		cpy := obj.Copy() // "Memento". Save the current state of the object
		obj.IntValue = 3
		obj.StringValue = "3"
		changed, err := av.Audit(cpy, obj, updateSignature2)
		if err != nil {
			t.Fatal(err)
		}
		if !changed {
			t.Errorf("Audit() returned false on StringValue, IntValue = 3, 3")
		}
	}

	tUpdate2 := updateSignature2.Timestamp()
	stateAfterUpdate2 := obj.Copy()

	// Check that Audit() returned false when there are no changes
	{
		oldAvState := fmt.Sprintf("%v", av)
		sig := getSig()
		cpy := obj.Copy()
		changed, err := av.Audit(cpy, obj, sig)
		if err != nil {
			t.Fatal(err)
		}
		if changed {
			t.Fatal("Audit() returned true when no changes had been applied to the object")
		}
		newAvState := fmt.Sprintf("%v", av)
		if oldAvState != newAvState {
			t.Fatalf("Audit() changed AuditValues data was when no changes had been applied to the object")
		}
	}

	// Test that Audit() returns error if oldValues is nil, now that there is an audit history
	{
		wantErr := fmt.Errorf("oldObj cannot be nil when there is an audit history. Only allowed on initial audit")
		sig := getSig()
		_, gotErr := av.Audit(nil, obj, sig)
		if !gotError(gotErr, wantErr) {
			t.Fatalf("Audit() returned wrong error when oldObj is nil after auditing\nWant %v\nGot  %v", wantErr, gotErr)
		}
	}

	// Test that Audit() returns error when signature timestamp is not after latest audit
	{
		signaturesWithInvalidTimestamp := SignatureSlice{
			NewSignature(Auditor{}, tUpdate2.Add(-time.Second)), // Timestamp is just before the latest audit entry
			updateSignature2, // Timestamp is equal to the latest audit entry
		}
		for _, sig := range signaturesWithInvalidTimestamp {
			_, err := av.Audit(obj, obj, sig)
			wantErr := fmt.Errorf("invalid signature timestamp: must be after latest audit timestamp (signature: %s, latest audit: %s)",
				sig.Timestamp(), tUpdate2,
			)
			if !gotError(err, wantErr) {
				t.Fatalf("Audit() returned wrong error on invalid signature timestamp\nWant %v\nGot  %v", wantErr, err)
			}
		}
	}

	// Never allow rollback to before creation
	tBeforeCreation := creationSignature.Timestamp().Add(-time.Minute)
	if err := av.RollbackTo(obj, tBeforeCreation); err != ErrDidNotExist {
		t.Errorf("Rolling back object to before creation returned wrong error\nWant %v\nGot  %v", ErrDidNotExist, err)
	}

	// Test rolling back state to timestamps around each update that was audited
	tests := []struct {
		name      string
		tRollback time.Time
		want      *auditableBasicObject
	}{
		{name: "After update 2", tRollback: tUpdate2.Add(time.Second), want: stateAfterUpdate2},
		{name: "At update 2", tRollback: tUpdate2, want: stateAfterUpdate2},
		{name: "Before update 2", tRollback: tUpdate2.Add(-time.Second), want: stateAfterUpdate1},
		{name: "After update 1", tRollback: tUpdate1.Add(time.Second), want: stateAfterUpdate1},
		{name: "At update 1", tRollback: tUpdate1, want: stateAfterUpdate1},
		{name: "Before update 1", tRollback: tUpdate1.Add(-time.Second), want: stateAtCreation},
		{name: "After creation", tRollback: tCreation.Add(time.Second), want: stateAtCreation},
		{name: "At creation", tRollback: tCreation, want: stateAtCreation},
	}
	for _, test := range tests {
		if err := av.RollbackTo(obj, test.tRollback); err != nil {
			t.Fatalf("RollbackTo(%s) error: %v", test.name, err)
		}

		// Validate that the state of the object is as expected
		want := test.want.Copy()
		want.tRollback = test.tRollback
		if !reflect.DeepEqual(want, obj) {
			t.Fatalf("Wrong state after RollbackTo(%s)\nWant %v\nGot  %v", test.name, want, obj)
		}

		// Validate that we can't roll back to a time *after* the current rollback time
		tAfterRollback := test.tRollback.Add(time.Second)
		wantErr := fmt.Errorf("object is already rolled back to a timestamp earlier than t (tRollback: %s, t: %s)",
			test.tRollback, tAfterRollback)
		if err := av.RollbackTo(obj, tAfterRollback); !gotError(err, wantErr) {
			t.Fatalf("Wrong error returned when rolling back with t > tRollback (%s)\nWant %v\nGot  %v", test.name, wantErr, err)
		}
		if !reflect.DeepEqual(want, obj) {
			t.Fatalf("Wrong state after rolling back with t > tRollback (%s)\nWant %v\nGot  %v", test.name, want, obj)
		}

		// Validate that we can't roll back to before creation
		if err := av.RollbackTo(obj, tBeforeCreation); err != ErrDidNotExist {
			t.Fatalf("Rolling back object to before creation returned wrong error\nWant %v\nGot  %v", ErrDidNotExist, err)
		}
		if !reflect.DeepEqual(want, obj) {
			t.Fatalf("Wrong state after rolling back to before creation (%s)\nWant %v\nGot  %v", test.name, want, obj)
		}
	}
}

type auditableBasicObject struct {
	StringValue  string
	BoolValue    bool
	IntValue     int
	Int64Value   int64
	Float64Value float64

	// Value is never changed and is here to assert that rolling back the
	// object does not alter this field
	StaticValue string

	tRollback time.Time
}

func (obj *auditableBasicObject) Copy() *auditableBasicObject {
	cpy := *obj
	return &cpy
}

func (obj *auditableBasicObject) GetFields() ([]Field, time.Time, error) {
	values := []Field{
		{"StringValue", obj.StringValue},
		{"BoolValue", obj.BoolValue},
		{"IntValue", obj.IntValue},
		{"Int64Value", obj.Int64Value},
		{"Float64Value", obj.Float64Value},
	}
	return values, obj.tRollback, nil
}

func (obj *auditableBasicObject) SetFields(values []Field, tRollback time.Time) error {
	for _, field := range values {
		switch field.Name {
		case "StringValue":
			obj.StringValue = field.Value.(string)
		case "BoolValue":
			obj.BoolValue = field.Value.(bool)
		case "IntValue":
			obj.IntValue = field.Value.(int)
		case "Int64Value":
			obj.Int64Value = field.Value.(int64)
		case "Float64Value":
			obj.Float64Value = field.Value.(float64)
		default:
			panic("Invalid field: " + field.String())
		}
	}
	obj.tRollback = tRollback
	return nil
}

func (obj *auditableBasicObject) String() string {
	return fmt.Sprintf("{ Str:%v Bool:%v Int:%v Int64:%v Float64:%v, Static:%v tRollback:%s }",
		obj.StringValue,
		obj.BoolValue,
		obj.IntValue,
		obj.Int64Value,
		obj.Float64Value,
		obj.StaticValue,
		obj.tRollback.Format(time.RFC3339),
	)
}

// Tests that we audit and roll back slice fields ([]string, []bool, []int, []int64 and []float64)
func TestAuditableValuesAuditAndRollbackSliceTypes(t *testing.T) {
	getSig := new(signatureGenerator).Next

	// TODO: use auditableObject instead
	obj := &auditableSliceObject{
		StringValue:  []string{"1"},
		BoolValue:    []bool{true},
		IntValue:     []int{1},
		Int64Value:   []int64{100},
		Float64Value: []float64{1},
		StaticValue:  "should not change",
	}

	var av AuditableValues

	// Creation
	creationSignature := getSig()
	if changed, err := av.Audit(nil, obj, creationSignature); err != nil {
		t.Fatal(err)
	} else if !changed {
		t.Errorf("Audit() returned false on creation event")
	}

	tCreation := creationSignature.Timestamp()
	stateAtCreation := obj.Copy()

	// Update all slices: add two more items
	updateSignature1 := getSig()
	{
		cpy := obj.Copy() // "Memento". Save the current state of the object
		obj.StringValue = []string{"1", "2", "3"}
		obj.BoolValue = []bool{true, false, true}
		obj.IntValue = []int{1, 2, 3}
		obj.Int64Value = []int64{1, 2, 3}
		obj.Float64Value = []float64{1, 2, 3}
		changed, err := av.Audit(cpy, obj, updateSignature1)
		if err != nil {
			t.Fatal(err)
		}
		if !changed {
			t.Errorf("Audit() returned false on IntValue = 2")
		}
	}

	tUpdate1 := updateSignature1.Timestamp()
	stateAfterUpdate1 := obj.Copy()

	// Update all slices: remove the middle item
	updateSignature2 := getSig()
	{
		cpy := obj.Copy() // "Memento". Save the current state of the object
		obj.StringValue = []string{"1", "3"}
		obj.BoolValue = []bool{true, true}
		obj.IntValue = []int{1, 3}
		obj.Int64Value = []int64{1, 3}
		obj.Float64Value = []float64{1, 3}
		changed, err := av.Audit(cpy, obj, updateSignature2)
		if err != nil {
			t.Fatal(err)
		}
		if !changed {
			t.Errorf("Audit() returned false on IntValue = 2")
		}
	}

	tUpdate2 := updateSignature2.Timestamp()
	stateAfterUpdate2 := obj.Copy()

	// Update all slices: change value at index 0
	updateSignature3 := getSig()
	{
		cpy := obj.Copy() // "Memento". Save the current state of the object
		obj.StringValue = []string{"11", "3"}
		obj.BoolValue = []bool{false, true}
		obj.IntValue = []int{11, 3}
		obj.Int64Value = []int64{11, 3}
		obj.Float64Value = []float64{11, 3}
		changed, err := av.Audit(cpy, obj, updateSignature3)
		if err != nil {
			t.Fatal(err)
		}
		if !changed {
			t.Errorf("Audit() returned false on IntValue = 2")
		}
	}

	tUpdate3 := updateSignature3.Timestamp()
	stateAfterUpdate3 := obj.Copy()

	// Check that Audit() returned false when there are no changes
	{
		oldAvState := fmt.Sprintf("%v", av)
		sig := getSig()
		cpy := obj.Copy()
		changed, err := av.Audit(cpy, obj, sig)
		if err != nil {
			t.Fatal(err)
		}
		if changed {
			t.Fatal("Audit() returned true when no changes had been applied to the object")
		}
		newAvState := fmt.Sprintf("%v", av)
		if oldAvState != newAvState {
			t.Fatalf("Audit() changed AuditValues data was when no changes had been applied to the object")
		}
	}

	// Test that Audit() returns error if oldValues is nil, now that there is an audit history
	{
		wantErr := fmt.Errorf("oldObj cannot be nil when there is an audit history. Only allowed on initial audit")
		sig := getSig()
		_, gotErr := av.Audit(nil, obj, sig)
		if !gotError(gotErr, wantErr) {
			t.Fatalf("Audit() returned wrong error when oldObj is nil after auditing\nWant %v\nGot  %v", wantErr, gotErr)
		}
	}

	// Test that Audit() returns error when signature timestamp is not after latest audit
	{
		signaturesWithInvalidTimestamp := SignatureSlice{
			NewSignature(Auditor{}, tUpdate3.Add(-time.Second)), // Timestamp is just before the latest audit entry
			updateSignature2, // Timestamp is equal to the latest audit entry
		}
		for _, sig := range signaturesWithInvalidTimestamp {
			_, err := av.Audit(obj, obj, sig)
			wantErr := fmt.Errorf("invalid signature timestamp: must be after latest audit timestamp (signature: %s, latest audit: %s)",
				sig.Timestamp(), tUpdate3,
			)
			if !gotError(err, wantErr) {
				t.Fatalf("Audit() returned wrong error on invalid signature timestamp\nWant %v\nGot  %v", wantErr, err)
			}
		}
	}

	// Never allow rollback to before creation
	tBeforeCreation := creationSignature.Timestamp().Add(-time.Minute)
	if err := av.RollbackTo(obj, tBeforeCreation); err != ErrDidNotExist {
		t.Errorf("Rolling back object to before creation returned wrong error\nWant %v\nGot  %v", ErrDidNotExist, err)
	}

	// Test rolling back state to timestamps around each update that was audited
	tests := []struct {
		name      string
		tRollback time.Time
		want      *auditableSliceObject
	}{
		{name: "After update 3", tRollback: tUpdate3.Add(time.Second), want: stateAfterUpdate3},
		{name: "At update 3", tRollback: tUpdate3, want: stateAfterUpdate3},
		{name: "Before update 3", tRollback: tUpdate3.Add(-time.Second), want: stateAfterUpdate2},
		{name: "After update 2", tRollback: tUpdate2.Add(time.Second), want: stateAfterUpdate2},
		{name: "At update 2", tRollback: tUpdate2, want: stateAfterUpdate2},
		{name: "Before update 2", tRollback: tUpdate2.Add(-time.Second), want: stateAfterUpdate1},
		{name: "After update 1", tRollback: tUpdate1.Add(time.Second), want: stateAfterUpdate1},
		{name: "At update 1", tRollback: tUpdate1, want: stateAfterUpdate1},
		{name: "Before update 1", tRollback: tUpdate1.Add(-time.Second), want: stateAtCreation},
		{name: "After creation", tRollback: tCreation.Add(time.Second), want: stateAtCreation},
		{name: "At creation", tRollback: tCreation, want: stateAtCreation},
	}
	for _, test := range tests {
		if err := av.RollbackTo(obj, test.tRollback); err != nil {
			t.Fatalf("RollbackTo(%s) error: %v", test.name, err)
		}

		// Validate that the state of the object is as expected
		want := test.want.Copy()
		want.tRollback = test.tRollback
		if !reflect.DeepEqual(want, obj) {
			t.Fatalf("Wrong state after RollbackTo(%s)\nWant %v\nGot  %v", test.name, want, obj)
		}

		// Validate that we can't roll back to a time *after* the current rollback time
		tAfterRollback := test.tRollback.Add(time.Second)
		wantErr := fmt.Errorf("object is already rolled back to a timestamp earlier than t (tRollback: %s, t: %s)",
			test.tRollback, tAfterRollback)
		if err := av.RollbackTo(obj, tAfterRollback); !gotError(err, wantErr) {
			t.Fatalf("Wrong error returned when rolling back with t > tRollback (%s)\nWant %v\nGot  %v", test.name, wantErr, err)
		}
		if !reflect.DeepEqual(want, obj) {
			t.Fatalf("Wrong state after rolling back with t > tRollback (%s)\nWant %v\nGot  %v", test.name, want, obj)
		}

		// Validate that we can't roll back to before creation
		if err := av.RollbackTo(obj, tBeforeCreation); err != ErrDidNotExist {
			t.Fatalf("Rolling back object to before creation returned wrong error\nWant %v\nGot  %v", ErrDidNotExist, err)
		}
		if !reflect.DeepEqual(want, obj) {
			t.Fatalf("Wrong state after rolling back to before creation (%s)\nWant %v\nGot  %v", test.name, want, obj)
		}
	}
}

type auditableSliceObject struct {
	StringValue  []string
	BoolValue    []bool
	IntValue     []int
	Int64Value   []int64
	Float64Value []float64

	// Value is never changed and is here to assert that rolling back the
	// object does not alter this field
	StaticValue string

	tRollback time.Time
}

func (obj *auditableSliceObject) Copy() *auditableSliceObject {
	cpy := *obj
	return &cpy
}

func (obj *auditableSliceObject) GetFields() ([]Field, time.Time, error) {
	values := []Field{
		{"StringValue", obj.StringValue},
		{"BoolValue", obj.BoolValue},
		{"IntValue", obj.IntValue},
		{"Int64Value", obj.Int64Value},
		{"Float64Value", obj.Float64Value},
	}
	return values, obj.tRollback, nil
}

func (obj *auditableSliceObject) SetFields(values []Field, tRollback time.Time) error {
	for _, field := range values {
		switch field.Name {
		case "StringValue":
			obj.StringValue = field.Value.([]string)
		case "BoolValue":
			obj.BoolValue = field.Value.([]bool)
		case "IntValue":
			obj.IntValue = field.Value.([]int)
		case "Int64Value":
			obj.Int64Value = field.Value.([]int64)
		case "Float64Value":
			obj.Float64Value = field.Value.([]float64)
		default:
			panic("Invalid field: " + field.String())
		}
	}
	obj.tRollback = tRollback
	return nil
}

func (obj *auditableSliceObject) String() string {
	return fmt.Sprintf("{ Str:%v Bool:%v Int:%v Int64:%v Float64:%v, Static:%v tRollback:%s }",
		obj.StringValue,
		obj.BoolValue,
		obj.IntValue,
		obj.Int64Value,
		obj.Float64Value,
		obj.StaticValue,
		obj.tRollback.Format(time.RFC3339),
	)
}

// Tests that we audit and roll back and object where GetValues() can return a map with different keys
func TestAuditableValuesAuditAndRollbackObjectWithDynamicValues(t *testing.T) {
	getSig := new(signatureGenerator).Next

	// TODO: use auditableObject instead
	obj := &auditableObject{
		Values: map[string]interface{}{
			"ValueA": "a1",
			"ValueB": "b1",
			"ValueC": "c1",
		},
	}

	var av AuditableValues

	// Creation
	creationSignature := getSig()
	if changed, err := av.Audit(nil, obj, creationSignature); err != nil {
		t.Fatal(err)
	} else if !changed {
		t.Errorf("Audit() returned false on creation event")
	}

	tCreation := creationSignature.Timestamp()
	stateAtCreation := obj.Copy()

	// Update values
	updateSignature1 := getSig()
	{
		cpy := obj.Copy() // "Memento". Save the current state of the object
		obj.Values = map[string]interface{}{
			"ValueA": "a1", // ValueA is not updated
			"ValueB": "b2", // ValueB is updated
			// ValueC is removed
			"ValueD": "d2", // "ValueD is added
		}
		changed, err := av.Audit(cpy, obj, updateSignature1)
		if err != nil {
			t.Fatal(err)
		}
		if !changed {
			t.Errorf("Audit() returned false on IntValue = 2")
		}
	}

	tUpdate1 := updateSignature1.Timestamp()
	stateAfterUpdate1 := obj.Copy()

	// Update values
	updateSignature2 := getSig()
	{
		cpy := obj.Copy() // "Memento". Save the current state of the object
		obj.Values = map[string]interface{}{
			"ValueA": "a3", // ValueA is updated
			// ValueB is removed
			"ValueC": "c3", // ValueC is added
			"ValueD": "d2", // "ValueD is not updated
		}
		changed, err := av.Audit(cpy, obj, updateSignature2)
		if err != nil {
			t.Fatal(err)
		}
		if !changed {
			t.Errorf("Audit() returned false on IntValue = 2")
		}
	}

	tUpdate2 := updateSignature2.Timestamp()
	stateAfterUpdate2 := obj.Copy()

	// Test rolling back state to timestamps around each update that was audited
	tests := []struct {
		name      string
		tRollback time.Time
		want      *auditableObject
	}{
		{name: "After update 2", tRollback: tUpdate2.Add(time.Second), want: stateAfterUpdate2},
		{name: "At update 2", tRollback: tUpdate2, want: stateAfterUpdate2},
		{name: "Before update 2", tRollback: tUpdate2.Add(-time.Second), want: stateAfterUpdate1},
		{name: "After update 1", tRollback: tUpdate1.Add(time.Second), want: stateAfterUpdate1},
		{name: "At update 1", tRollback: tUpdate1, want: stateAfterUpdate1},
		{name: "Before update 1", tRollback: tUpdate1.Add(-time.Second), want: stateAtCreation},
		{name: "After creation", tRollback: tCreation.Add(time.Second), want: stateAtCreation},
		{name: "At creation", tRollback: tCreation, want: stateAtCreation},
	}
	for _, test := range tests {
		if err := av.RollbackTo(obj, test.tRollback); err != nil {
			t.Fatalf("RollbackTo(%s) error: %v", test.name, err)
		}

		// Validate that the state of the object is as expected
		want := test.want.Copy()
		want.tRollback = test.tRollback
		if !reflect.DeepEqual(want, obj) {
			t.Fatalf("Wrong state after RollbackTo(%s)\nWant %v\nGot  %v", test.name, want, obj)
		}
	}
}

type auditableObject struct {
	Values map[string]interface{}

	tRollback time.Time
}

func (obj *auditableObject) Copy() *auditableObject {
	cpy := &auditableObject{
		Values:    make(map[string]interface{}, len(obj.Values)),
		tRollback: obj.tRollback,
	}
	for key, value := range obj.Values {
		cpy.Values[key] = value
	}
	return cpy
}

func (obj *auditableObject) GetFields() ([]Field, time.Time, error) {
	fields := make([]Field, 0, len(obj.Values))
	for key, value := range obj.Values {
		fields = append(fields, Field{key, value})
	}
	return fields, obj.tRollback, nil
}

func (obj *auditableObject) SetFields(fields []Field, tRollback time.Time) error {
	m := make(map[string]interface{}, len(fields))
	for _, field := range fields {
		m[field.Name] = field.Value
	}
	obj.Values = m
	obj.tRollback = tRollback
	return nil
}

func (obj *auditableObject) String() string {
	return fmt.Sprintf("{ Values:%v tRollback:%s }", obj.Values, obj.tRollback.Format(time.RFC3339))
}

func TestAuditableValuesSerialization(t *testing.T) {
	getSig := new(signatureGenerator).Next
	getHistory := func(values ...interface{}) struct {
		fields    fieldSlice
		signature Signature
	} {
		fields := make([]Field, 0, len(values))
		for i, value := range values {
			name := fmt.Sprintf("field%d", i)
			fields = append(fields, Field{name, value})
		}
		return struct {
			fields    fieldSlice
			signature Signature
		}{fields, getSig()}
	}
	value := AuditableValues{
		history: []auditHistory{
			// Magic values
			getHistory(magicValueHistoryCreation),
			getHistory(magicValueFieldRemoved),
			// Basic types
			getHistory("abc", "def"),                  // string
			getHistory(true, false),                   // bool
			getHistory(-1, 0, 1),                      // int
			getHistory(int64(-1), int64(0), int64(1)), // int64
			getHistory(-1.5, 0, 1.5),                  // float64
			// Slices
			getHistory([]string{"abc", "def"}, []string{"123", "456"}), // []string
			getHistory([]bool{true, false}, []bool{false, true}),       // []bool
			getHistory([]int{-1, 0, 1}, []int{1, 2, 3}),                // []int
			getHistory([]int64{-1, 0, 1}, []int64{1, 2, 3}),            // int64
			getHistory([]float64{-1.5, 0, 1.5}),                        // []float64
		},
	}
	b, err := value.Serialize()
	if err != nil {
		t.Fatalf("Serialize() error: %v", err)
	}
	var got AuditableValues
	if err := got.Deserialize(b); err != nil {
		t.Fatalf("Deserialize() error: %v", err)
	}
	if !reflect.DeepEqual(value, got) {
		t.Errorf("Wrong value after serialize/deserialize\nWant %v\nGot  %v", value, got)
	}
}

func TestAuditableValuesLatestSignatureForField(t *testing.T) {
	getSig := new(signatureGenerator).Next

	var (
		sig0 = getSig() // Creation signature
		sig1 = getSig() // Update 1
		sig2 = getSig() // Update 2
		sig3 = getSig() // Update 3
	)

	var av AuditableValues
	av.addHistory(sig0, Field{Value: magicValueHistoryCreation})
	av.addHistory(sig1, Field{Name: "A", Value: ""}, Field{Name: "B", Value: ""}, Field{Name: "C", Value: ""})
	av.addHistory(sig2, Field{Name: "A", Value: ""}, Field{Name: "B", Value: ""})
	av.addHistory(sig3, Field{Name: "A", Value: ""})

	tests := map[string]Signature{
		"A": sig3,
		"B": sig2,
		"C": sig1,
		"D": sig0, // No updates have been registered for key D. Creation signature should be returned
	}
	for key, want := range tests {
		got := av.LatestSignatureForField(key)
		if !got.Equal(want) {
			t.Errorf("Wrong signature returned for key %s: want %v, got %v", key, want, got)
		}
	}
}

func TestAuditableValuesSignaturesForField(t *testing.T) {
	getSig := new(signatureGenerator).Next

	var (
		sig0 = getSig() // Creation signature
		sig1 = getSig() // Update 1
		sig2 = getSig() // Update 2
		sig3 = getSig() // Update 3
	)

	var av AuditableValues
	av.addHistory(sig0, Field{Value: magicValueHistoryCreation})
	av.addHistory(sig1, Field{Name: "A", Value: ""}, Field{Name: "B", Value: ""}, Field{Name: "C", Value: ""})
	av.addHistory(sig2, Field{Name: "A", Value: ""}, Field{Name: "B", Value: ""})
	av.addHistory(sig3, Field{Name: "A", Value: ""})

	tests := map[string]SignatureSlice{
		"A": {sig0, sig1, sig2, sig3},
		"B": {sig0, sig1, sig2},
		"C": {sig0, sig1},
		"D": {sig0},
	}
	for key, want := range tests {
		got := av.SignaturesForField(key)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Wrong signature returned for key %s\nWant %v\nGot  %v", key, want, got)
		}
	}
}

type signatureGenerator struct {
	Auditor Auditor
	counter int
}

func (gen *signatureGenerator) Next(timestamp ...time.Time) Signature {
	gen.counter++
	t := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).
		AddDate(0, 0, gen.counter).
		Add(time.Duration(gen.counter) * time.Minute)
	return NewSignature(gen.Auditor, t)
}
