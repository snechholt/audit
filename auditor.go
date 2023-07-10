package audit

import (
	"fmt"
	"strings"
)
type AuditorKind string

type Auditor struct {
	kind AuditorKind
	id string
}

func NewAuditor(kind AuditorKind, id string) Auditor {
	if strings.Contains(string(kind), "/") || strings.Contains(id, "/"){
		panic("No slashes")
	}
	return Auditor{kind:kind,id:id}
}

func (auditor Auditor) Kind() AuditorKind {
	return auditor.kind
}

func (auditor Auditor) ID() string {
	return auditor.id
}

func (auditor Auditor) IsZero() bool {
	return auditor == Auditor{}
}

func (auditor Auditor) Equal(actor2 Auditor) bool {
	return auditor.kind == actor2.kind && auditor.id == actor2.id
}

func (auditor Auditor) Encode() string {
	return string(auditor.kind) + "/" + auditor.id
}

func (auditor *Auditor) Decode(src string) error {
	split := strings.Split(src, "/")
	if len(split) != 2 {
		return fmt.Errorf("invalid encoded actor: %s", src)
	}
	auditor.kind = AuditorKind(split[0])
	auditor.id = split[1]
	return nil
}

func (auditor Auditor) String() string {
	return auditor.Encode()
}