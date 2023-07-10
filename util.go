package audit

import "fmt"

func equals(value1, value2 interface{}) bool {
	switch v1 := value1.(type) {
	case string:
		v2, ok := value2.(string)
		return ok && v1 == v2
	case bool:
		v2, ok := value2.(bool)
		return ok && v1 == v2
	case int:
		v2, ok := value2.(int)
		return ok && v1 == v2
	case int64:
		v2, ok := value2.(int64)
		return ok && v1 == v2
	case float64:
		v2, ok := value2.(float64)
		return ok && v1 == v2
	case []string:
		v2, ok := value2.([]string)
		if !ok || len(v1) != len(v2) {
			return false
		}
		for i := range v1 {
			if v1[i] != v2[i] {
				return false
			}
		}
		return true
	case []bool:
		v2, ok := value2.([]bool)
		if !ok || len(v1) != len(v2) {
			return false
		}
		for i := range v1 {
			if v1[i] != v2[i] {
				return false
			}
		}
		return true
	case []int:
		v2, ok := value2.([]int)
		if !ok || len(v1) != len(v2) {
			return false
		}
		for i := range v1 {
			if v1[i] != v2[i] {
				return false
			}
		}
		return true
	case []int64:
		v2, ok := value2.([]int64)
		if !ok || len(v1) != len(v2) {
			return false
		}
		for i := range v1 {
			if v1[i] != v2[i] {
				return false
			}
		}
		return true
	case []float64:
		v2, ok := value2.([]float64)
		if !ok || len(v1) != len(v2) {
			return false
		}
		for i := range v1 {
			if v1[i] != v2[i] {
				return false
			}
		}
		return true
	case []byte:
		v2, ok := value2.([]byte)
		if !ok || len(v1) != len(v2) {
			return false
		}
		for i := range v1 {
			if v1[i] != v2[i] {
				return false
			}
		}
		return true
	default:
		panic(fmt.Sprintf("Unsupported value type: %T", value1))
	}
}

type stringSlice []string

func (slice stringSlice) IndexOf(s string) int {
	for i := range slice {
		if slice[i] == s {
			return i
		}
	}
	return -1
}

func (slice stringSlice) Contains(s string) bool {
	for i := range slice {
		if slice[i] == s {
			return true
		}
	}
	return false
}

