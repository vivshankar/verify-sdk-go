// Package types extends Go types
package types

import (
	"encoding/json"

	jose "github.com/go-jose/go-jose/v4"
)

type Map map[string]any

// SafeStringSlice converts a map entry to a string array if possible
func (m Map) SafeStringSlice(key string, def []string) []string {
	if m == nil {
		return def
	}

	mval, ok := m[key]
	if !ok {
		return def
	}

	var result []string
	if sa, ok := mval.([]string); ok {
		result = make([]string, len(sa))
		copy(result, sa)
	} else if ia, ok := mval.([]any); ok {
		for _, val := range ia {
			if s, ok := val.(string); ok {
				result = append(result, s)
			}
		}
		if len(result) == 0 {
			return def
		}
	} else if v, ok := mval.(string); ok {
		result = append(result, v)
	} else {
		return def
	}
	return result
}

// SafeSlice converts a map entry to a any array if possible
func (m Map) SafeSlice(key string, def []any) []any {
	if m == nil {
		return def
	}

	mval, ok := m[key]
	if !ok {
		return def
	}

	vals, ok := mval.([]any)
	if !ok {
		return def
	}

	return vals
}

// SafeString converts a map entry to a string if possible
func (m Map) SafeString(key string, def string) string {
	if m == nil {
		return def
	}

	mval, ok := m[key]
	if !ok {
		return def
	}

	val, ok := mval.(string)
	if !ok {
		return def
	}

	if val == "" {
		return def
	}

	return val
}

// SafeBool converts a map entry to a bool if possible
func (m Map) SafeBool(key string, def bool) bool {
	if m == nil {
		return def
	}

	mval, ok := m[key]
	if !ok {
		return def
	}

	val, ok := mval.(bool)
	if !ok {
		return def
	}

	return val
}

// SafeUInt64 converts a map entry to a uint64 if possible
func (m Map) SafeUInt64(key string, def uint64) uint64 {
	if m == nil {
		return def
	}

	mval, ok := m[key]
	if !ok {
		return def
	}

	val, ok := mval.(float64)
	if !ok {
		return def
	}

	return uint64(val)
}

// SafeInt64 converts a map entry to a int64 if possible
func (m Map) SafeInt64(key string, def int64) int64 {
	if m == nil {
		return def
	}

	claim, ok := m[key]
	if !ok {
		return def
	}

	switch t := claim.(type) {
	case float64:
		return int64(t)
	case int64:
		return t
	case json.Number:
		v, err := t.Int64()
		if err == nil {
			return v
		}
		vf, err := t.Float64()
		if err != nil {
			return 0
		}
		return int64(vf)
	}
	return 0
}

// SafeMap converts a map entry to a map[string]any if possible
func (m Map) SafeMap(key string, def map[string]any) map[string]any {
	if m == nil {
		return def
	}

	mval, ok := m[key]
	if !ok {
		return def
	}

	val, ok := mval.(map[string]any)
	if !ok {
		return def
	}

	return val
}

// SafeJWKS convert a map entry to *jose.JSONWebKeySet object if possible, otherwise return nil
func (m Map) SafeJWKS(key string) *jose.JSONWebKeySet {
	if m == nil {
		return nil
	}

	mval, ok := m[key]
	if !ok {
		return nil
	}

	// We cannot just cast it, the approach we take is to marshal and unmarshal
	sval, err := json.Marshal(mval)
	if err != nil {
		return nil
	}

	val := &jose.JSONWebKeySet{}
	if err = json.Unmarshal(sval, val); err != nil {
		return nil
	}

	return val
}
