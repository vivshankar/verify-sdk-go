// Package types extends Go types
package types

import "strings"

const replacement = ""

var newlineReplacer = strings.NewReplacer(
	"\r\n", replacement,
	"\r", replacement,
	"\n", replacement,
	"\v", replacement,
	"\f", replacement,
	"\u0085", replacement,
	"\u2028", replacement,
	"\u2029", replacement,
)

// String converts an interface to string
func String(obj any) string {
	result := ""
	if x, ok := obj.(string); ok {
		result = x
	}
	return result
}

func RemoveNewline(str string) string {
	return newlineReplacer.Replace(str)
}
