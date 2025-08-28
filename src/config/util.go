package config

import "strings"

// EnsureDot appends a trailing dot to s if missing.
func EnsureDot(s string) string {
	if s == "" {
		return "."
	}
	if strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}

// IPsFrom extracts plain strings from a slice of IPAddr.
func IPsFrom(list []IPAddr) []string {
	out := make([]string, 0, len(list))
	for _, a := range list {
		if a.IP != "" {
			out = append(out, a.IP)
		}
	}
	return out
}
