package main

// zone_index.go contains helpers for building and querying an index of zone
// names and record types. The index is used when constructing DNSSEC records
// such as NSEC to describe which names and types exist in a zone.

import (
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// canonicalLess compares two domain names using the DNSSEC canonical
// ordering as defined in RFC4034 §6.1. Labels are compared
// case-insensitively from right to left. The shorter name sorts first
// when all compared labels are equal.
func canonicalLess(a, b string) bool {
	a = strings.ToLower(ensureDot(a))
	b = strings.ToLower(ensureDot(b))
	a = strings.TrimSuffix(a, ".")
	b = strings.TrimSuffix(b, ".")
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	for i, j := len(as)-1, len(bs)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if as[i] == bs[j] {
			continue
		}
		return as[i] < bs[j]
	}
	return len(as) < len(bs)
}





// hasName reports whether owner exists in the zone index.




// successor returns the index of the smallest element in names that is
// canonically greater than q. The result wraps to 0 if q is greater than all
// names.
func successor(names []string, q string) int {
	i := sort.Search(len(names), func(i int) bool { return canonicalLess(q, names[i]) })
	return i % len(names)
}

// predecessor returns the index of the largest element in names that is
// canonically less than q. The result wraps to the last index if q is less than
// or equal to the first name.
func predecessor(names []string, q string) int {
	i := sort.Search(len(names), func(i int) bool { return !canonicalLess(names[i], q) })
	if i == 0 {
		return len(names) - 1
	}
	return i - 1
}

// nextName returns the next owner name in canonical order. If owner doesn't
// exist in the zone, the next existing name after owner is returned, wrapping
// around to the first name.
func (z *zoneIndex) nextName(owner string) string {
	owner = strings.ToLower(ensureDot(owner))
	if len(z.names) == 0 {
		return owner
	}
	return z.names[successor(z.names, owner)]
}



// typeBitmap returns the type bitmap for the given owner.
func (z *zoneIndex) typeBitmap(owner string) []uint16 {
	owner = strings.ToLower(ensureDot(owner))
	m := z.types[owner]
	if m == nil {
		return nil
	}
	var out []uint16
	for t := range m {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}


