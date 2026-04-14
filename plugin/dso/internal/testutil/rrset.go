package testutil

import (
	"slices"

	"github.com/miekg/dns"
)

func ContainsRR(rrs []dns.RR, rr dns.RR) bool {
	return slices.ContainsFunc(rrs, func(rr1 dns.RR) bool {
		return dns.IsDuplicate(rr, rr1)
	})
}

func DeleteRR(rrs []dns.RR, rr dns.RR) []dns.RR {
	return slices.DeleteFunc(rrs, func(rr1 dns.RR) bool {
		return dns.IsDuplicate(rr, rr1)
	})
}

func AppendRRSet(dst []dns.RR, rrs ...dns.RR) []dns.RR {
	for i := range rrs {
		dst = append(dst, dns.Copy(rrs[i]))
	}
	return dst
}

func CloneRRSet(rrs []dns.RR) []dns.RR {
	if rrs == nil {
		return nil
	}
	return AppendRRSet(make([]dns.RR, 0, len(rrs)), rrs...)
}
