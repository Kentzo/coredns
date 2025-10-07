package dso

import (
	"context"
	"strconv"
	"strings"

	"github.com/coredns/coredns/plugin/metadata"
	"github.com/coredns/coredns/plugin/pkg/replacer"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

var labels = map[string]func(*dns.Msg) string{
	"{/dso/rcode}":   metadataDSORcode,
	"{/dso/type}":    metadataDSOType,
	"{/dso/tlvtype}": metadataDSOTLVType,
	"{/dso/tlvs}":    metadataDSOTLVs,
}

func metadataDSORcode(m *dns.Msg) string {
	if rcode := dns.RcodeToString[m.Rcode]; rcode != "" {
		return rcode
	}
	return strconv.Itoa(m.Rcode)
}

func metadataDSOType(m *dns.Msg) string {
	switch {
	case dns.IsDSORequest(m):
		return "REQ"
	case dns.IsDSOUnidirectional(m):
		return "UNI"
	case dns.IsDSOResponse(m):
		return "REP"
	default:
		return "BAD"
	}
}

func metadataDSOTLVType(m *dns.Msg) string {
	if len(m.Stateful) == 0 {
		return replacer.EmptyValue
	}
	return dns.DSOType(m.Stateful[0].DSOType()).String()
}

func metadataDSOTLVs(m *dns.Msg) string {
	if len(m.Stateful) == 0 {
		return replacer.EmptyValue
	}

	names := make([]string, len(m.Stateful))
	values := make([]string, len(m.Stateful))
	maxNameLen := 0
	for i, t := range m.Stateful {
		names[i] = dns.DSOType(t.DSOType()).String()
		v := t.String()
		if strings.Contains(v, "\n") {
			v = "\n" + v
		}
		values[i] = v
		maxNameLen = max(maxNameLen, len(names[i]))
	}

	s := ""
	for i, n := range names {
		s += "\n" + strings.Repeat(" ", maxNameLen-len(n)) + n + ": "
		s += values[i]
	}
	return s
}

func (d *DSO) Metadata(ctx context.Context, state request.Request) context.Context {
	if state.Req.Opcode != dns.OpcodeStateful {
		return ctx
	}
	for l, f := range labels {
		metadata.SetValueFunc(ctx, l[1:len(l)-1], func() string {
			return f(state.Req)
		})
	}
	return ctx
}
