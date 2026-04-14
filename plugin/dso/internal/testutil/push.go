//go:build ignore
package testutil

import (
	"fmt"
	"strings"
	"testing"

	"github.com/coredns/coredns/plugin/dso/internal/push"
	"github.com/miekg/dns"
)

func NewPushSubMsg(id uint16, name string, ty, cl uint16) *dns.Msg {
	m := new(dns.Msg)
	dns.SetDSORequest(m, id)
	m.Stateful = append(m.Stateful, &dns.DSOSubscribe{Name: name, Rrtype: ty, Class: cl})
	return m
}

func NewPushUnsubMsg(subId uint16) *dns.Msg {
	m := new(dns.Msg)
	dns.SetDSOUnidirectional(m)
	m.Stateful = append(m.Stateful, &dns.DSOUnsubscribe{SubscribeId: subId})
	return m
}

func NewPushReconfirmMsg(rr dns.RR) *dns.Msg {
	m := new(dns.Msg)
	dns.SetDSOUnidirectional(m)
	m.Stateful = append(m.Stateful, &dns.DSOReconfirm{Rr: rr})
	return m
}

func AssertPushSubscribe(tb testing.TB, push *push.Handler, sesh *HookableSession, m *dns.Msg) {
	tb.Helper()

	gotRcode := push.ServeDSO(sesh.Session, sesh.W, m)
	if gotRcode != dns.RcodeSuccess {
		tb.Fatalf("Expected subscribe, got %v", gotRcode)
	}

	gotM := AssertAnyMsg(tb, sesh)
	if !dns.IsDSOResponse(gotM) {
		tb.Fatalf("Expected DSO Response, got %v", gotM)
	}
	if gotM.Id != m.Id {
		tb.Errorf("Expected ID %v, got %v", m.Id, gotM.Id)
	}
	if gotM.Rcode != dns.RcodeSuccess {
		tb.Errorf("Expected RcodeSuccess, got %v", gotM.Rcode)
	}
}

func AssertPushUnsubscribe(tb testing.TB, push *push.Handler, sesh *HookableSession, m *dns.Msg) {
	tb.Helper()

	gotRcode := push.ServeDSO(sesh.Session, sesh.W, m)
	if gotRcode != dns.RcodeSuccess {
		tb.Fatalf("Expected unsubscribe, got %v", gotRcode)
	}
	AssertNoMsg(tb, sesh)
}

func AssertPushReconfirm(tb testing.TB, push *push.Handler, sesh *HookableSession, m *dns.Msg) {
	tb.Helper()

	gotRcode := push.ServeDSO(sesh.Session, sesh.W, m)
	if gotRcode != dns.RcodeSuccess {
		tb.Fatalf("Expected reconfirm, got %v", gotRcode)
	}
}

func AssertPushUpdateMsg(tb testing.TB, sesh *HookableSession, wantChange ...dns.RR) *dns.Msg {
	tb.Helper()

	gotM := AssertAnyMsg(tb, sesh)
	if !dns.IsDSOUnidirectional(gotM) {
		tb.Fatalf("Expected DSO Unidirectional, got %v", gotM)
	}
	tlv, ok := gotM.Stateful[0].(*dns.DSOPush)
	if !ok {
		tb.Fatalf("Expected Push TLV, got %v", gotM.Stateful)
	}

	seenGot := make([]bool, len(tlv.Change))
	seenWant := make([]bool, len(wantChange))
	for gotI, gotRR := range tlv.Change {
		for wantI, wantRR := range wantChange {
			if !seenWant[wantI] && dns.IsDuplicate(gotRR, wantRR) && gotRR.Header().Ttl == wantRR.Header().Header().Ttl {
				seenGot[gotI] = true
				seenWant[wantI] = true
				break
			}
		}
	}
	var b strings.Builder
	for i, gotRR := range tlv.Change {
		if !seenGot[i] {
			fmt.Fprintf(&b, "  - %v\n", gotRR)
		}
	}
	for i, wantRR := range wantChange {
		if !seenWant[i] {
			fmt.Fprintf(&b, "  + %v\n", wantRR)
		}
	}
	if b.Len() > 0 {
		tb.Fatalf("Update mimsatch:\n%s", b.String())
	}
	return gotM
}

func NewRRf(format string, a ...any) dns.RR {
	r, err := dns.NewRR(fmt.Sprintf(format, a...))
	if r == nil {
		panic(err)
	}
	return r
}

var DefaultPushOpts = push.Opts{
	Zones:           []string{"."},
	AnyTypes:        []uint16{dns.TypeA, dns.TypeAAAA},
	AnyClasses:      []uint16{dns.ClassINET},
	RefreshInterval: NoMessageTimeout / 10,
	DebounceDelay:   0,
}
