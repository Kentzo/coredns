//go:build ignore
package push_test

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin/dso/internal/push"
	"github.com/coredns/coredns/plugin/dso/internal/testutil"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

func TestZoneAuthorization(t *testing.T) {
	opts := testutil.DefaultPushOpts
	opts.Zones = []string{"a.test."}
	handler := push.New(opts)
	sesh := testutil.SetupEstablishedSession(t, &dnsserver.Server{}, nil)

	m := testutil.NewPushSubMsg(1, "b.test.", dns.TypeA, dns.ClassINET)
	gotRcode := handler.ServeDSO(sesh.Session, sesh.W, m)
	if gotRcode != dns.RcodeNotAuth {
		t.Errorf("Expected RcodeNotAuth, got %v", gotRcode)
	}
}

func TestSubscribe(t *testing.T) {
	t.Parallel()

	server, mapPlugin := testutil.SetupStubServer(t)
	handler := push.New(testutil.DefaultPushOpts)
	sesh := testutil.SetupEstablishedSession(t, server, nil)

	m := testutil.NewPushSubMsg(1, "test.", dns.TypeA, dns.ClassINET)
	testutil.AssertPushSubscribe(t, handler, sesh, m)
	testutil.AssertNoMsg(t, sesh)

	mapPlugin.Answers.SetRR(
		testutil.NewRRf("test. IN A 192.0.2.1"),
	)
	testutil.AssertPushUpdateMsg(t, sesh,
		testutil.NewRRf("test. IN A 192.0.2.1"),
	)
}

func TestUnsubscribe(t *testing.T) {
	t.Parallel()

	server, mapPlugin := testutil.SetupStubServer(t)
	handler := push.New(testutil.DefaultPushOpts)
	sesh := testutil.SetupEstablishedSession(t, server, nil)

	m := testutil.NewPushSubMsg(1, "test.", dns.TypeA, dns.ClassINET)
	testutil.AssertPushSubscribe(t, handler, sesh, m)

	m = testutil.NewPushUnsubMsg(1)
	testutil.AssertPushUnsubscribe(t, handler, sesh, m)

	mapPlugin.Answers.SetRR(
		testutil.NewRRf("test. IN A 192.0.2.2"),
	)
	testutil.AssertNoMsg(t, sesh)
}

func TestReconfirm(t *testing.T) {
	t.Parallel()

	server, mapPlugin := testutil.SetupStubServer(t)
	opts := testutil.DefaultPushOpts
	opts.RefreshInterval = 0
	handler := push.New(opts)
	sesh := testutil.SetupEstablishedSession(t, server, nil)

	// No Record
	m := testutil.NewPushSubMsg(1, "test.", dns.TypeA, dns.ClassINET)
	testutil.AssertPushSubscribe(t, handler, sesh, m)
	testutil.AssertNoMsg(t, sesh)

	m = testutil.NewPushReconfirmMsg(testutil.NewRRf("test. IN A 192.0.2.1"))
	testutil.AssertPushReconfirm(t, handler, sesh, m)
	testutil.AssertNoMsg(t, sesh)

	// Add Record
	mapPlugin.Answers.SetRR(
		testutil.NewRRf("test. IN A 192.0.2.1"),
	)
	m = testutil.NewPushReconfirmMsg(testutil.NewRRf("test. IN A 192.0.2.100"))
	testutil.AssertPushReconfirm(t, handler, sesh, m)
	testutil.AssertPushUpdateMsg(t, sesh,
		testutil.NewRRf("test. IN A 192.0.2.1"),
	)

	// Same Record
	m = testutil.NewPushReconfirmMsg(testutil.NewRRf("test. IN A 192.0.2.100"))
	testutil.AssertPushReconfirm(t, handler, sesh, m)
	testutil.AssertNoMsg(t, sesh)

	// Update Record
	mapPlugin.Answers.SetRR(
		testutil.NewRRf("test. IN A 192.0.2.2"),
	)
	m = testutil.NewPushReconfirmMsg(testutil.NewRRf("test. IN A 192.0.2.100"))
	testutil.AssertPushReconfirm(t, handler, sesh, m)
	testutil.AssertPushUpdateMsg(t, sesh,
		testutil.NewRRf("test. %d IN A 192.0.2.1", dns.DSOPushTTLRemove),
		testutil.NewRRf("test. IN A 192.0.2.2"),
	)

	// Remove Record
	mapPlugin.Answers.Clear()
	m = testutil.NewPushReconfirmMsg(testutil.NewRRf("test. IN A 192.0.2.100"))
	testutil.AssertPushReconfirm(t, handler, sesh, m)
	testutil.AssertPushUpdateMsg(t, sesh,
		testutil.NewRRf("test. %d IN A 192.0.2.2", dns.DSOPushTTLRemove),
	)
}

func TestUpdate(t *testing.T) {
	t.Parallel()

	server, mapPlugin := testutil.SetupStubServer(t)
	handler := push.New(testutil.DefaultPushOpts)
	sesh := testutil.SetupEstablishedSession(t, server, nil)

	// Subscribe
	m := testutil.NewPushSubMsg(1, "test.", dns.TypeA, dns.ClassINET)
	testutil.AssertPushSubscribe(t, handler, sesh, m)

	mapPlugin.Answers.SetRR(
		testutil.NewRRf("test. IN A 192.0.2.1"),
	)
	testutil.AssertPushUpdateMsg(t, sesh,
		testutil.NewRRf("test. IN A 192.0.2.1"),
	)

	// Replace
	mapPlugin.Answers.SetRR(
		testutil.NewRRf("test. IN A 192.0.2.2"),
		testutil.NewRRf("test. IN A 192.0.2.3"),
		testutil.NewRRf("test. IN A 192.0.2.4"),
	)
	testutil.AssertPushUpdateMsg(t, sesh,
		testutil.NewRRf("test. %d IN A 192.0.2.1", dns.DSOPushTTLRemove),
		testutil.NewRRf("test. IN A 192.0.2.2"),
		testutil.NewRRf("test. IN A 192.0.2.3"),
		testutil.NewRRf("test. IN A 192.0.2.4"),
	)

	// Update
	mapPlugin.Answers.SetRR(
		testutil.NewRRf("test. IN A 192.0.2.2"),
		testutil.NewRRf("test. IN A 192.0.2.3"),
		testutil.NewRRf("test. IN A 192.0.2.5"),
	)
	testutil.AssertPushUpdateMsg(t, sesh,
		testutil.NewRRf("test. %d IN A 192.0.2.4", dns.DSOPushTTLRemove),
		testutil.NewRRf("test. IN A 192.0.2.5"),
	)

	// Delete
	mapPlugin.Answers.SetRR(
		testutil.NewRRf("test. IN A 192.0.2.2"),
		testutil.NewRRf("test. IN A 192.0.2.5"),
	)
	testutil.AssertPushUpdateMsg(t, sesh,
		testutil.NewRRf("test. %d IN A 192.0.2.3", dns.DSOPushTTLRemove),
	)

	// Clear
	mapPlugin.Answers.Clear()
	testutil.AssertPushUpdateMsg(t, sesh,
		testutil.NewRRf("test. %d IN A 192.0.2.2", dns.DSOPushTTLRemove),
		testutil.NewRRf("test. %d IN A 192.0.2.5", dns.DSOPushTTLRemove),
	)
}

func TestWildcardUpdate(t *testing.T) {
	t.Parallel()

	server, mapPlugin := testutil.SetupStubServer(t)
	handler := push.New(testutil.DefaultPushOpts)
	handler.Opts.RefreshInterval = 0
	sesh := testutil.SetupEstablishedSession(t, server, nil)

	// Subscribe
	m := testutil.NewPushSubMsg(1, "test.", dns.TypeA, dns.ClassINET)
	testutil.AssertPushSubscribe(t, handler, sesh, m)

	m = testutil.NewPushSubMsg(2, "test.", dns.TypeANY, dns.ClassANY)
	testutil.AssertPushSubscribe(t, handler, sesh, m)

	mapPlugin.Answers.SetRR(
		testutil.NewRRf("test. IN A 192.0.2.1"),
		testutil.NewRRf("test. IN AAAA 2001:db8::1"),
	)
	handler.Refresh()
	testutil.AssertPushUpdateMsg(t, sesh,
		testutil.NewRRf("test. IN A 192.0.2.1"),
		testutil.NewRRf("test. IN AAAA 2001:db8::1"),
	)

	// Replace
	mapPlugin.Answers.SetRR(
		testutil.NewRRf("test. IN A 192.0.2.2"),
		testutil.NewRRf("test. IN A 192.0.2.3"),
		testutil.NewRRf("test. IN A 192.0.2.4"),
		testutil.NewRRf("test. IN AAAA 2001:db8::2"),
		testutil.NewRRf("test. IN AAAA 2001:db8::3"),
		testutil.NewRRf("test. IN AAAA 2001:db8::4"),
	)
	handler.Refresh()
	testutil.AssertPushUpdateMsg(t, sesh,
		testutil.NewRRf("test. %d IN A 192.0.2.1", dns.DSOPushTTLRemove),
		testutil.NewRRf("test. %d IN AAAA 2001:db8::1", dns.DSOPushTTLRemove),
		testutil.NewRRf("test. IN A 192.0.2.2"),
		testutil.NewRRf("test. IN A 192.0.2.3"),
		testutil.NewRRf("test. IN A 192.0.2.4"),
		testutil.NewRRf("test. IN AAAA 2001:db8::2"),
		testutil.NewRRf("test. IN AAAA 2001:db8::3"),
		testutil.NewRRf("test. IN AAAA 2001:db8::4"),
	)

	// Update
	mapPlugin.Answers.SetRR(
		testutil.NewRRf("test. IN A 192.0.2.2"),
		testutil.NewRRf("test. IN A 192.0.2.3"),
		testutil.NewRRf("test. IN A 192.0.2.5"),
		testutil.NewRRf("test. IN AAAA 2001:db8::2"),
		testutil.NewRRf("test. IN AAAA 2001:db8::3"),
		testutil.NewRRf("test. IN AAAA 2001:db8::5"),
	)
	handler.Refresh()
	testutil.AssertPushUpdateMsg(t, sesh,
		testutil.NewRRf("test. %d IN A 192.0.2.4", dns.DSOPushTTLRemove),
		testutil.NewRRf("test. %d IN AAAA 2001:db8::4", dns.DSOPushTTLRemove),
		testutil.NewRRf("test. IN A 192.0.2.5"),
		testutil.NewRRf("test. IN AAAA 2001:db8::5"),
	)

	// Delete
	mapPlugin.Answers.SetRR(
		testutil.NewRRf("test. IN A 192.0.2.2"),
		testutil.NewRRf("test. IN A 192.0.2.5"),
		testutil.NewRRf("test. IN AAAA 2001:db8::2"),
		testutil.NewRRf("test. IN AAAA 2001:db8::5"),
	)
	handler.Refresh()
	testutil.AssertPushUpdateMsg(t, sesh,
		testutil.NewRRf("test. %d IN A 192.0.2.3", dns.DSOPushTTLRemove),
		testutil.NewRRf("test. %d IN AAAA 2001:db8::3", dns.DSOPushTTLRemove),
	)

	// Clear
	mapPlugin.Answers.Clear()
	handler.Refresh()
	testutil.AssertPushUpdateMsg(t, sesh,
		testutil.NewRRf("test. %d IN A 192.0.2.2", dns.DSOPushTTLRemove),
		testutil.NewRRf("test. %d IN A 192.0.2.5", dns.DSOPushTTLRemove),
		testutil.NewRRf("test. %d IN AAAA 2001:db8::2", dns.DSOPushTTLRemove),
		testutil.NewRRf("test. %d IN AAAA 2001:db8::5", dns.DSOPushTTLRemove),
	)

	// Unsubscribe
	m = testutil.NewPushUnsubMsg(2)
	testutil.AssertPushUnsubscribe(t, handler, sesh, m)

	mapPlugin.Answers.SetRR(
		testutil.NewRRf("test. IN A 192.0.2.1"),
		testutil.NewRRf("test. IN AAAA 2001:db8::1"),
	)
	handler.Refresh()
	testutil.AssertPushUpdateMsg(t, sesh,
		testutil.NewRRf("test. IN A 192.0.2.1"),
	)
}

func TestUpdateAny(t *testing.T) {
	t.Parallel()

	server, mapPlugin := testutil.SetupStubServer(t)
	handler := push.New(testutil.DefaultPushOpts)
	handler.Opts.RefreshInterval = 0
	handler.Opts.AnyTypes = []uint16{dns.TypeA}
	handler.Opts.AnyClasses = []uint16{dns.ClassINET}
	sesh := testutil.SetupEstablishedSession(t, server, nil)

	m := testutil.NewPushSubMsg(1, "a.test.", dns.TypeANY, dns.ClassANY)
	testutil.AssertPushSubscribe(t, handler, sesh, m)

	mapPlugin.Answers.SetRR(
		testutil.NewRRf("a.test. IN AAAA 2001:db8::1"),
		testutil.NewRRf("a.test. CH AAAA 2001:db8::1"),
	)
	handler.Refresh()
	testutil.AssertNoMsg(t, sesh)

	m = testutil.NewPushSubMsg(2, "b.test.", dns.TypeAAAA, dns.ClassINET)
	testutil.AssertPushSubscribe(t, handler, sesh, m)
	handler.Refresh()
	testutil.AssertPushUpdateMsg(t, sesh,
		testutil.NewRRf("a.test. IN AAAA 2001:db8::1"),
	)
}

func TestSubscribeAfterClose(t *testing.T) {
	t.Parallel()

	server, mapPlugin := testutil.SetupStubServer(t)
	handler := push.New(testutil.DefaultPushOpts)
	sesh := testutil.SetupEstablishedSession(t, server, nil)

	m := testutil.NewPushSubMsg(1, "a.test.", dns.TypeA, dns.ClassINET)
	testutil.AssertPushSubscribe(t, handler, sesh, m)

	mapPlugin.Answers.SetRR(
		testutil.NewRRf("a.test. IN A 192.0.2.1"),
	)
	testutil.AssertPushUpdateMsg(t, sesh,
		testutil.NewRRf("a.test. IN A 192.0.2.1"),
	)

	sesh.SetClosed()
	testutil.AssertSessionClosed(t, sesh)
	testutil.AssertNoMsg(t, sesh)

	m = testutil.NewPushSubMsg(2, "b.test.", dns.TypeA, dns.ClassINET)
	gotRcode := handler.ServeDSO(sesh.Session, sesh.W, m)
	if gotRcode != dns.RcodeServerFailure {
		t.Errorf("Expected RcodeServerFailure, got %v", gotRcode)
	}
}

func TestDuplicateSubscribe(t *testing.T) {
	t.Parallel()

	tcs := []struct {
		name string
		m1   *dns.Msg
		m2   *dns.Msg
	}{
		{"ID", testutil.NewPushSubMsg(1, "test.", dns.TypeA, dns.ClassINET), testutil.NewPushSubMsg(1, "test.", dns.TypeAAAA, dns.ClassINET)},
		{"TLV", testutil.NewPushSubMsg(1, "test.", dns.TypeA, dns.ClassINET), testutil.NewPushSubMsg(2, "test.", dns.TypeA, dns.ClassINET)},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			handler := push.New(testutil.DefaultPushOpts)
			sesh := testutil.SetupEstablishedSession(t, &dnsserver.Server{}, nil)

			handler.ServeDSO(sesh.Session, sesh.W, tc.m1)
			gotRcode := handler.ServeDSO(sesh.Session, sesh.W, tc.m2)
			if gotRcode != dns.RcodeServerFailure {
				t.Errorf("Expected RcodeServerFailure, got %v", gotRcode)
			}
		})
	}
}

func TestDuplicateUnsubscribe(t *testing.T) {
	t.Parallel()

	handler := push.New(testutil.DefaultPushOpts)
	sesh := testutil.SetupEstablishedSession(t, &dnsserver.Server{}, nil)
	question := dns.Question{Name: "test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

	m := testutil.NewPushSubMsg(1, question.Name, question.Qtype, question.Qclass)
	testutil.AssertPushSubscribe(t, handler, sesh, m)

	m = testutil.NewPushUnsubMsg(1)
	testutil.AssertPushUnsubscribe(t, handler, sesh, m)
	testutil.AssertNoMsg(t, sesh)

	m = testutil.NewPushUnsubMsg(1)
	testutil.AssertPushUnsubscribe(t, handler, sesh, m)
	testutil.AssertNoMsg(t, sesh)
}

func TestReplySubscribeBeforeUpdate(t *testing.T) {
	t.Parallel()

	server, mapPlugin := testutil.SetupStubServer(t)
	handler := push.New(testutil.DefaultPushOpts)
	handler.Opts.RefreshInterval = 0
	sesh := testutil.SetupEstablishedSession(t, server, nil)
	w := sesh.W.(*testutil.HookableWriter)

	m := testutil.NewPushSubMsg(1, "a.test.", dns.TypeA, dns.ClassINET)
	testutil.AssertPushSubscribe(t, handler, sesh, m)

	mapPlugin.Answers.SetRR(
		test.A("b.test. IN A 192.0.2.1"),
	)

	h := w.Hook(2, true)
	go func() {
		m = testutil.NewPushSubMsg(2, "b.test.", dns.TypeA, dns.ClassINET)
		handler.ServeDSO(sesh.Session, w, m)
	}()
	<-h.OnEnterC
	testutil.AssertNoMsg(t, sesh)

	close(h.WriteC)
	gotM := testutil.AssertAnyMsg(t, sesh)
	if !dns.IsDSOResponse(gotM) || gotM.Id != 2 {
		t.Errorf("Expected subscription response, got %v", gotM)
	}

	testutil.AssertPushUpdateMsg(t, sesh,
		testutil.NewRRf("b.test. IN A 192.0.2.1"),
	)
}

func TestUpdateAfterResubscribe(t *testing.T) {
	t.Parallel()

	server, mapPlugin := testutil.SetupStubServer(t)
	handler := push.New(testutil.DefaultPushOpts)
	handler.Opts.RefreshInterval = 0
	sesh := testutil.SetupEstablishedSession(t, server, nil)

	mapPlugin.Answers.SetRR(
		testutil.NewRRf("test. IN A 192.0.2.1"),
	)

	subM := testutil.NewPushSubMsg(1, "test.", dns.TypeA, dns.ClassINET)
	testutil.AssertPushSubscribe(t, handler, sesh, subM)
	testutil.AssertPushUpdateMsg(t, sesh,
		testutil.NewRRf("test. IN A 192.0.2.1"),
	)

	unsubM := testutil.NewPushUnsubMsg(subM.Id)
	testutil.AssertPushUnsubscribe(t, handler, sesh, unsubM)

	testutil.AssertPushSubscribe(t, handler, sesh, subM)
	testutil.AssertPushUpdateMsg(t, sesh,
		testutil.NewRRf("test. IN A 192.0.2.1"),
	)
}

func TestManualRefresh(t *testing.T) {
	t.Parallel()

	server, mapPlugin := testutil.SetupStubServer(t)
	handler := push.New(testutil.DefaultPushOpts)
	handler.Opts.RefreshInterval = 0
	sesh := testutil.SetupEstablishedSession(t, server, nil)

	m := testutil.NewPushSubMsg(1, "test.", dns.TypeA, dns.ClassINET)
	testutil.AssertPushSubscribe(t, handler, sesh, m)
	testutil.AssertNoMsg(t, sesh)

	mapPlugin.Answers.SetRR(
		testutil.NewRRf("test. IN A 192.0.2.1"),
	)
	handler.Refresh()
	testutil.AssertPushUpdateMsg(t, sesh,
		testutil.NewRRf("test. IN A 192.0.2.1"),
	)
}

func TestDebounce(t *testing.T) {
	t.Parallel()

	server, mapPlugin := testutil.SetupStubServer(t)
	handler := push.New(testutil.DefaultPushOpts)
	handler.Opts.DebounceDelay = 5 * testutil.NoMessageTimeout
	handler.Opts.RefreshInterval = 0
	sesh := testutil.SetupEstablishedSession(t, server, nil)

	wantAnswer := []dns.RR{
		testutil.NewRRf("a.test. IN A 192.0.2.1"),
		testutil.NewRRf("b.test. IN A 192.0.2.1"),
		testutil.NewRRf("c.test. IN A 192.0.2.1"),
		testutil.NewRRf("d.test. IN A 192.0.2.1"),
		testutil.NewRRf("e.test. IN A 192.0.2.1"),
	}

	mapPlugin.Answers.SetRR(wantAnswer...)
	for i, rr := range wantAnswer {
		m := testutil.NewPushSubMsg(uint16(i+1), rr.Header().Name, rr.Header().Rrtype, rr.Header().Class)
		testutil.AssertPushSubscribe(t, handler, sesh, m)
	}
	testutil.AssertNoMsg(t, sesh)

	time.Sleep(handler.Opts.DebounceDelay)
	testutil.AssertPushUpdateMsg(t, sesh, wantAnswer...)
}

func TestCNAME(t *testing.T) {
	t.Parallel()

	server, mapPlugin := testutil.SetupStubServer(t)
	handler := push.New(testutil.DefaultPushOpts)
	sesh := testutil.SetupEstablishedSession(t, server, nil)

	mapPlugin.Answers.SetQ(dns.Question{Name: "a.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		testutil.NewRRf("a.test. IN CNAME b.test."),
		testutil.NewRRf("b.test. IN A 192.0.2.1"),
		testutil.NewRRf("b.test. IN A 192.0.2.2"),
		testutil.NewRRf("b.test. IN A 192.0.2.3"),
	)
	m := testutil.NewPushSubMsg(1, "a.test.", dns.TypeA, dns.ClassINET)
	testutil.AssertPushSubscribe(t, handler, sesh, m)
	testutil.AssertPushUpdateMsg(t, sesh,
		testutil.NewRRf("a.test. IN CNAME b.test."),
	)
}

func TestClosingSession(t *testing.T) {
	t.Parallel()

	handler := push.New(testutil.DefaultPushOpts)
	sesh := testutil.SetupEstablishedSession(t, &dnsserver.Server{}, nil)

	m := testutil.NewPushSubMsg(1, "test.", dns.TypeA, dns.ClassINET)
	testutil.AssertPushSubscribe(t, handler, sesh, m)

	sesh.Close(nil, 0, dns.RcodeSuccess)
	<-time.After(testutil.NoMessageTimeout)
	if len(handler.Subs) != 0 {
		t.Errorf("Expected no subscribers, got %v", handler.Subs)
	}
}

func TestExpandSubscribeTLV(t *testing.T) {
	t.Parallel()

	anyTypes := []uint16{dns.TypeA, dns.TypeAAAA}
	anyClasses := []uint16{dns.ClassINET, dns.ClassCHAOS}

	tcs := []struct {
		name string
		tlv  dns.DSOSubscribe
		want []dns.DSOSubscribe
	}{
		{"Neither", dns.DSOSubscribe{Name: "test.", Rrtype: dns.TypeA, Class: dns.ClassINET}, []dns.DSOSubscribe{
			{Name: "test.", Rrtype: dns.TypeA, Class: dns.ClassINET},
		}},
		{"Type", dns.DSOSubscribe{Name: "test.", Rrtype: dns.TypeANY, Class: dns.ClassINET}, []dns.DSOSubscribe{
			{Name: "test.", Rrtype: dns.TypeA, Class: dns.ClassINET},
			{Name: "test.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET}},
		},
		{"Class", dns.DSOSubscribe{Name: "test.", Rrtype: dns.TypeA, Class: dns.ClassANY}, []dns.DSOSubscribe{
			{Name: "test.", Rrtype: dns.TypeA, Class: dns.ClassINET},
			{Name: "test.", Rrtype: dns.TypeA, Class: dns.ClassCHAOS},
		}},
		{"Both", dns.DSOSubscribe{Name: "test.", Rrtype: dns.TypeANY, Class: dns.ClassANY}, []dns.DSOSubscribe{
			{Name: "test.", Rrtype: dns.TypeA, Class: dns.ClassINET},
			{Name: "test.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET},
			{Name: "test.", Rrtype: dns.TypeA, Class: dns.ClassCHAOS},
			{Name: "test.", Rrtype: dns.TypeAAAA, Class: dns.ClassCHAOS},
		}},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := slices.Collect(push.ExpandSubscribeTLV(tc.tlv, anyClasses, anyTypes))
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Expected %v, got %v", tc.want, got)
			}
		})
	}
}

func TestSplitPushMsg(t *testing.T) {
	t.Parallel()

	// Each template results in RR of size 1169. This size is special: 1169 * 14 + 12 + 4 = DSOPushLenMax
	template := `%02d.test 10 IN TXT "` + strings.Repeat("T", 1145) + `"`

	tcs := []struct {
		name          string
		repeatRR      int
		wantMsgsCount int
	}{
		{"Below", 13, 1},
		{"At", 14, 1},
		{"Above", 15, 2},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var (
				wantRRs []dns.RR
				gotRRs  []dns.RR
				gotMsgs []*dns.Msg
			)

			m := new(dns.Msg)
			dns.SetDSOUnidirectional(m)
			tlv := &dns.DSOPush{}
			m.Stateful = append(m.Stateful, tlv)
			for i := range tc.repeatRR {
				rr := test.TXT(fmt.Sprintf(template, i))
				tlv.Change = append(tlv.Change, rr)
				wantRRs = append(wantRRs, rr)
			}

			for m := range push.SplitPushMsg(m) {
				gotMsgs = append(gotMsgs, m.Copy())
			}

			if len(gotMsgs) != tc.wantMsgsCount {
				t.Fatalf("Expected %d messages, got %d", tc.wantMsgsCount, len(gotMsgs))
			}

			for _, m := range gotMsgs {
				gotRRs = append(gotRRs, m.Stateful[0].(*dns.DSOPush).Change...)
			}
			for i := range wantRRs {
				if !dns.IsDuplicate(wantRRs[i], gotRRs[i]) {
					t.Fatalf("Expected %v, got %v", wantRRs, gotRRs)
				}
			}
		})
	}
}
