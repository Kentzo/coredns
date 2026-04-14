//go:build ignore

package testutil

import (
	"testing"
	"time"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin/dso/internal/session"
	"github.com/miekg/dns"
)

type HookableSession struct {
	*session.Session
}

func (s *HookableSession) ReadMsg() (*dns.Msg, bool) {
	return s.W.(*HookableWriter).ReadMsg()
}

func (s *HookableSession) ReadMsgWithTimeout(timeout time.Duration) (*dns.Msg, bool) {
	return s.W.(*HookableWriter).ReadMsgWithTimeout(timeout)
}

func (s *HookableSession) AsyncWriteMsg(m *dns.Msg) (done <-chan error) {
	d := make(chan error, 1)
	go func() {
		d <- s.WriteMsg(nil, m)
		close(d)
	}()
	return d
}

func (s *HookableSession) HookWriteMsg(m *dns.Msg) (h WriteHook, done <-chan error) {
	h = s.W.(*HookableWriter).Hook(m.Id, m.Response)
	d := s.AsyncWriteMsg(m)
	return h, d
}

// SetupSession makes a session that writes to conn. If conn is nil, StubConn is used.
func SetupSession(tb testing.TB, server *dnsserver.Server, conn session.LingerConn) *HookableSession {
	tb.Helper()

	w := NewHookableWriter()

	if conn == nil {
		conn = StubConn{
			local:  w.LocalAddr(),
			remote: w.RemoteAddr(),
		}
	}
	w.tcp = conn
	sesh := &HookableSession{session.NewWithID(w, session.NewIDWithConn(server, conn))}
	tb.Cleanup(func() {
		sesh.SetClosed()
	})
	return sesh
}

func SetupWaitingSession(tb testing.TB, server *dnsserver.Server, conn session.LingerConn) *HookableSession {
	tb.Helper()

	sesh := SetupSession(tb, server, conn)
	AssertSessionWaiting(tb, sesh)
	return sesh
}

func SetupPendingSession(tb testing.TB, server *dnsserver.Server, conn session.LingerConn) (*HookableSession, WriteHook, <-chan error) {
	tb.Helper()

	sesh := SetupSession(tb, server, conn)
	m := NewRepMsg(1)
	h, done := sesh.HookWriteMsg(m)
	<-h.OnEnterC
	AssertSessionPending(tb, sesh)
	return sesh, h, done
}

func SetupEstablishedSession(tb testing.TB, server *dnsserver.Server, conn session.LingerConn) *HookableSession {
	tb.Helper()

	sesh := SetupSession(tb, server, conn)
	sesh.WriteMsg(nil, NewRepMsg(1))
	sesh.ReadMsg()
	AssertSessionEstablished(tb, sesh)
	return sesh
}

func SetupClosedSession(tb testing.TB, server *dnsserver.Server, conn session.LingerConn) *HookableSession {
	tb.Helper()

	sesh := SetupSession(tb, server, conn)
	sesh.Close(nil, 0, dns.RcodeSuccess)
	AssertSessionClosed(tb, sesh)
	return sesh
}

func NewRepMsg(id uint16) *dns.Msg {
	m := new(dns.Msg)
	m.Id = id
	m.Response = true
	m.Opcode = dns.OpcodeStateful
	m.Rcode = dns.RcodeSuccess
	m.Stateful = append(m.Stateful, &dns.DSOKeepAlive{})
	return m
}

func NewErrorRepMsg(id uint16) *dns.Msg {
	m := new(dns.Msg)
	m.Id = id
	m.Response = true
	m.Opcode = dns.OpcodeStateful
	m.Rcode = dns.RcodeStatefulTypeNotImplemented
	return m
}

func NewReqMsg(id uint16) *dns.Msg {
	m := new(dns.Msg)
	dns.SetDSORequest(m, id)
	m.Stateful = append(m.Stateful, &dns.DSOKeepAlive{})
	return m
}

func NewUniMsg() *dns.Msg {
	m := new(dns.Msg)
	dns.SetDSOUnidirectional(m)
	m.Stateful = append(m.Stateful, &dns.DSOKeepAlive{})
	return m
}

func AssertSessionWaiting(tb testing.TB, sesh *HookableSession) {
	tb.Helper()

	if gotState := sesh.State(); gotState != session.Waiting {
		tb.Fatalf("Expected SessionWaiting, got %v", gotState)
	}
}

func AssertSessionPending(tb testing.TB, sesh *HookableSession) {
	tb.Helper()

	if gotState := sesh.State(); gotState != session.Pending {
		tb.Fatalf("Expected SessionPending, got %v", gotState)
	}
}

func AssertSessionEstablished(tb testing.TB, sesh *HookableSession) {
	tb.Helper()

	if gotState := sesh.State(); gotState != session.Established {
		tb.Fatalf("Expected SessionEstablished, got %v", gotState)
	}
}

func AssertSessionClosed(tb testing.TB, sesh *HookableSession) {
	tb.Helper()

	if gotState := sesh.State(); gotState != session.Closed {
		tb.Fatalf("Expected SessionClosed, got %v", gotState)
	}

	select {
	case <-sesh.Done():
	default:
		tb.Error("Expected session to be done")
	}
}

func AssertCloseMsg(tb testing.TB, sesh *HookableSession) (tlv *dns.DSORetryDelay) {
	tb.Helper()

	gotM := AssertAnyMsg(tb, sesh)
	if !dns.IsDSOUnidirectional(gotM) || len(gotM.Stateful) == 0 {
		tb.Fatalf("Expected DSO Close Unidirectional, got %v", gotM)
	}
	tlv, ok := gotM.Stateful[0].(*dns.DSORetryDelay)
	if !ok {
		tb.Fatalf("Expected DSO Close Unidirectional, got %v", gotM)
	}
	return tlv
}

func AssertAnyMsg(tb testing.TB, sesh *HookableSession) *dns.Msg {
	tb.Helper()

	gotM, ok := sesh.ReadMsgWithTimeout(NoMessageTimeout)
	if !ok {
		tb.Fatal("Expected message, got none")
	}
	return gotM
}

func AssertNoMsg(tb testing.TB, sesh *HookableSession) {
	tb.Helper()

	gotM, ok := sesh.ReadMsgWithTimeout(NoMessageTimeout)
	if ok {
		tb.Fatalf("Expected no message, got %v", gotM)
	}
}

const NoMessageTimeout = 500 * time.Millisecond
