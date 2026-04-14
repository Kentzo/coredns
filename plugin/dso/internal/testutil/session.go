package testutil

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/dso"
	"github.com/miekg/dns"
)

const NoMessageTimeout = 500 * time.Millisecond

type Session struct {
	*dso.Session
}

func (s *Session) AsyncWriteMsg(msg []byte) (done <-chan error) {
	d := make(chan error, 1)
	go func() {
		d <- s.WriteMsg(msg)
		close(d)
	}()
	return d
}

func (s *Session) HookWriteMsg(msg []byte) (h WriteHook, done <-chan error) {
	h = s.Conn.(*Conn).Hook(binary.BigEndian.Uint16(msg), msg[2]&0x80 != 0)
	d := s.AsyncWriteMsg(msg)
	return h, d
}

func (s *Session) ExpectWrittenMsg() (msg []byte, ok bool) {
	msg, ok = <-s.Conn.(*Conn).TeeC
	return msg, ok
}

func (s *Session) ExpectWrittenMsgWithTimeout(timeout time.Duration) (msg []byte, ok bool) {
	select {
	case msg, ok = <-s.Conn.(*Conn).TeeC:
		return msg, ok
	case <-time.After(timeout):
		return nil, false
	}
}

func (s *Session) AssertWrittenAnyMsg(tb testing.TB) []byte {
	tb.Helper()

	gotMsg, ok := s.ExpectWrittenMsgWithTimeout(NoMessageTimeout)
	if !ok {
		tb.Fatal("Expected message, got none")
	}
	return gotMsg
}

func (s *Session) AssertWrittenCloseMsg(tb testing.TB) dso.RetryDelay {
	tb.Helper()

	var p dso.MsgParser
	msgH, err := p.Start(s.AssertWrittenAnyMsg(tb), dso.OriginServer)
	if err != nil {
		tb.Fatalf("Expected to unpack message, got %v", err)
	}
	if !msgH.IsUnidirectional() {
		tb.Fatalf("Expected to unidirectional, got %v", err)
	}
	tlvH, err := p.TLVHeader()
	if err != nil {
		tb.Fatalf("Expected to unpack TLV, got %v", err)
	}
	if tlvH.Type != dso.TypeRetryDelay {
		tb.Fatalf("Expected to RetryDelay, got %v", tlvH)
	}
	tlv, err := p.RetryDelay()
	if err != nil {
		tb.Fatalf("Expected to unpack RetryDelay, got %v", err)
	}
	return tlv
}

func (s *Session) AssertWrittenNoMsg(tb testing.TB) {
	tb.Helper()

	gotM, ok := s.ExpectWrittenMsgWithTimeout(NoMessageTimeout)
	if ok {
		tb.Fatalf("Expected no message, got %v", gotM)
	}
}

func (s *Session) AssertState(tb testing.TB, wantState dso.SessionState) {
	tb.Helper()

	if gotState := s.State(); gotState != wantState {
		tb.Fatalf("Expected %v, got %v", wantState, gotState)
	}

	if wantState == dso.SessionClosing || wantState == dso.SessionClosed {
		select {
		case <-s.Done():
		default:
			tb.Error("Expected session to be done")
		}
	}
}

// NewSession makes a session that writes to conn. If conn is nil, StubConn is used.
func NewSession(tb testing.TB, conn net.Conn) *Session {
	tb.Helper()

	conn = NewConn(conn)
	sesh := &Session{
		dso.NewSession(conn, dso.KeepAlive{
			InactivityTimeout: dso.InactivityTimeoutDefault,
			KeepAliveInterval: dso.KeepAliveIntervalDefault,
		}),
	}
	tb.Cleanup(func() {
		sesh.ConnClosed()
	})
	return sesh
}

func SetupWaitingSession(tb testing.TB, conn net.Conn) *Session {
	tb.Helper()

	sesh := NewSession(tb, conn)
	sesh.AssertState(tb, dso.SessionWaiting)
	return sesh
}

func SetupPendingSession(tb testing.TB, conn net.Conn) (sesh *Session, hook WriteHook, done <-chan error) {
	tb.Helper()

	sesh = NewSession(tb, conn)
	m := NewRepMsg(1)
	h, done := sesh.HookWriteMsg(m)
	<-h.OnEnterC
	sesh.AssertState(tb, dso.SessionPending)
	return sesh, h, done
}

func SetupEstablishedSession(tb testing.TB, conn net.Conn) *Session {
	tb.Helper()

	sesh := NewSession(tb, conn)
	sesh.WriteMsg(NewRepMsg(1))
	sesh.ExpectWrittenMsg()
	sesh.AssertState(tb, dso.SessionEstablished)
	return sesh
}

func SetupClosingSession(tb testing.TB, conn net.Conn) *Session {
	tb.Helper()

	sesh := NewSession(tb, conn)
	sesh.WriteMsg(NewRepMsg(1))
	sesh.ExpectWrittenMsg()
	sesh.WriteCloseMsg(dns.RcodeSuccess, 0)
	sesh.ExpectWrittenMsg()
	sesh.AssertState(tb, dso.SessionClosing)
	return sesh
}

func SetupClosedSession(tb testing.TB, conn net.Conn) *Session {
	tb.Helper()

	sesh := NewSession(tb, conn)
	sesh.WriteCloseMsg(dns.RcodeSuccess, 0)
	sesh.AssertState(tb, dso.SessionClosed)
	return sesh
}

func NewRepMsg(id uint16) []byte {
	var (
		buf [32]byte
		b   = dso.NewMsgBuilder(buf[:])
	)
	b.SetMsgHeader(dso.MsgHeader{
		ID:       id,
		Response: true,
		Rcode:    dns.RcodeSuccess,
	})
	b.WriteKeepAlive(dso.KeepAlive{})
	return b.Message()
}

func NewErrorRepMsg(id uint16) []byte {
	var (
		buf [32]byte
		b   = dso.NewMsgBuilder(buf[:])
	)
	b.SetMsgHeader(dso.MsgHeader{
		ID:       id,
		Response: true,
		Rcode:    dns.RcodeStatefulTypeNotImplemented,
	})
	return b.Message()
}

func NewReqMsg(id uint16) []byte {
	var (
		buf [32]byte
		b   = dso.NewMsgBuilder(buf[:])
	)
	b.SetMsgHeader(dso.MsgHeader{
		ID:       id,
		Response: false,
		Rcode:    dns.RcodeSuccess,
	})
	b.WriteKeepAlive(dso.KeepAlive{})
	return b.Message()
}

func NewUniMsg() []byte {
	var (
		buf [32]byte
		b   = dso.NewMsgBuilder(buf[:])
	)
	b.SetMsgHeader(dso.MsgHeader{
		ID:       0,
		Response: false,
		Rcode:    dns.RcodeSuccess,
	})
	b.WriteKeepAlive(dso.KeepAlive{})
	return b.Message()
}
