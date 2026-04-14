package dso

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"weak"

	"github.com/miekg/dns"
)

var (
	ErrSessionState  = fmt.Errorf("bad DSO state")
	ErrSessionClosed = fmt.Errorf("%w: closed", ErrSessionState)
)

type SessionState uint32

const (
	// SessionWaiting is a state where the session is waiting for an establishing response.
	SessionWaiting SessionState = iota
	// SessionPending is a state where the session is handling the establishing response.
	// Other messages are allowed but will block until writing the establishing response
	// either succeeds or fails.
	SessionPending
	// SessionEstablished is a state where the session is successfully established
	// and accepts messages.
	SessionEstablished
	// SessionClosing is a state where the session no longer accepts new messages
	// but the underlying connection may still be functional.
	SessionClosing
	// SessionClosed is a state where the session no longer accepts new messages
	// and the underlying connection is known to be non-functional.
	SessionClosed
)

func (s SessionState) String() string {
	switch s {
	case SessionWaiting:
		return "Waiting"
	case SessionPending:
		return "Pending"
	case SessionEstablished:
		return "Established"
	case SessionClosing:
		return "Closing"
	case SessionClosed:
		return "Closed"
	default:
		return strconv.FormatUint(uint64(s), 2)
	}
}

// Session implements server-side state management of RFC 8490 DNS Stateful Operations session.
//
//  1. Initially, the state is [SessionWaiting] in which the session only accepts responses.
//  2. First response with the zero RCODE is an establishing respose. It changes state
//     to [SessionPending] in which all messages are accepted, but actual writing is delayed.
//  3. Once establishing response is written successfully, state is changed to [SessionEstablished]
//     in which delayed writes are unblocked and all messages are accepted and written.
//  4. When the user writes a unidirectional with [RetryDelay] primary TLV, state is changed
//     to [SessionClosing]. The session remains in this state until session's owner uses
//     [Session.Close] to signal that underlying connection is non-functional which changes
//     state to its final value [SessionClosed].
//
// If any write fails with an error, it's interpreted that the underlying connection is non-functional
// and the state is changed [SessionClosed] directly.
//
// Each TCP connection should have at most one session.
type Session struct {
	Conn net.Conn

	KeepAlive KeepAlive

	state    atomic.Uint32
	mu       sync.RWMutex  // serialize writes of close unidirectional vs all other
	pendingC chan struct{} // closed if state is SessionEstablished or SessionClosed
	closingC chan struct{} // closed when underlying connection is marked as non-functional
	doneC    chan struct{} // closed if state is SessionClosed

	activeAt atomic.Int64
	aliveAt  atomic.Int64
}

// NewSession creates new Session.
func NewSession(conn net.Conn, ka KeepAlive) (s *Session) {
	s = &Session{
		Conn:      conn,
		KeepAlive: ka,
		pendingC:  make(chan struct{}),
		closingC:  make(chan struct{}),
		doneC:     make(chan struct{}),
	}
	t := time.Now()
	s.activeAt.Store(int64(t.Sub(monoTimeStart)))
	s.aliveAt.Store(int64(t.Sub(monoTimeStart)))
	return s
}

// State returns current state.
func (s *Session) State() SessionState {
	return SessionState(s.state.Load())
}

func (s *Session) TickKeepAlive() {
	s.aliveAt.Store(int64(time.Since(monoTimeStart)))
}

func (s *Session) TickActivity() {
	s.activeAt.Store(int64(time.Since(monoTimeStart)))
}

// CheckTimeout verifies whether session is considered active and alive at time t.
func (s *Session) CheckTimeout(t time.Time) (active, alive bool) {
	// RFC 8490, Section 6.4.2: A server will forcibly abort an idle client session after five
	// seconds or twice the inactivity timeout value, whichever is greater.
	//
	// RFC 8490, Section 6.4.2: In the case of a zero inactivity timeout value,
	// this means that if a client fails to close an idle client session, then the server
	// will forcibly abort the idle session after five seconds.
	//
	// RFC 8490, Section 6.4.2: An inactivity timeout of 0xFFFFFFFF represents "infinity"
	// and informs the client that it may keep an idle connection open as long as it wishes.
	switch s.KeepAlive.InactivityTimeout {
	case InactivityTimeoutNever:
		active = true
	default:
		active = int64(t.Sub(monoTimeStart)-time.Duration(s.activeAt.Load())) > max((5*time.Second).Milliseconds(), 2*int64(s.KeepAlive.InactivityTimeout))
	}

	// RFC 8490, Section 6.5.1: If, at any time during the life of the DSO Session,
	// twice the keepalive interval value (i.e., 30 seconds by default) elapses without
	// any DNS messages being sent or received on a DSO Session, the server SHOULD consider
	// the client delinquent and SHOULD forcibly abort the DSO Session.
	//
	// RFC 8490, Section 6.5.2: the server MUST NOT send a DSO Keepalive message ...
	// with a keepalive interval value less than ten seconds
	//
	// RFC 8490, Section 6.5.2: A keepalive interval value of 0xFFFFFFFF represents
	// "infinity" and informs the client that it should generate no DSO keepalive traffic.
	switch s.KeepAlive.KeepAliveInterval {
	case KeepAliveIntervalNever:
		alive = true
	default:
		alive = int64(t.Sub(monoTimeStart)-time.Duration(s.aliveAt.Load())) > 2*max((10*time.Second).Milliseconds(), int64(s.KeepAlive.KeepAliveInterval))
	}

	return active, alive
}

// ReadMsg reads message from conn and updates activity and alive timeouts as necessary.
// It's ok to call this method on nil receiver.
func (s *Session) ReadMsg(reader dns.Reader, conn net.Conn, timeout time.Duration) (msg []byte, err error) {
	if msg, err = reader.ReadTCP(conn, timeout); err != nil {
		return nil, err
	}

	// RFC 8490, Section 6.3: At both servers and clients, the generation or reception of any
	// complete DNS message (including DNS requests, responses, updates, DSO messages, etc.)
	// resets both timers for that DSO Session, with the one exception being that
	// a DSO Keepalive message resets only the keepalive timer, not the inactivity timeout timer.

	if s != nil {
		// For similicity neither completeness nor correctness of DNS and DSO message is verified.
		// Only simple check is performed to distinguish DSO KeepAlive messages.
		isKeepAlive := len(msg) >= MsgHeaderLen+TLVHeaderLen+KeepAliveLen && Type(binary.BigEndian.Uint16(msg[MsgHeaderLen:])) == TypeKeepAlive
		if isKeepAlive {
			s.TickKeepAlive()
		} else {
			s.TickActivity()
			s.TickKeepAlive()
		}
	}

	return msg, err
}

// WriteMsg writes message and updates session's state if needed.
//
// Returns [ErrSessionClosed] if session is closed, [ErrSessionState] if it's in the wrong state.
// Otherwise the writing error is returned, if any.
//
// Session establishing response that is other than [KeepAlive] will be followed by
// the KeepAlive unidirectional.
//
// Session termination [RetryDelay] unidirectional is recognized: it's the last message
// allowed to be written.
func (s *Session) WriteMsg(msg []byte) (err error) {
	_ = msg[MsgHeaderLen-1]
	// Trust the caller to pass properly formatted message and use naive check for dispatching.
	var (
		isUnidirectional = binary.BigEndian.Uint16(msg) == 0
		isRequest        = !isUnidirectional && (msg[2]&0x80) == 0
		rcode            = msg[3] & 0xF

		isCloseUnidirectional = isUnidirectional && len(msg) >= MsgHeaderLen+TLVHeaderLen+RetryDelayLen && Type(binary.BigEndian.Uint16(msg[MsgHeaderLen:])) == TypeRetryDelay
	)

	var locker sync.Locker
	if isCloseUnidirectional {
		locker = &s.mu
	} else {
		locker = s.mu.RLocker()
	}
	locker.Lock()
	defer locker.Unlock()

	switch {
	case isCloseUnidirectional:
		err = s.writeCloseUnidirectional(msg)
	case isUnidirectional:
		err = s.writeUnidirectional(msg)
	case isRequest:
		err = s.writeRequest(msg)
	case rcode != dns.RcodeSuccess:
		err = s.writeErrorResponse(msg)
	case s.state.CompareAndSwap(uint32(SessionWaiting), uint32(SessionPending)):
		err = s.writeEstablishingResponse(msg)
	default:
		err = s.writeResponse(msg)
	}

	if err != nil && !errors.Is(err, ErrSessionState) {
		// Close session on writing error.
		switch SessionState(s.state.Swap(uint32(SessionClosed))) {
		case SessionWaiting:
			fallthrough
		case SessionPending:
			close(s.pendingC)
			fallthrough
		case SessionEstablished:
			close(s.doneC)
			fallthrough
		case SessionClosing:
			close(s.closingC)
		case SessionClosed:
		default:
			panic("unexpected DSO state")
		}
	}

	if err != nil {
		// RFC 8490, Section 6.3: At both servers and clients, the generation or reception of any
		// complete DNS message (including DNS requests, responses, updates, DSO messages, etc.)
		// resets both timers for that DSO Session, with the one exception being that
		// a DSO Keepalive message resets only the keepalive timer, not the inactivity timeout timer.
		isKeepAlive := len(msg) >= MsgHeaderLen+TLVHeaderLen+KeepAliveLen && Type(binary.BigEndian.Uint16(msg[MsgHeaderLen:])) == TypeKeepAlive
		if isKeepAlive {
			s.TickKeepAlive()
		} else {
			s.TickKeepAlive()
			s.TickActivity()
		}
	}

	return err
}

// WriteCloseMsg writes unidirectional that asks client to gracefully close the connection.
//
// The message is not padded. If padding is needed, build custom message and use [Session.WriteMsg].
func (s *Session) WriteCloseMsg(rcode uint8, retryDelay uint32) (err error) {
	var (
		buf [MsgHeaderLen + TLVHeaderLen + RetryDelayLen]byte
		b   = NewMsgBuilder(buf[:])
	)
	b.SetMsgHeader(MsgHeader{0, false, rcode})
	b.WriteRetryDelay(RetryDelay{retryDelay})
	return s.WriteMsg(b.Message())
}

// ConnClosed is called externally when the session owner determines
// that the underlying connection is no longer functional.
func (s *Session) ConnClosed() {
	switch SessionState(s.state.Swap(uint32(SessionClosed))) {
	case SessionWaiting:
		fallthrough
	case SessionPending:
		close(s.pendingC)
		fallthrough
	case SessionEstablished:
		close(s.doneC)
		fallthrough
	case SessionClosing:
		close(s.closingC)
	case SessionClosed:
	default:
		panic("unexpected DSO state")
	}
}

// Done returns channel that's closed when session is closed.
func (s *Session) Done() <-chan struct{} {
	return s.doneC
}

func doClose(weakSesh weak.Pointer[Session], weakConn weak.Pointer[net.Conn], closingC chan struct{}) {
	// Section 6.6.1: After sending a DSO Retry Delay message, the server SHOULD
	// allow the client five seconds to close the connection, and if the client
	// has not closed the connection after five seconds, then the server SHOULD
	// forcibly abort the connection.
	select {
	case <-time.After(5 * time.Second):
	case <-closingC:
		return
	}
	if sesh := weakSesh.Value(); sesh != nil {
		if SessionState(sesh.state.Swap(uint32(SessionClosed))) == SessionClosing {
			abortConn(sesh.Conn)
			close(closingC)
		}
	} else if conn := weakConn.Value(); conn != nil {
		// User abandoned session but conn is still around.
		abortConn(*conn)
	}
}

func (s *Session) writeCloseUnidirectional(msg []byte) (err error) {
	if SessionState(s.state.Load()) == SessionClosed {
		return ErrSessionClosed
	}

	switch SessionState(s.state.Swap(uint32(SessionClosing))) {
	case SessionWaiting:
		s.state.Store(uint32(SessionClosed))
		close(s.pendingC)
		close(s.closingC)
		close(s.doneC)
		return nil
	case SessionEstablished:
		_, err = s.Conn.Write(msg)
		close(s.doneC)
		if err == nil {
			go doClose(weak.Make(s), weak.Make(&s.Conn), s.closingC)
		}
		return err
	case SessionClosing:
		return ErrSessionClosed
	default:
		panic("unexpected DSO state")
	}
}

func (s *Session) writeUnidirectional(msg []byte) (err error) {
	state := SessionState(s.state.Load())
	if state == SessionPending {
		<-s.pendingC
		state = SessionState(s.state.Load())
	}

	switch state {
	case SessionWaiting:
		return ErrSessionState
	case SessionEstablished:
		_, err = s.Conn.Write(msg)
		return err
	case SessionClosing:
		fallthrough
	case SessionClosed:
		return ErrSessionClosed
	default:
		panic("unexpected DSO state")
	}
}

func (s *Session) writeRequest(msg []byte) (err error) {
	state := SessionState(s.state.Load())
	if state == SessionPending {
		<-s.pendingC
		state = SessionState(s.state.Load())
	}

	switch state {
	case SessionWaiting:
		return ErrSessionState
	case SessionEstablished:
		_, err = s.Conn.Write(msg)
		return err
	case SessionClosing:
		fallthrough
	case SessionClosed:
		return ErrSessionClosed
	default:
		panic("unexpected DSO state")
	}
}

func (s *Session) writeErrorResponse(msg []byte) (err error) {
	// Responses with non-zero Rcode are written regardless of session's state:
	// - SessionWaiting: error responses don't change state and only notify client
	// - SessionClosed: client considers all responses as being in-flight and ignores
	_, err = s.Conn.Write(msg)
	return err
}

func (s *Session) writeEstablishingResponse(msg []byte) (err error) {
	_, err = s.Conn.Write(msg)
	if err == nil && (len(msg) < MsgHeaderLen+TLVHeaderLen+KeepAliveLen || Type(binary.BigEndian.Uint16(msg[MsgHeaderLen:])) != TypeKeepAlive) {
		// The session is established via a non-KeepAlive exchange. Tell the client our timeouts.
		var (
			buf [MsgHeaderLen + TLVHeaderLen + KeepAliveLen]byte
			b   = NewMsgBuilder(buf[:])
		)
		b.SetMsgHeader(MsgHeader{0, false, dns.RcodeSuccess})
		b.WriteKeepAlive(s.KeepAlive)
		_, err = s.Conn.Write(b.Message())
	}
	if err != nil {
		return err
	}

	if !s.state.CompareAndSwap(uint32(SessionPending), uint32(SessionEstablished)) {
		return ErrSessionClosed
	}
	close(s.pendingC)

	return err
}

func (s *Session) writeResponse(msg []byte) (err error) {
	state := SessionState(s.state.Load())
	if state == SessionPending {
		<-s.pendingC
		state = SessionState(s.state.Load())
	}

	switch state {
	case SessionEstablished:
		_, err = s.Conn.Write(msg)
		return err
	case SessionClosing:
		fallthrough
	case SessionClosed:
		return ErrSessionClosed
	default:
		panic("unexpected DSO state")
	}
}

func abortConn(conn net.Conn) error {
	netConn := conn
	if netConner, ok := netConn.(interface{ NetConn() net.Conn }); ok {
		netConn = netConner.NetConn()
	}
	if setLingerer, ok := netConn.(interface{ SetLinger(int) error }); ok {
		setLingerer.SetLinger(0)
	}
	return conn.Close()
}

var monoTimeStart = time.Now()
