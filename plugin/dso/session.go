package dso

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"weak"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/miekg/dns"
)

// SessionState is the list of session states.
type SessionState uint32

const (
	// The session is waiting for an establishing exchange.
	SessionWaiting SessionState = iota
	// The session is being established.
	SessionPending
	// The session is successfully established.
	SessionEstablished
	// The session is closed and no longer accepts new messages.
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
	case SessionClosed:
		return "Closed"
	default:
		return strconv.FormatUint(uint64(s), 2)
	}
}

// Session implements state management of RFC 8490 DNS Stateful Operations session.
//
// Each TCP connection should have at most one session.
type Session struct {
	// Original writer that was used to create the session.
	W  dns.ResponseWriter
	ID SessionID

	state    atomic.Uint32
	mu       *sync.RWMutex // serialize writes of close vs all other
	pendingC chan struct{} // closed if state is (SessionEstablished | SessionClosed)
	doneC    chan struct{} // closed if state is SessionClosed

	DefaultKeepAlive *dns.DSOKeepAlive
}

// NewSession creates new Session.
func NewSession(ctx context.Context, w dns.ResponseWriter) *Session {
	return NewSessionWithID(ctx, w, NewSessionID(ctx, w))
}

// NewSessionWithID creates new Session but uses a given ID instead of deriving its own.
func NewSessionWithID(ctx context.Context, w dns.ResponseWriter, id SessionID) *Session {
	s := new(Session)
	s.W = w
	s.ID = id
	s.mu = new(sync.RWMutex)
	s.pendingC = make(chan struct{})
	s.doneC = make(chan struct{})
	idleTimeout := s.ID.server.IdleTimeout
	s.DefaultKeepAlive = &dns.DSOKeepAlive{
		InactivityTimeout: uint32(max(0*time.Second, min(idleTimeout-5*time.Second, idleTimeout/2)).Milliseconds()),
		KeepAliveInterval: uint32(max(dns.DSOKeepAliveIntervalMin, idleTimeout/2).Milliseconds()),
	}
	log.Debugf("%v: SessionWaiting", w.RemoteAddr())
	return s
}

// State returns current session state.
func (s *Session) State() SessionState {
	return SessionState(s.state.Load())
}

// IsValidState checks whether the session state is valid to receive the DSO message.
//
// Returns [ErrSessionClosed] if session is closed, [ErrSessionState] if it's in the wrong state.
func (s *Session) IsValidState(r *dns.Msg) error {
	switch SessionState(s.state.Load()) {
	case SessionWaiting:
		if dns.IsDSORequest(r) {
			return nil
		}
		fallthrough
	case SessionPending:
		return ErrSessionState
	case SessionEstablished:
		return nil
	case SessionClosed:
		return ErrSessionClosed
	default:
		return ErrSessionState
	}
}

// WriteMsg writes message and updates associated session state if necessary.
//
// Returns [ErrSessionClosed] if session is closed, [ErrSessionState] if it's in the wrong state.
// If state is appropriate, the writing result is returned.
//
// w is optional. If nil, session's original response writer is used.
func (s *Session) WriteMsg(w dns.ResponseWriter, r *dns.Msg) (err error) {
	if w == nil {
		w = s.W
	}
	// Messages can be written concurrently with the following exceptions:
	// 1. Requests, unidirectional and consequent NOERROR responses must wait
	//    until the 1st successful reponse is sent
	// 2. No messages can be written after Close unidirectional
	isCloseUnidirectional := dns.IsDSOUnidirectional(r) && r.Stateful[0].DSOType() == dns.StatefulTypeRetryDelay
	var locker sync.Locker
	if isCloseUnidirectional {
		locker = s.mu
	} else {
		locker = s.mu.RLocker()
	}

	locker.Lock()
	defer locker.Unlock()

	switch {
	case isCloseUnidirectional:
		err = s.writeCloseUnidirectional(w, r)
	case dns.IsDSOUnidirectional(r):
		err = s.writeUnidirectional(w, r)
	case dns.IsDSORequest(r):
		err = s.writeRequest(w, r)
	default:
		err = s.writeResponse(w, r)
	}

	if err != nil && !errors.Is(err, ErrSessionState) {
		// Close session on writing error.
		switch SessionState(s.state.Swap(uint32(SessionClosed))) {
		case SessionPending:
			close(s.pendingC)
			fallthrough
		case SessionEstablished:
			close(s.doneC)
			log.Debugf("%v: SessionClosed (error, %v)", w.RemoteAddr(), err)
		case SessionClosed:
		default:
			panic("unexpected DSO state")
		}
	}

	return err
}

// Close attempts to gracefully close the connection with a RetryDelay DSO message.
//
// w is optional. If nil, session's original response writer is used.
func (s *Session) Close(w dns.ResponseWriter, retryDelay time.Duration, rcode int) error {
	if w == nil {
		w = s.W
	}
	m := new(dns.Msg)
	dns.SetDSOClose(m, retryDelay, rcode)
	return s.WriteMsg(w, m)
}

// Abort forcibly aborts the connection.
//
// w is optional. If nil, session's original response writer is used.
func (s *Session) Abort(w dns.ResponseWriter) {
	s.OnConnClosed()
	if w == nil {
		s.ID.conn.SetLinger(0)
		s.W.Close()
	} else {
		AbortConn(w)
	}
}

// OnConnClosed is called externally when the session owner determines
// that the underlying connection is dead.
func (s *Session) OnConnClosed() {
	if SessionState(s.state.Load()) == SessionClosed {
		return
	}

	s.mu.RLock()
	switch SessionState(s.state.Swap(uint32(SessionClosed))) {
	case SessionWaiting:
		fallthrough
	case SessionPending:
		close(s.pendingC)
		fallthrough
	case SessionEstablished:
		close(s.doneC)
	}
	s.mu.RUnlock()
	log.Debugf("%v: SessionClosed (event)", s.W.RemoteAddr())
}

// Done returns a channel that's closed when the session is closed.
func (s *Session) Done() <-chan struct{} {
	return s.doneC
}

func (s *Session) writeCloseUnidirectional(w dns.ResponseWriter, r *dns.Msg) (err error) {
	// isCloseUnidirectional has exclusive access and thus session cannot be in pending state.
	state := SessionState(s.state.Load())
	if state == SessionClosed {
		return nil
	}

	log.Debugf("%v: SessionClosed (retrydelay)", w.RemoteAddr())
	switch state {
	case SessionWaiting:
		s.state.Store(uint32(SessionClosed))
		close(s.pendingC)
		close(s.doneC)
		return nil
	case SessionEstablished:
		s.state.Store(uint32(SessionClosed))
		close(s.doneC)
		err := w.WriteMsg(r)
		// Section 6.6.1: After sending a DSO Retry Delay message, the server SHOULD
		// allow the client five seconds to close the connection, and if the client
		// has not closed the connection after five seconds, then the server SHOULD
		// forcibly abort the connection.
		ws := weak.Make(s)
		doneC := s.doneC
		go func() {
			select {
			case <-doneC:
			case <-time.After(5 * time.Second):
				if s := ws.Value(); s != nil {
					s.Abort(nil)
				}
			}
		}()
		return err
	default:
		panic("unexpected DSO state")
	}
}

func (s *Session) writeUnidirectional(w dns.ResponseWriter, r *dns.Msg) (err error) {
	state := SessionState(s.state.Load())
	if state == SessionPending {
		<-s.pendingC
		state = SessionState(s.state.Load())
	}

	switch state {
	case SessionWaiting:
		return ErrSessionState
	case SessionEstablished:
		return w.WriteMsg(r)
	case SessionClosed:
		return ErrSessionClosed
	default:
		panic("unexpected DSO state")
	}
}

func (s *Session) writeRequest(w dns.ResponseWriter, r *dns.Msg) (err error) {
	state := SessionState(s.state.Load())
	if state == SessionPending {
		<-s.pendingC
		state = SessionState(s.state.Load())
	}

	switch state {
	case SessionWaiting:
		return ErrSessionState
	case SessionEstablished:
		return w.WriteMsg(r)
	case SessionClosed:
		return ErrSessionClosed
	default:
		panic("unexpected DSO state")
	}
}

func (s *Session) writeResponse(w dns.ResponseWriter, r *dns.Msg) (err error) {
	state := SessionState(s.state.Load())
	isEstablishingResponse := state == SessionWaiting && r.Rcode == dns.RcodeSuccess && s.state.CompareAndSwap(uint32(SessionWaiting), uint32(SessionPending))
	if !isEstablishingResponse {
		<-s.pendingC
		state = SessionState(s.state.Load())
	} else {
		log.Debugf("%v: SessionPending", w.RemoteAddr())
	}

	switch state {
	case SessionWaiting:
		fallthrough
	case SessionEstablished:
		err = w.WriteMsg(r)
		if !isEstablishingResponse {
			return err
		}
		if !s.state.CompareAndSwap(uint32(SessionPending), uint32(SessionEstablished)) {
			return ErrSessionClosed
		}

		close(s.pendingC)
		log.Debugf("%v: SessionEstablished", w.RemoteAddr())
		if len(r.Stateful) == 0 || r.Stateful[0].DSOType() != dns.StatefulTypeKeepAlive {
			// The session is established via a non-KeepAlive exchange. Tell the client our timeouts.
			m := new(dns.Msg)
			dns.SetDSOUnidirectional(m)
			m.Stateful = append(m.Stateful, s.DefaultKeepAlive)
			err = w.WriteMsg(m)
		}
		return err
	case SessionClosed:
		return ErrSessionClosed
	default:
		panic("unexpected DSO state")
	}
}

// SessionID identifies a session by referring the connection and its server.
type SessionID struct {
	server *dnsserver.Server
	conn   LingerConn // underlying network connection
}

// NewSessionID creates an identifier from the server value in context and underlying network connection.
func NewSessionID(ctx context.Context, w dns.ResponseWriter) SessionID {
	return SessionID{
		server: ctx.Value(dnsserver.Key{}).(*dnsserver.Server),
		conn:   GetConn(w),
	}
}

var (
	ErrSessionState  = errors.New("bad DSO state")
	ErrSessionClosed = fmt.Errorf("%w: closed", ErrSessionState)
)
