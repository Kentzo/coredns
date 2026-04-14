package dso

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/dso/internal/lookup"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

var (
	ErrUnexpected = fmt.Errorf("unexpected DSO message")
)

type (
	// Server implements DSO via underlying [dns.Server].
	//
	//
	Server struct {
		Host   string
		Config Config

		sessions     map[net.Conn]*Session
		sessionsMu   sync.RWMutex
		sessionsCond *sync.Cond // signled during shutdown once sessions is empty

		// logH  *logHandler
		push   map[*Session]*Subscription
		pushMu sync.RWMutex

		tcp      *dns.Server
		tls      *dns.Server
		upstream atomic.Pointer[dnsserver.Server]

		shutdown atomic.Bool

		cleanupT *time.Ticker
	}
	// tcpHandler handles DSO messages and rejects everything else.
	tcpHandler struct {
		dso    *Server
		reader dns.Reader
	}
	// tlsHandler handles DSO messages and, if DSO Push is enabled,
	// authoritatively responds to DNS queries within the configured Push zones.
	// Everything else is rejected.
	tlsHandler struct {
		dso    *Server
		reader dns.Reader
	}
	// seshConn wraps [net.Conn] and lazily created [Session].
	seshConn struct {
		S *Session
		C net.Conn
	}
)

// NewServer returns new DSO server.
func NewServer(host string, cfg Config) (s *Server) {
	s = &Server{
		Host:     host,
		Config:   cfg,
		sessions: make(map[net.Conn]*Session),
	}
	s.sessionsCond = sync.NewCond(s.sessionsMu.RLocker())
	if cfg.Push != nil {
		s.push = make(map[*Session]*Subscription)
	}
	return s
}

func (s *Server) Start() (err error) {
	if s.Config.TCPPort != 0 {
		port := max(s.Config.TCPPort, 0)
		var (
			addr = s.Host + ":" + strconv.Itoa(port)
			ln   net.Listener
		)
		ln, err = net.Listen("tcp", addr)
		if err != nil {
			err = fmt.Errorf("failed to start TCP listener on %s: %w", addr, err)
			return err
		}
		log.Infof("DSO over TCP listens on %v", ln.Addr())
		tcpHandler := &tcpHandler{dso: s}
		s.tcp = &dns.Server{
			Listener:      ln,
			Net:           "tcp",
			TsigSecret:    s.Config.TsigSecret,
			MaxTCPQueries: -1,
			Handler:       tcpHandler,
			DecorateReader: func(r dns.Reader) dns.Reader {
				tcpHandler.reader = r
				return tcpHandler
			},
			MsgAcceptFunc: tcpHandler.msgAccept,
		}
		defer func() {
			if err != nil {
				ln.Close()
				s.tcp = nil
			}
		}()
	}

	if s.Config.TLSPort != 0 {
		port := max(s.Config.TLSPort, 0)
		var (
			addr = s.Host + ":" + strconv.Itoa(port)
			ln   net.Listener
		)
		ln, err = tls.Listen("tcp", addr, s.Config.TLSConfig)
		if err != nil {
			err = fmt.Errorf("failed to start TLS listener on %s: %w", addr, err)
			return err
		}
		log.Infof("DSO over TLS listens on %v", ln.Addr())
		tlsHandler := &tlsHandler{dso: s}
		s.tls = &dns.Server{
			Listener:      ln,
			Net:           "tcp-tls",
			TsigSecret:    s.Config.TsigSecret,
			MaxTCPQueries: -1,
			Handler:       tlsHandler,
			DecorateReader: func(r dns.Reader) dns.Reader {
				tlsHandler.reader = r
				return tlsHandler
			},
			MsgAcceptFunc: tlsHandler.msgAccept,
		}
		defer func() {
			if err != nil {
				ln.Close()
				s.tls = nil
			}
		}()
	}

	if s.tcp == nil && s.tls == nil {
		return fmt.Errorf("no services")
	}

	var (
		wg    sync.WaitGroup
		wgErr error
	)
	for _, dnsServer := range [...]*dns.Server{s.tcp, s.tls} {
		if dnsServer == nil {
			continue
		}
		defer func() {
			if err != nil {
				dnsServer.Shutdown()
			}
		}()
		wg.Add(1)
		// [dns.Server.ActivateAndServe] returns startup errors immediatelly
		// but calls [dns.Server.NotifyStartedFunc] and blocks when started successfully.
		dnsServer.NotifyStartedFunc = func() {
			dnsServer.NotifyStartedFunc = nil
			wg.Done()
		}
		go func() {
			if err := dnsServer.ActivateAndServe(); err != nil {
				if dnsServer.NotifyStartedFunc != nil {
					dnsServer.NotifyStartedFunc = nil
					wgErr = fmt.Errorf("failed to activate DNS server listening on %s: %w", dnsServer.Listener.Addr(), err)
					wg.Done()
				}
			}
			// Note that [dns.Server.Shutdown] is not called here, see [Server.Shutdown].
		}()
	}
	wg.Wait()
	err = wgErr
	if err != nil {
		return err
	}

	s.cleanupT = time.NewTicker(DefaultCleanupInterval)
	go s.doCleanup()
	return nil
}

func (s *Server) Shutdown(ctx context.Context, reconnectInterval time.Duration) error {
	// Stop periodic cleanups.
	s.cleanupT.Stop()

	// Stop dispatching DNS messages on existing TCP connections.
	s.shutdown.Store(true)

	// Stop accepting new TCP connections.
	for _, dnsServer := range [...]*dns.Server{s.tcp, s.tls} {
		if dnsServer != nil {
			dnsServer.Listener.Close()
		}
	}

	// Close sessions gracefully.
	var wg sync.WaitGroup
	s.sessionsMu.RLock()
	for _, sesh := range s.sessions {
		wg.Go(func() {
			sesh.WriteCloseMsg(dns.RcodeSuccess, uint32(reconnectInterval.Milliseconds())) //nolint:gosec
		})
	}
	s.sessionsMu.RUnlock()
	wg.Wait()

	// Wait for sessions to close.
	condC := make(chan struct{})
	go func() {
		s.sessionsMu.RLock()
		defer s.sessionsMu.RUnlock()

		for len(s.sessions) > 0 {
			s.sessionsCond.Wait()
		}
		close(condC)
	}()
	select {
	case <-condC:
	case <-ctx.Done():
	}

	// Shutdown the DNS servers.
	for _, dnsServer := range [...]*dns.Server{s.tcp, s.tls} {
		if dnsServer != nil {
			wg.Go(func() {
				dnsServer.ShutdownContext(ctx)
			})
		}
	}
	wg.Wait()

	return ctx.Err()
}

func (s *Server) doCleanup() {
	for range s.cleanupT.C {
		s.Cleanup()
	}
}

// Cleanup sheds inactive and non-functional sessions.
func (s *Server) Cleanup() {
	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()

	s.pushMu.RLock()
	defer s.pushMu.RUnlock()

	for _, sesh := range s.sessions {
		active, alive := sesh.CheckTimeout(time.Now())
		if alive && !active {
			if sub := s.push[sesh]; sub != nil {
				active = sub.IsActive()
			}
		}
		if !alive || !active {
			abortConn(sesh.Conn)
		}
	}
}

// Compact shrinks maps.
func (s *Server) Compact() {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()

	s.pushMu.Lock()
	defer s.pushMu.Unlock()

	s.sessions = maps.Clone(s.sessions)
	s.push = maps.Clone(s.push)

	for _, sub := range s.push {
		sub.Compact()
	}
}

// ConnClosed frees resources associated with the connection, if any.
func (s *Server) ConnClosed(conn net.Conn) {
	s.sessionsMu.Lock()
	if sesh, ok := s.sessions[conn]; ok {
		sesh.ConnClosed()
		delete(s.sessions, conn)
		if len(s.sessions) == 0 && s.shutdown.Load() {
			s.sessionsCond.Signal()
		}
	}
	s.sessionsMu.Unlock()
}

// serveDSO parses and dispatches DSO message, establishing [Session] if needed.
func (s *Server) serveDSO(sc *seshConn, msg []byte) (err error) {
	defer func() {
		// RFC 8490, Section 6.6.1.1: At the instant a server chooses to initiate
		// a DSO Retry Delay message, there may be DNS requests already in flight
		// from client to server on this DSO Session, which will arrive at the server
		// after its DSO Retry Delay message has been sent. The server MUST silently
		// ignore such incoming requests and MUST NOT generate any response
		// messages for them.
		if errors.Is(err, ErrSessionClosed) {
			err = nil
		}
	}()

	var parser MsgParser
	msgHeader, err := parser.Start(msg, OriginClient)
	if err != nil {
		return err
	}

	// RFC 8490, Section 5.2.2: If a client or server receives a response (QR=1)
	// where the MESSAGE ID is zero, or is any other value that does not match
	// the MESSAGE ID of any of its outstanding operations, this is a fatal error
	// and the recipient MUST forcibly abort the connection immediately.
	if !msgHeader.IsRequest() && !msgHeader.IsUnidirectional() {
		return ErrUnexpected
	}

	// RFC 8490, Section 7.3: It is only applicable when the DSO Transport layer uses
	// encryption such as TLS.
	var builder *MsgBuilder
	_, isTLS := sc.C.(*tls.Conn)
	if isTLS && parser.IsPadded() {
		bufPtr := tlsMsgPool.Get()
		defer func() { tlsMsgPool.Put(bufPtr) }()
		builder = NewMsgBuilder(*bufPtr)
		builder.EnablePadding(TLSBlockLen)
	} else {
		var msgBuf [32]byte // Server writes short replies with at most one KeepAlive TLV
		builder = NewMsgBuilder(msgBuf[:])
	}
	defer func() { builder.Finish() }()

	tlvHeader, err := parser.TLVHeader()
	if err != nil {
		return err
	}

	switch tlvHeader.Type {
	case TypeKeepAlive:
		return s.serveKeepAlive(sc, msgHeader, builder, &parser)
	case TypeSubscribe:
		return s.serveSubscribe(sc, msgHeader, builder, &parser)
	case TypeUnsubscribe:
		return s.serveUnsubscribe(sc, &parser)
	case TypeReconfirm:
		return s.serveReconfirm(sc, &parser)
	default:
		return s.serveUnexpected(sc, msgHeader, builder)
	}
}

// parseTLV checks usage, unpacks and verifies TLV.
func parseTLV[T TLV](expected, actual Usage, parseFunc func() (T, error)) (tlv T, err error) {
	if expected != actual {
		return tlv, ErrUnexpected
	}
	tlv, err = parseFunc()
	if err == nil {
		err = tlv.Verify(actual)
	}
	if err != nil {
		return tlv, err
	}
	return tlv, nil
}

func (s *Server) serveKeepAlive(sc *seshConn, msgHeader MsgHeader, builder *MsgBuilder, parser *MsgParser) (err error) {
	ka, err := parseTLV(UsageCP, parser.TLVUsage(), parser.KeepAlive)
	if err != nil {
		return err
	}

	if err = sc.EnsureSession(s); err != nil {
		return err
	}

	// Accept reduced timeout and keepalive as it helps the server shed
	// the connection sooner. Note the server merely agrees to receive KA
	// more often.

	sc.S.KeepAlive = KeepAlive{
		min(sc.S.KeepAlive.InactivityTimeout, ka.InactivityTimeout),
		max(min(sc.S.KeepAlive.KeepAliveInterval, ka.KeepAliveInterval), KeepAliveIntervalMin),
	}
	builder.SetMsgHeader(MsgHeader{
		ID:       msgHeader.ID,
		Response: true,
		Rcode:    dns.RcodeSuccess,
	})
	builder.WriteKeepAlive(sc.S.KeepAlive)
	return sc.Write(builder.Message())
}

func (s *Server) serveSubscribe(sc *seshConn, msgHeader MsgHeader, builder *MsgBuilder, parser *MsgParser) (err error) {
	var tlv Subscribe
	tlv, err = parseTLV(UsageCP, parser.TLVUsage(), parser.Subscribe)
	if err != nil {
		return err
	}

	// RFC 8765, Section 6.2.2: For RCODE = 5 (REFUSED), which occurs on a server that
	// implements DNS Push Notifications but is currently configured to disallow
	// DNS Push Notifications
	_, isTLS := sc.C.(*tls.Conn)
	if !isTLS || s.push == nil {
		return writeDSOError(sc, msgHeader.ID, dns.RcodeRefused, nil, builder)
	}

	// RFC 8765, Section 6.2.2: For RCODE = 9 (NOTAUTH), which occurs on a server
	// that implements DNS Push Notifications but is not configured to be authoritative
	// for the requested name
	if plugin.Zones(s.Config.Push.Zones).Matches(tlv.Name) == "" {
		return writeDSOError(sc, msgHeader.ID, dns.RcodeNotAuth, nil, builder)
	}

	upstream := s.upstream.Load()
	if upstream == nil {
		// Upstream is not yet known. Fail for now, but tell client to retry later.
		return writeDSOError(sc, msgHeader.ID, dns.RcodeServerFailure, &badUpstreamRetryDelay, builder)
	}

	if err = sc.EnsureSession(s); err != nil {
		return err
	}

	s.pushMu.Lock()
	sub, ok := s.push[sc.S]
	if !ok {
		sub = newSubscription(sc.S, upstream, s.Config.Push)
		s.push[sc.S] = sub
		go func() {
			sub.doRefresh()

			// Normally doRefresh runs as long as sesh is alive.
			// But in case something unexpected happens make sure
			// no more than one Subscription per session exists.

			<-sc.S.Done()
			s.pushMu.Lock()
			delete(s.push, sc.S)
			s.pushMu.Unlock()
		}()
	}
	s.pushMu.Unlock()

	return sub.Add(builder, msgHeader.ID, tlv)
}

func (s *Server) serveUnsubscribe(sc *seshConn, parser *MsgParser) (err error) {
	var tlv Unsubscribe
	tlv, err = parseTLV(UsageCU, parser.TLVUsage(), parser.Unsubscribe)
	if err != nil {
		return err
	}

	// RFC 8490, Section 5.1: Until a DSO Session has been ... established, a
	// client MUST NOT initiate DSO unidirectional messages.
	if sc.S == nil {
		return ErrUnexpected
	}

	if s.push == nil {
		return nil
	}

	s.pushMu.RLock()
	defer s.pushMu.RUnlock()

	if sub, ok := s.push[sc.S]; ok {
		sub.Remove(tlv)
	}
	return nil
}

func (s *Server) serveReconfirm(sc *seshConn, parser *MsgParser) (err error) {
	var tlv Reconfirm
	tlv, err = parseTLV(UsageCU, parser.TLVUsage(), parser.Reconfirm)
	if err != nil {
		return err
	}

	// RFC 8490, Section 5.1: Until a DSO Session has been ... established, a
	// client MUST NOT initiate DSO unidirectional messages.
	if sc.S == nil {
		return ErrUnexpected
	}

	if s.push == nil {
		return nil
	}

	s.pushMu.RLock()
	defer s.pushMu.RUnlock()

	if sub, ok := s.push[sc.S]; ok {
		sub.Reconfirm(tlv)
	}
	return nil
}

func (s *Server) serveUnexpected(sc *seshConn, msgHeader MsgHeader, builder *MsgBuilder) (err error) {
	if msgHeader.IsRequest() {
		// RFC 8490, Section 5.4.5: If a DSO request message is received containing
		// an unrecognized Primary TLV ... then the receiver MUST send an error response
		// with a matching MESSAGE ID, and RCODE DSOTYPENI.
		return writeDSOError(sc, msgHeader.ID, dns.RcodeStatefulTypeNotImplemented, nil, builder)
	} else {
		// RFC 8490, Section 5.4.5: If a DSO unidirectional message is received containing
		// ... an unrecognized Primary TLV ... then this is a fatal error and the recipient
		// MUST forcibly abort the connection immediately.
		return ErrUnexpected
	}
}

// SetUpstream used by [Handler] to set upstream once it's avaialble.
func (s *Server) SetUpstream(upstream *dnsserver.Server) {
	s.upstream.CompareAndSwap(nil, upstream)
}

// Refresh refreshes subscriptions of all push clients ahead of periodic interval.
func (s *Server) Refresh() {
	if s.push == nil {
		return
	}
	s.pushMu.RLock()
	for _, sub := range s.push {
		sub.Refresh()
	}
	s.pushMu.RUnlock()
}

func (h *tcpHandler) msgAccept(dh dns.Header) dns.MsgAcceptAction {
	return dns.MsgRejectNotImplemented
}

func readTCP(dso *Server, conn net.Conn, tcpConn *net.TCPConn, reader dns.Reader, timeout time.Duration) (msg []byte, err error) {
	defer func() {
		// [dns.Server] closes connection on error.
		if err != nil {
			dso.ConnClosed(conn)
		}
	}()

	var (
		sc       = newSeshConn(dso, conn)
		shutdown = dso.shutdown.Load()
	)
	for {
		if msg, err = sc.S.ReadMsg(reader, conn, timeout); err != nil {
			return nil, err
		}

		shutdown = shutdown || dso.shutdown.Load() // shutdown remains set
		if shutdown {
			// Keep reading until [Server.Shutdown] closes connection.
			continue
		}

		if len(msg) >= MsgHeaderLen {
			// Handle DSO outside of dns.Server's loop.
			bits := binary.BigEndian.Uint16(msg[2:])
			opcode := int(bits>>11) & 0xF
			if opcode == dns.OpcodeStateful {
				if err = dso.serveDSO(sc, msg); err != nil {
					tcpConn.SetLinger(0)
					return nil, err
				} else {
					continue
				}
			}
		}

		return msg, err
	}
}

// ReadTCP implements [dns.Reader.ReadTCP].
func (h *tcpHandler) ReadTCP(conn net.Conn, timeout time.Duration) (msg []byte, err error) {
	return readTCP(h.dso, conn, conn.(*net.TCPConn), h.reader, timeout)
}

// ReadUDP implements [dns.Reader.ReadUDP].
func (h *tcpHandler) ReadUDP(conn *net.UDPConn, timeout time.Duration) ([]byte, *dns.SessionUDP, error) {
	panic("TLSHandler should never get ReadUDP!")
}

// ServeDNS implements [dns.Handler.ServeDNS].
func (h *tcpHandler) ServeDNS(w dns.ResponseWriter, m *dns.Msg) {
	panic("TCPHandler should never get ReadUDP!")
}

func (h *tlsHandler) msgAccept(dh dns.Header) dns.MsgAcceptAction {
	opcode := int(dh.Bits>>11) & 0xF
	switch {
	case h.dso.push != nil && opcode == dns.OpcodeQuery:
		return dns.DefaultMsgAcceptFunc(dh)
	default:
		return dns.MsgRejectNotImplemented
	}
}

// ServeDNS implements [dns.Handler.ServeDNS].
func (h *tlsHandler) ServeDNS(w dns.ResponseWriter, m *dns.Msg) {
	state := request.Request{W: w, Req: m}
	if plugin.Zones(h.dso.Config.Push.Zones).Matches(state.Name()) == "" {
		writeDNSError(w, m, dns.RcodeNotAuth)
		return
	}

	upstream := h.dso.upstream.Load()
	if upstream == nil {
		// Upstream is currently unknown, but will be eventually set by [Handler].
		writeDNSError(w, m, dns.RcodeServerFailure)
		return
	}

	// RFC 8765, Section 3: For any zone for which the server is authoritative, it
	// MUST respond authoritatively for queries for names falling within
	// that zone
	answer := lookup.Do(upstream, w, m)
	if !answer.Authoritative {
		log.Warningf("DSO failed to answer authoritatively to %q", m.Question[0].String())
	}
	w.WriteMsg(answer)
}

// ReadTCP implements [dns.Reader.ReadTCP].
func (h *tlsHandler) ReadTCP(conn net.Conn, timeout time.Duration) (msg []byte, err error) {
	return readTCP(h.dso, conn, conn.(*tls.Conn).NetConn().(*net.TCPConn), h.reader, timeout)
}

// ReadUDP implements [dns.Reader.ReadUDP].
func (h *tlsHandler) ReadUDP(conn *net.UDPConn, timeout time.Duration) ([]byte, *dns.SessionUDP, error) {
	panic("TLSHandler should never get ReadUDP!")
}

func newSeshConn(s *Server, conn net.Conn) (sc *seshConn) {
	s.sessionsMu.RLock()
	sc = &seshConn{
		S: s.sessions[conn],
		C: conn,
	}
	s.sessionsMu.RUnlock()
	return sc
}

func (sc *seshConn) EnsureSession(s *Server) error {
	if sc.S != nil {
		return nil
	}
	return sc.ensureSessionSlow(s)
}

func (sc *seshConn) ensureSessionSlow(s *Server) error {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()

	if s.shutdown.Load() {
		return ErrSessionClosed
	}

	var ok bool
	sc.S, ok = s.sessions[sc.C]
	if !ok {
		sc.S = NewSession(sc.C, KeepAlive{
			InactivityTimeout: uint32(s.Config.InactivityTimeout.Milliseconds()), //nolint:gosec
			KeepAliveInterval: uint32(s.Config.KeepAliveInterval.Milliseconds()), //nolint:gosec
		})
		s.sessions[sc.C] = sc.S
	}
	return nil
}

func (sc *seshConn) Write(msg []byte) (err error) {
	if sc.S != nil {
		err = sc.S.WriteMsg(msg)
	} else {
		_, err = sc.C.Write(msg)
	}
	return err
}

func writeDSOError(sc *seshConn, id uint16, rcode uint8, rd *RetryDelay, builder *MsgBuilder) error {
	builder.SetMsgHeader(MsgHeader{
		ID:       id,
		Response: true,
		Rcode:    rcode,
	})
	if rd != nil {
		builder.WriteRetryDelay(*rd)
	}
	return sc.Write(builder.Message())
}

func writeDNSError(w dns.ResponseWriter, m *dns.Msg, rcode int) error {
	state := request.Request{W: w, Req: m}
	answer := new(dns.Msg)
	answer.SetRcode(m, rcode)
	state.SizeAndDo(answer)
	return w.WriteMsg(answer)
}

var (
	// tlsMsgPool used by [Server] for writes that require encryption padding.
	tlsMsgPool = NewMsgPool(TLSBlockLen)

	// badUpstreamRetryDelay is included in error response to subscription request
	// when upstream is not yet known.
	badUpstreamRetryDelay = RetryDelay{RetryDelay: uint32(time.Second.Milliseconds())}
)
