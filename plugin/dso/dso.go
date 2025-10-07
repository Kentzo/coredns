// Package dso provide the DNS Stateful Operations (DSO) handler.
package dso

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/debug"

	"github.com/miekg/dns"
)

type dsoOpts struct {
	cleanup  time.Duration
	restart  time.Duration
	shutdown time.Duration
}

type DSO struct {
	sync.RWMutex

	Next plugin.Handler

	sessions map[SessionID]*Session
	opts     dsoOpts
	cleanupT *time.Ticker
	doneC    chan struct{}

	logH  *logHandler
	pushH *pushHandler
}

func New(opts dsoOpts) *DSO {
	return &DSO{
		sessions: make(map[SessionID]*Session),
		opts:     opts,
	}
}

func (d *DSO) Name() string { return "dso" }

func (d *DSO) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	if r.Opcode != dns.OpcodeStateful {
		return plugin.NextOrFailure(d.Name(), d.Next, ctx, w, r)
	}

	if d.logH != nil {
		w = d.logH.newWriter(ctx, w, r)
	}

	rcode, sesh, _ := d.ServeDSO(ctx, w, r)
	switch rcode {
	case dns.RcodeSuccess:
		// Do nothing.
	case dns.RcodeServerFailure:
		if sesh != nil {
			sesh.Abort(w)
		} else {
			AbortConn(w)
		}
	default:
		m := new(dns.Msg)
		dns.SetDSOResponse(m, r, rcode)
		w.WriteMsg(m)
	}
	return dns.RcodeSuccess, nil
}

// ServeDSO handles stateful DNS messages.
//
// [dns.RcodeSuccess] indicates that the message was handled, [dns.RcodeServerFailure] indicates
// that the connection must be aborted. Other rcodes must be sent back to the client.
func (d *DSO) ServeDSO(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, *Session, error) {
	// RFC 8490, Section 5.2.2: If a client or server receives a response (QR=1)
	// where the MESSAGE ID is zero, or is any other value that does not match
	// the MESSAGE ID of any of its outstanding operations, this is a fatal error
	// and the recipient MUST forcibly abort the connection immediately.
	if !dns.IsDSORequest(r) && !dns.IsDSOUnidirectional(r) {
		return dns.RcodeServerFailure, nil, nil
	}

	t := r.Stateful[0].DSOType()
	switch t {
	case dns.StatefulTypeKeepAlive:
	case dns.StatefulTypeSubscribe:
		fallthrough
	case dns.StatefulTypeUnsubscribe:
		fallthrough
	case dns.StatefulTypeReconfirm:
		// RFC 8765, Section 6.2.2: For RCODE = 5 (REFUSED), which occurs on a server that
		// implements DNS Push Notifications but is currently configured to disallow
		// DNS Push Notifications
		if d.pushH == nil {
			return dns.RcodeRefused, nil, nil
		}
	default:
		// RFC 8490, Section 5.4.5: If a DSO request message is received containing
		// an unrecognized Primary TLV, with a nonzero MESSAGE ID (indicating that
		// a response is expected), then the receiver MUST send an error response
		// with a matching MESSAGE ID, and RCODE DSOTYPENI.
		if dns.IsDSORequest(r) {
			return dns.RcodeStatefulTypeNotImplemented, nil, nil
		}

		// RFC 8490, Section 5.4.5: If a DSO unidirectional message is received containing
		// ... an unrecognized Primary TLV ... then this is a fatal error and the recipient
		// MUST forcibly abort the connection immediately.
		return dns.RcodeServerFailure, nil, nil
	}

	if dns.IsValidDSOMsg(r, false, nil) != nil {
		debug.Hexdumpf(r, "Invalid DSO message")
		return dns.RcodeServerFailure, nil, nil
	}

	sesh := d.GetSession(ctx, w)
	if err := sesh.IsValidState(r); err != nil {
		// RFC 8490, Section 6.6.1.1: At the instant a server chooses to initiate
		// a DSO Retry Delay message, there may be DNS requests already in flight
		// from client to server on this DSO Session, which will arrive at the server
		// after its DSO Retry Delay message has been sent. The server MUST silently
		// ignore such incoming requests and MUST NOT generate any response
		// messages for them.
		if errors.Is(err, ErrSessionClosed) {
			return dns.RcodeSuccess, sesh, nil
		}
		debug.Hexdumpf(r, "Session is not ready for DSO message: %s", sesh.State())
		return dns.RcodeServerFailure, sesh, nil
	}

	switch t {
	case dns.StatefulTypeKeepAlive:
		// CoreDNS's timeouts are not adjustable: ignore values requested by the client.
		m := new(dns.Msg)
		dns.SetDSOResponse(m, r, dns.RcodeSuccess)
		m.Stateful = append(m.Stateful, sesh.DefaultKeepAlive)
		sesh.WriteMsg(w, m)
		return dns.RcodeSuccess, sesh, nil
	case dns.StatefulTypeSubscribe:
		fallthrough
	case dns.StatefulTypeUnsubscribe:
		fallthrough
	case dns.StatefulTypeReconfirm:
		rcode, err := d.pushH.ServeDSO(sesh, w, r)
		return rcode, sesh, err
	}

	panic("unexpected DSO TLV")
}

// GetSession allocates or returns existing DSO session for a given connection.
func (d *DSO) GetSession(ctx context.Context, w dns.ResponseWriter) *Session {
	id := NewSessionID(ctx, w)

	d.Lock()
	sesh, ok := d.sessions[id]
	if !ok {
		sesh = NewSessionWithID(ctx, w, id)
		d.sessions[id] = sesh
		go func() {
			<-sesh.doneC
			d.Lock()
			delete(d.sessions, id)
			d.Unlock()
		}()
	}
	d.Unlock()

	return sesh
}

func (d *DSO) OnStartup() error {
	d.cleanupT = time.NewTicker(d.opts.cleanup)
	d.doneC = make(chan struct{})
	go d.doCleanup(d.cleanupT, d.doneC)
	return nil
}

func (d *DSO) OnRestart() error {
	d.cleanupT.Stop()
	close(d.doneC)

	d.Lock()
	for _, sesh := range d.sessions {
		go sesh.Close(nil, d.opts.restart, dns.RcodeSuccess)
	}
	d.Unlock()
	return nil
}

func (d *DSO) OnFinalShutdown() error {
	d.cleanupT.Stop()
	close(d.doneC)

	d.Lock()
	for _, sesh := range d.sessions {
		go sesh.Close(nil, d.opts.shutdown, dns.RcodeSuccess)
	}
	d.Unlock()
	return nil
}

// doCleanup periodically checks sessions and releases resources for closed or dead connections.
func (d *DSO) doCleanup(cleanupT *time.Ticker, doneC chan struct{}) {
	for {
		select {
		case <-cleanupT.C:
			var wg sync.WaitGroup
			d.Lock()
			for id, sesh := range d.sessions {
				wg.Add(1)
				go func() {
					if sesh.State() == SessionClosed {
						return
					}
					if CheckConn(id.conn) != nil {
						sesh.OnConnClosed()
					}
					wg.Done()
				}()
			}
			d.Unlock()
			wg.Wait()
		case <-doneC:
			return
		}
	}
}
