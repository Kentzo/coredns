//go:build ignore
package testutil

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/dso"
	"github.com/coredns/coredns/plugin/dso/internal/push"
	"github.com/miekg/dns"
)

func questionMatch(a, b dns.Question) bool {
	switch {
	case a.Name != b.Name:
		return false
	case a.Qclass != b.Qclass && a.Qclass != dns.ClassANY && b.Qclass != dns.ClassANY:
		return false
	case a.Qtype != b.Qtype && a.Qtype != dns.TypeANY && b.Qtype != dns.TypeANY:
		return false
	default:
		return true
	}
}

type Answers struct {
	m    map[dns.Question][]dns.RR
	keys []dns.Question
	mu   sync.RWMutex
}

func NewAnswers() *Answers {
	return &Answers{
		m: make(map[dns.Question][]dns.RR),
	}
}

func (a *Answers) add(rrs ...dns.RR) {
	for _, rr := range rrs {
		h := rr.Header()
		q := dns.Question{Name: h.Name, Qclass: h.Class, Qtype: h.Rrtype}
		if q.Qclass == dns.ClassANY || q.Qtype == dns.TypeANY {
			panic("unexpected RR class or type")
		}
		qrrs, qexists := a.m[q]
		if !qexists {
			a.keys = append(a.keys, q)
		}
		rrexists := ContainsRR(qrrs, rr)
		if !rrexists {
			a.m[q] = append(qrrs, dns.Copy(rr))
		}
	}
}

// SetRR resets all records to RRs.
func (a *Answers) SetRR(rrs ...dns.RR) {
	a.mu.Lock()
	defer a.mu.Unlock()

	clear(a.m)
	clear(a.keys)
	a.keys = a.keys[:0]
	a.add(rrs...)
}

// AddRR appends unique RRs.
func (a *Answers) AddRR(rrs ...dns.RR) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.add(rrs...)
}

// SetQ resets records of a given question, duplicate RRs as well as nil are allowed.
func (a *Answers) SetQ(q dns.Question, rrs ...dns.RR) {
	a.mu.Lock()
	defer a.mu.Unlock()

	_, exists := a.m[q]
	a.m[q] = CloneRRSet(rrs)
	if !exists {
		a.keys = append(a.keys, q)
	}
}

// LoadQ returns records for a given question.
func (a *Answers) LoadQ(q dns.Question) (rrs []dns.RR, ok bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	rrs, ok = a.m[q]
	return rrs, ok
}

// LoadAnyQ returns records for a question picked at random.
func (a *Answers) LoadAnyQ(prng *rand.Rand) (q dns.Question, rrs []dns.RR, ok bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if len(a.keys) > 0 {
		ok = true
		i := prng.IntN(len(a.keys))
		q = a.keys[i]
		rrs = CloneRRSet(a.m[q])
	}
	return q, rrs, ok
}

// Clear removes all records.
func (a *Answers) Clear() {
	a.mu.Lock()
	defer a.mu.Unlock()

	clear(a.m)
	clear(a.keys)
	a.keys = a.keys[:0]
}

// DeleteQ removes a given question.
func (a *Answers) DeleteQ(q dns.Question) (ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	i := slices.Index(a.keys, q)
	if i == -1 {
		return false
	}
	delete(a.m, q)
	a.keys = slices.Delete(a.keys, i, i+1)
	return true
}

// RemoveRR removes a given RR.
func (a *Answers) RemoveRR(rrs ...dns.RR) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for _, rr := range rrs {
		h := rr.Header()
		q := dns.Question{Name: h.Name, Qclass: h.Class, Qtype: h.Rrtype}
		if q.Qclass == dns.ClassANY || q.Qtype == dns.TypeANY {
			panic("unexpected RR class or type")
		}
		rrs, exists := a.m[q]
		if exists {
			a.m[q] = DeleteRR(rrs, rr)
		}
	}
}

// Clone returns a deep copy of records as [map].
func (a *Answers) Clone() (m map[dns.Question][]dns.RR) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	m = make(map[dns.Question][]dns.RR, len(a.m))
	for q, rrs := range a.m {
		m[q] = CloneRRSet(rrs)
	}
	return m
}

type MapPlugin struct {
	Answers *Answers
}

func NewMapPlugin() *MapPlugin {
	return &MapPlugin{
		Answers: NewAnswers(),
	}
}

func (p *MapPlugin) Name() string { return "map" }

func (p *MapPlugin) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	m := new(dns.Msg)
	if rrs, ok := p.Answers.LoadQ(r.Question[0]); ok {
		m.SetReply(r)
		for _, rr := range rrs {
			m.Answer = append(m.Answer, dns.Copy(rr))
		}
	} else {
		m.SetRcode(r, dns.RcodeNameError)
	}
	w.WriteMsg(m)
	return dns.RcodeSuccess, nil
}

type Subscription struct {
	ID uint16
	Q  dns.Question
}

type pendingReq struct {
	m    *dns.Msg
	repC chan *dns.Msg
}

// Simple DSO client that can handle TCP pipelining.
type Client struct {
	Subs    []Subscription
	Answers *Answers

	mu         sync.Mutex
	kaInterval time.Duration
	kaTimer    *time.Timer

	conn    *dns.Conn
	pending map[uint16]pendingReq

	ctx    context.Context
	cancel context.CancelCauseFunc
	doneC  chan struct{}
}

func NewClient(conn *dns.Conn) *Client {
	c := &Client{
		Answers:    NewAnswers(),
		kaInterval: dns.DSOKeepAliveIntervalDefault,
		kaTimer:    time.NewTimer(dns.DSOKeepAliveIntervalDefault),
		pending:    make(map[uint16]pendingReq),
		conn:       conn,
		doneC:      make(chan struct{}),
	}
	c.kaTimer.Stop()
	c.ctx, c.cancel = context.WithCancelCause(context.TODO())
	return c
}

func (c *Client) ExchangeKeepAliveMsg() (err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	m, err := c.exchange(NewReqMsg(c.uniqueID()))
	if err != nil {
		return err
	}
	newInterval := time.Duration(m.Stateful[0].(*dns.DSOKeepAlive).KeepAliveInterval) * time.Millisecond
	if c.kaInterval != newInterval {
		c.kaInterval = newInterval
		c.kaTimer.Reset(c.kaInterval)
	}
	return nil
}

func (c *Client) ExchangeSubscribeMsg(q dns.Question) (id uint16, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	subscribed := slices.ContainsFunc(c.Subs, func(s Subscription) bool {
		return s.Q == q
	})
	id = c.uniqueID()
	c.Subs = append(c.Subs, Subscription{id, q})
	_, err = c.exchange(NewPushSubMsg(id, q.Name, q.Qtype, q.Qclass))
	if subscribed && err == nil {
		err = fmt.Errorf("unexpected successful duplicate subscribe")
	}
	if err != nil {
		c.cancel(err)
		return 0, err
	}
	return id, nil
}

func (c *Client) WriteUnsubscribeMsg(id uint16) (err error) {
	err = c.WriteMsg(NewPushUnsubMsg(id))
	if err != nil {
		return err
	}
	i := slices.IndexFunc(c.Subs, func(s Subscription) bool {
		return s.ID == id
	})
	if i == -1 {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.Subs = slices.Delete(c.Subs, i, i+1)
	return nil
}

func (c *Client) WriteReconfirmMsg(rr dns.RR) error {
	return c.WriteMsg(NewPushReconfirmMsg(rr))
}

func (c *Client) WriteMsg(m *dns.Msg) (err error) {
	err = c.conn.WriteMsg(m)
	if err == nil {
		c.kaTimer.Reset(c.kaInterval)
	}
	return err
}

func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) Abort() error {
	c.conn.Conn.(*net.TCPConn).SetLinger(0)
	return c.conn.Close()
}

func (c *Client) Err() (err error) {
	err = context.Cause(c.ctx)
	if errors.Is(err, context.Canceled) {
		err = nil
	}
	return err
}

func (c *Client) Done() <-chan struct{} {
	return c.doneC
}

func (c *Client) handleClose() {
	c.cancel(nil)
}

func (c *Client) handleKA(m *dns.Msg) {
	err := dns.IsValidDSOMsg(m, true, nil)
	if err != nil {
		c.cancel(err)
		return
	}

	newInterval := time.Duration(m.Stateful[0].(*dns.DSOKeepAlive).KeepAliveInterval) * time.Millisecond
	if c.kaInterval != newInterval {
		c.kaInterval = newInterval
		c.kaTimer.Reset(c.kaInterval)
	}
}

func (c *Client) handlePushUpdate(m *dns.Msg) {
	err := dns.IsValidDSOMsg(m, true, nil)
	if err != nil {
		c.cancel(err)
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	tlv := m.Stateful[0].(*dns.DSOPush)
	for _, rr := range tlv.Change {
		h := rr.Header()
		q := dns.Question{Name: h.Name, Qclass: h.Class, Qtype: h.Rrtype}
		subscribed := slices.ContainsFunc(c.Subs, func(s Subscription) bool {
			return questionMatch(s.Q, q)
		})
		switch {
		case !subscribed:
			continue
		case h.Ttl == dns.DSOPushTTLRemove:
			c.Answers.RemoveRR(rr)
		case dns.DSOPushTTLAddMin <= h.Ttl && h.Ttl <= dns.DSOPushTTLAddMax:
			c.Answers.AddRR(rr)
		default:
			c.cancel(fmt.Errorf("unexpected ttl %v", h.Ttl))
			return
		}
	}
}

func (c *Client) handleResponse(m *dns.Msg) {
	c.mu.Lock()
	defer c.mu.Unlock()

	p, ok := c.pending[m.Id]
	if ok {
		delete(c.pending, m.Id)
	} else {
		c.cancel(fmt.Errorf("unexpected response %v", m))
		return
	}

	err := dns.IsValidDSOMsg(m, true, p.m)
	if err == nil {
		p.repC <- m
	} else {
		p.repC <- nil
		c.cancel(err)
		return
	}
}

func (c *Client) Serve() {
	type read struct {
		m   *dns.Msg
		err error
	}
	readC := make(chan read, 1)
	go func() {
		var r read
		for r.err == nil {
			m, err := c.conn.ReadMsg()
			r = read{m, err}
			readC <- r
		}
		close(readC)
	}()

	defer func() {
		c.kaTimer.Stop()

		cause := context.Cause(c.ctx)
		switch {
		case cause == nil:
			fallthrough
		case errors.Is(cause, context.Canceled):
			c.Close()
		default:
			c.Abort()
		}

		for range readC {
		}
		close(c.doneC)
	}()

	for c.ctx.Err() == nil {
		select {
		case <-c.kaTimer.C:
			go c.ExchangeKeepAliveMsg()
		case r := <-readC:
			switch {
			case errors.Is(r.err, net.ErrClosed):
				fallthrough
			case errors.Is(r.err, io.EOF):
				c.cancel(nil)
			case r.err != nil:
				c.cancel(r.err)
			case dns.IsDSOUnidirectional(r.m) && r.m.Stateful[0].DSOType() == dns.StatefulTypeRetryDelay:
				c.handleClose()
			case dns.IsDSOUnidirectional(r.m) && r.m.Stateful[0].DSOType() == dns.StatefulTypeKeepAlive:
				c.handleKA(r.m)
			case dns.IsDSOUnidirectional(r.m) && r.m.Stateful[0].DSOType() == dns.StatefulTypePush:
				c.handlePushUpdate(r.m)
			case dns.IsDSOResponse(r.m):
				c.handleResponse(r.m)
			default:
				c.cancel(fmt.Errorf("unexpected message %v", r.m))
			}
		}
	}
}

func (c *Client) exchange(m *dns.Msg) (*dns.Msg, error) {
	repC := make(chan *dns.Msg, 1)
	c.pending[m.Id] = pendingReq{m, repC}
	c.mu.Unlock()
	defer func() {
		defer close(repC)
		c.mu.Lock()
		delete(c.pending, m.Id)
	}()

	err := c.WriteMsg(m)

	if err != nil {
		return nil, err
	}

	select {
	case m := <-repC:
		switch {
		case m == nil:
			return nil, fmt.Errorf("bad response")
		case m.Rcode != dns.RcodeSuccess:
			return nil, fmt.Errorf("rcode %v", m.Rcode)
		default:
			return m, nil
		}
	case <-c.doneC:
		return nil, fmt.Errorf("closed: %w", context.Cause(c.ctx))
	}
}

func (c *Client) uniqueID() uint16 {
	var id uint16
	for {
		id = dns.Id()
		if id == 0 {
			continue
		}
		if _, taken := c.pending[id]; taken {
			continue
		}
		taken := slices.ContainsFunc(c.Subs, func(s Subscription) bool {
			return s.ID == id
		})
		if taken {
			continue
		}
		break
	}
	return id
}

func CheckParity(c *Client, p *MapPlugin) (changes map[dns.Question][]dns.RR) {
	cA := c.Answers.Clone()
	pA := p.Answers.Clone()
	changes = make(map[dns.Question][]dns.RR)
	for q, want := range pA {
		subscribed := slices.ContainsFunc(c.Subs, func(s Subscription) bool {
			return questionMatch(s.Q, q)
		})
		if subscribed {
			got := cA[q]
			_, changeBuf, _ := push.ComputeChange(got, want, nil)
			if len(*changeBuf) > 0 {
				changes[q] = *changeBuf
			}
		}
	}
	return changes
}

// SetupStubServer returns stub server without listening socket and just enough to handle ServeDNS calls.
func SetupStubServer(tb testing.TB) (*dnsserver.Server, *MapPlugin) {
	tb.Helper()

	cfg := &dnsserver.Config{
		Zone:        ".",
		Transport:   "dns",
		ListenHosts: []string{""},
		Port:        "",
		Debug:       false,
		Stacktrace:  false,
	}
	mapPlugin := NewMapPlugin()
	cfg.AddPlugin(func(next plugin.Handler) plugin.Handler { return mapPlugin })
	s, err := dnsserver.NewServer("dns://", []*dnsserver.Config{cfg})
	if err != nil {
		tb.Fatalf("Expected Server, got %v", err)
	}
	return s, mapPlugin
}

// SetupServer returns proper server with listening socket that can handle DSO.
func SetupServer(tb testing.TB, dsoRules string) (*dnsserver.Server, *MapPlugin, *dso.DSO) {
	tb.Helper()

	cfg := &dnsserver.Config{
		Zone:        ".",
		Transport:   "dns",
		ListenHosts: []string{"127.0.0.1"},
		Port:        "0",
		Debug:       false,
		Stacktrace:  false,
	}

	c := caddy.NewTestController("dns", dsoRules)
	c.ServerBlockKeys = append(c.ServerBlockKeys, ".")
	dsoPlugin, err := dso.Parse(c)
	if err != nil {
		tb.Fatalf("Expected DSO plugin, got %v", err)
	}
	cfg.AddPlugin(func(next plugin.Handler) plugin.Handler {
		dsoPlugin.Next = next
		return dsoPlugin
	})

	mapPlugin := NewMapPlugin()
	cfg.AddPlugin(func(next plugin.Handler) plugin.Handler { return mapPlugin })

	server, err := dnsserver.NewServer("dns://", []*dnsserver.Config{cfg})
	if err != nil {
		tb.Fatalf("Expected server, got %v", err)
	}
	server.IdleTimeout = 24 * time.Hour
	server.ReadTimeout = 24 * time.Hour
	server.WriteTimeout = 24 * time.Hour
	tb.Cleanup(func() {
		server.Stop()
	})

	l, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		tb.Fatalf("Expected listener, got %v", err)
	}
	server.Addr = "dns://" + l.Addr().String()
	go server.Serve(l)

	err = dsoPlugin.OnFirstStartup()
	if err != nil {
		tb.Fatalf("Expected DSO plugin to startup, got %v", err)
	}
	tb.Cleanup(func() {
		dsoPlugin.OnFinalShutdown()
	})

	return server, mapPlugin, dsoPlugin
}

func SetupClient(tb testing.TB, server *dnsserver.Server) *Client {
	tb.Helper()

	c := new(dns.Client)
	c.Net = "tcp"
	c.Dialer = &net.Dialer{}
	c.DialTimeout = 1 * time.Hour
	c.Timeout = 1 * time.Hour
	c.ReadTimeout = 1 * time.Hour
	c.WriteTimeout = 1 * time.Hour
	conn, err := c.DialContext(tb.Context(), server.Addr[6:])
	if err != nil {
		tb.Fatalf("Expected to Dial, got %v", err)
	}
	client := NewClient(conn)
	tb.Cleanup(func() {
		client.Close()
	})
	go client.Serve()
	return client
}
