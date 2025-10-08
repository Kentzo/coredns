package dso

import (
	"context"
	"errors"
	"iter"
	"sync"
	"time"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/nonwriter"
	"github.com/coredns/coredns/plugin/pkg/response"
	"github.com/miekg/dns"
)

type pushOpts struct {
	zones      []string
	anyTypes   []uint16
	anyClasses []uint16
	refresh    time.Duration
	debounce   time.Duration
	maxSubs    int
}

type pushHandler struct {
	sync.RWMutex
	opts pushOpts
	subs map[SessionID]*subscription
}

func newPushHandler(opts pushOpts) *pushHandler {
	return &pushHandler{
		opts: opts,
		subs: make(map[SessionID]*subscription),
	}
}

func (p *pushHandler) ServeDSO(sesh *Session, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	switch tlv := r.Stateful[0].(type) {
	case *dns.DSOSubscribe:
		return p.subscribe(sesh, w, r, tlv)
	case *dns.DSOUnsubscribe:
		return p.unsubscribe(sesh, tlv)
	case *dns.DSOReconfirm:
		return p.reconfirm(tlv)
	default:
		panic("unexpected DSO TLV")
	}
}

func (p *pushHandler) subscribe(sesh *Session, w dns.ResponseWriter, r *dns.Msg, tlv *dns.DSOSubscribe) (int, error) {
	if plugin.Zones(p.opts.zones).Matches(tlv.Name) == "" {
		// RFC 8765, Section 6.2.2: For RCODE = 9 (NOTAUTH), which occurs on a server
		// that implements DNS Push Notifications but is not configured to be authoritative
		// for the requested name
		return dns.RcodeNotAuth, nil
	}

	p.Lock()
	sub, ok := p.subs[sesh.ID]
	if !ok {
		sub = newSubscription(sesh, &p.opts)
		p.subs[sesh.ID] = sub
	}
	p.Unlock()

	err := sub.add(r.Id, *tlv)
	switch {
	case err == nil:
		sesh.WriteMsg(w, dns.SetDSOResponse(new(dns.Msg), r, dns.RcodeSuccess))
		return dns.RcodeSuccess, nil
	case errors.Is(err, errLimit):
		// RcodeServerFailure is sent back to indicate that server's resources are exhausted.
		sesh.WriteMsg(w, dns.SetDSOResponse(new(dns.Msg), r, dns.RcodeServerFailure))
		return dns.RcodeSuccess, nil
	case errors.Is(err, errDup):
		fallthrough
	case errors.Is(err, errClosed):
		fallthrough
	default:
		// RFC 8765, Section 6.2.1: If a server receives such a duplicate SUBSCRIBE message,
		// this is a fatal error and the server MUST forcibly abort the connection immediately.
		return dns.RcodeServerFailure, nil
	}
}

func (p *pushHandler) unsubscribe(sesh *Session, tlv *dns.DSOUnsubscribe) (int, error) {
	p.RLock()
	sub, ok := p.subs[sesh.ID]
	p.RUnlock()

	if ok {
		sub.remove(tlv.SubscribeId)
	}

	// RFC 8765, Section 6.4.1: servers MUST silently ignore UNSUBSCRIBE messages that
	// do not match any currently active subscription.
	return dns.RcodeSuccess, nil
}

func (p *pushHandler) reconfirm(tlv *dns.DSOReconfirm) (int, error) {
	p.RLock()
	for _, s := range p.subs {
		s.confirm(*tlv)
	}
	p.RUnlock()

	return dns.RcodeSuccess, nil
}

type subscription struct {
	sync.Mutex
	byID   map[uint16]dns.DSOSubscribe
	byTLV  map[dns.DSOSubscribe]struct{}

	active map[dns.DSOSubscribe]int
	pending  map[dns.DSOSubscribe]int
	reconfirm  map[dns.DSOSubscribe]dns.RR

	addC chan struct{}
	confirmC chan struct{}

	opts *pushOpts
}

func newSubscription(sesh *Session, opts *pushOpts) *subscription {
	s := subscription{
		byID:  make(map[uint16]dns.DSOSubscribe),
		byTLV: make(map[dns.DSOSubscribe]struct{}),
		active: make(map[dns.DSOSubscribe]int),
		pending:  make(map[dns.DSOSubscribe]int),
		reconfirm:  make(map[dns.DSOSubscribe]dns.RR),
		addC: make(chan struct{}, 1),
		confirmC: make(chan struct{}, 1),
		opts: opts,
	}
	go s.doRefresh(sesh)
	return &s
}

// add expands, if necessary, and adds subscription for a given TLV.
func (s *subscription) add(id uint16, tlv dns.DSOSubscribe) error {
	s.Lock()
	defer s.Unlock()

	if s.byID == nil {
		return errClosed
	}
	if len(s.byID) > s.opts.maxSubs {
		return errLimit
	}
	if _, ok := s.byID[id]; ok {
		return errDup
	}
	if _, ok := s.byTLV[tlv]; ok {
		return errDup
	}

	s.byID[id] = tlv
	s.byTLV[tlv] = struct{}{}
	for t := range expandSubscribeTLV(tlv, s.opts) {
		s.pending[t] += 1
		if s.active[t] == 0 && s.pending[t] == 1 {
			select {
			case s.addC <- struct{}{}:
			default:
			}
		}
	}
	return nil
}

// remove removes the subscriptions associated with a given ID, if one exists.
func (s *subscription) remove(id uint16) {
	s.Lock()
	defer s.Unlock()

	tlv, ok := s.byID[id]
	if !ok {
		return // not subscribed or stopped
	}

	for t := range expandSubscribeTLV(tlv, s.opts) {
		s.pending[t] -= 1
	}
	delete(s.byID, id)
	delete(s.byTLV, tlv)
}

func (s *subscription) confirm(tlv dns.DSOReconfirm) {
	h := tlv.Rr.Header()
	t := dns.DSOSubscribe{
		Name:   h.Name,
		Rrtype: h.Rrtype,
		Class:  h.Class,
	}

	s.Lock()
	defer s.Unlock()

	if _, ok := s.byTLV[t]; !ok {
		return // not subscribed or stopped
	}

	s.reconfirm[t] = tlv.Rr
	select {
	case s.confirmC <- struct{}{}:
	default:
	}
}

// coalescePending processes pending and updates active.
func (s *subscription) coalescePending(add, remove bool) []dns.DSOSubscribe {
	var dirty []dns.DSOSubscribe
	for t, diffCount := range s.pending {
		oldCount := s.active[t]
		switch {
		case oldCount == 0 && diffCount > 0:
			if add {
				s.active[t] = diffCount
				dirty = append(dirty, t)
				delete(s.pending, t)
			}
		case oldCount > 0 && (oldCount+diffCount) <= 0:
			if remove {
				delete(s.active, t)
				delete(s.pending, t)
			}
		default:
			s.active[t] += diffCount
			delete(s.pending, t)
		}
	}
	return dirty
}

// doRefresh periodically fetches RRs and sends changes to client, if necessary.
func (s *subscription) doRefresh(sesh *Session) {
	defer func() {
		s.Lock()
		s.byID = nil
		s.byTLV = nil
		close(s.addC)
		close(s.confirmC)
		s.Unlock()
	}()

	server := sesh.ID.server
	ctx := context.WithValue(context.Background(), dnsserver.Key{}, server)
	nw := nonwriter.New(sesh.W)

	refreshTicker := time.NewTicker(s.opts.refresh)
	defer refreshTicker.Stop()

	cachedAnswers := make(map[dns.DSOSubscribe]dns.RR) // what server sent
Refresh:
	for {
		var (
			dirty         []dns.DSOSubscribe
			clientAnswers map[dns.DSOSubscribe]dns.RR // what client knows
		)

		select {
		case <-s.addC:
			select {
			case <-time.After(s.opts.debounce):
			case <-sesh.doneC:
				break Refresh
			}
			s.Lock()
			dirty = s.coalescePending(true, true)
			s.Unlock()
		case <-s.confirmC:
			select {
			case <-time.After(s.opts.debounce):
			case <-sesh.doneC:
				break Refresh
			}
			s.Lock()
			s.coalescePending(false, true)
			dirty = make([]dns.DSOSubscribe, 0, len(s.reconfirm))
			clientAnswers = make(map[dns.DSOSubscribe]dns.RR, len(s.reconfirm))
			for t, rr := range s.reconfirm {
				if _, ok := s.active[t]; !ok {
					continue // not subscribed
				}
				dirty = append(dirty, t)
				clientAnswers[t] = rr
			}
			s.Unlock()
		case <-refreshTicker.C:
			s.Lock()
			s.coalescePending(true, true)
			dirty = make([]dns.DSOSubscribe, 0, len(s.active))
			for t := range s.active {
				dirty = append(dirty, t)
			}
			s.Unlock()
		case <-sesh.doneC:
			break Refresh
		}

		if len(dirty) == 0 {
			continue Refresh // no changes
		}

		newAnswers := make(map[dns.DSOSubscribe]dns.RR, len(dirty))
		for _, t := range dirty {
			server.ServeDNS(ctx, nw, newQueryMsg(t))

			var ty response.Type
			if nw.Msg.Rcode == dns.RcodeRefused {
				ty = response.NameError
			} else {
				ty, _ = response.Typify(nw.Msg, time.Now().UTC())
			}

			switch ty {
			case response.NoError:
				newAnswers[t] = nw.Msg.Answer[0]
			case response.NoData, response.NameError:
				newAnswers[t] = nil
			}
		}

		change := make([]dns.RR, 0, len(newAnswers))
		s.Lock()
		s.coalescePending(false, true)
		for t, newRR := range newAnswers {
			if _, ok := s.active[t]; !ok {
				continue // not subscribed anymore
			}

			oldRR, ok := clientAnswers[t]
			if !ok {
				oldRR = cachedAnswers[t]
			}
			cachedAnswers[t] = newRR // keep the most recent RR in the cache

			if oldRR == newRR || (oldRR != nil && newRR != nil && dns.IsDuplicate(oldRR, newRR)) {
				continue // no change
			}

			if newRR == nil {
				// Special RR for removal.
				newRR = dns.Copy(oldRR)
				newRR.Header().Ttl = dns.DSOPushTTLRemove
			}
			change = append(change, newRR)
		}

		pushM, pushTLV := newPushMsg()
		pushTLV.Change = change
		for m := range splitPushMsg(pushM) {
			if sesh.WriteMsg(nil, m) != nil {
				break
			}
		}
	}
}

// newQueryMsg creates a DNS Query message.
func newQueryMsg(tlv dns.DSOSubscribe) *dns.Msg {
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = true
	m.Question = append(m.Question, dns.Question{
		Name:   tlv.Name,
		Qtype:  tlv.Rrtype,
		Qclass: tlv.Class,
	})
	return m
}

// newPushMsg creates a DSO PUSH message.
func newPushMsg() (*dns.Msg, *dns.DSOPush) {
	m := new(dns.Msg)
	m.Compress = true
	dns.SetDSOUnidirectional(m)
	tlv := new(dns.DSOPush)
	m.Stateful = append(m.Stateful, tlv)
	return m, tlv
}

// expandSubscribeTLV expands wildcards in the subscription TLV.
func expandSubscribeTLV(tlv dns.DSOSubscribe, opts *pushOpts) iter.Seq[dns.DSOSubscribe] {
	return func(yield func(dns.DSOSubscribe) bool) {
		if tlv.Rrtype != dns.TypeANY && tlv.Class != dns.ClassANY {
			yield(tlv)
			return
		}

		types := []uint16{tlv.Rrtype}
		if types[0] == dns.TypeANY {
			types = opts.anyTypes
		}
		classes := []uint16{tlv.Class}
		if classes[0] == dns.ClassANY {
			classes = opts.anyClasses
		}
		for _, ty := range types {
			for _, cl := range classes {
				tlv1 := tlv
				tlv1.Rrtype = ty
				tlv1.Class = cl
				if !yield(tlv1) {
					return
				}
			}
		}
	}
}

// splitPushMsg splits the push DSO message such that each message takes at most 16382 bytes in wire format.
func splitPushMsg(m *dns.Msg) iter.Seq[*dns.Msg] {
	return func(yield func(*dns.Msg) bool) {
		if m.Len() <= dns.DSOPushLenMax {
			yield(m)
			return
		}

		len := 0
		m1, tlv := newPushMsg()
		for _, rr := range m.Stateful[0].(*dns.DSOPush).Change {
			rrLen := dns.Len(rr)
			if len+rrLen > dns.DSOPushLenMax-12-4 { // DNS header + TLV header
				if !yield(m1) {
					return
				}
				len = 0
				m1, tlv = newPushMsg()
			}
			len += rrLen
			tlv.Change = append(tlv.Change, rr)
		}
		yield(m1)
	}
}

var (
	errDup    error = errors.New("duplicate subscription")
	errLimit        = errors.New("subscriptions limit reached")
	errClosed       = errors.New("closed subscription")
)
