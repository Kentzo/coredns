package dso

import (
	"fmt"
	"iter"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin/dso/internal/lookup"
	"github.com/miekg/dns"
)

var (
	ErrDuplicateSub = fmt.Errorf("duplicate Push subscription")
)

type (
	// answer is cached upstream lookup result to client's subscription.
	//
	// Up to 4 client subscriptions may reference the same answer because of wildcards.
	answer struct {
		rrs      []dns.RR
		refcount int
	}

	// Subscription is per-session subscriptions.
	//
	// Client subscription is expanded and periodically refreshed ([PushConfig.RefreshInterval])
	// via upstream lookups. Initial subscription burst is countered with [PushConfig.DebounceDelay].
	//
	// Freshly fetched RRset of each subscription is compared against most recently sent copy.
	// Only non-empty difference is sent to client.
	//
	// Wildcard requests are expanded to [PushConfig.ClassANY] and [PushConfig.TypeANY].
	// However, if client directly requests class or type that is missing from these lists,
	// both per-session expansion lists and existing wildcard subscriptions are updated
	// to avoid discrepancy.
	Subscription struct {
		mu sync.RWMutex

		sesh     *Session
		upstream *dnsserver.Server
		config   *PushConfig

		byID          map[uint16]Subscribe   // Subscriptions by ID, as requested.
		byTLV         map[Subscribe]struct{} // Subscriptions by TLV, as requested.
		byTLVExpanded map[Subscribe]*answer  // Subscriptions and corresponding answers, expanded.

		anyByTLV map[Subscribe]struct{} // Wildcard subscriptions, subset of byTLV.
		classANY []uint16               // Extra per-session wildcard classes.
		typeANY  []uint16               // Extra per-session wildcard types.

		dirty    map[Subscribe]struct{} // Dirty subscriptions, subset of byTLVExpanded.
		dirtyC   chan struct{}          // Signal that dirty is not empty.
		refreshC chan struct{}          // Signal that refresh is needed.
	}
)

func newSubscription(sesh *Session, upstream *dnsserver.Server, cfg *PushConfig) *Subscription {
	return &Subscription{
		sesh:     sesh,
		upstream: upstream,
		config:   cfg,

		byID:          make(map[uint16]Subscribe),
		byTLV:         make(map[Subscribe]struct{}),
		byTLVExpanded: make(map[Subscribe]*answer),

		anyByTLV: make(map[Subscribe]struct{}),
		classANY: cfg.ClassANY,
		typeANY:  cfg.TypeANY,

		dirty:    make(map[Subscribe]struct{}),
		dirtyC:   make(chan struct{}, 1),
		refreshC: make(chan struct{}, 1),
	}
}

func (sub *Subscription) add(tlvs iter.Seq[Subscribe]) (dirty bool) {
	for tlv := range tlvs {
		a, ok := sub.byTLVExpanded[tlv]
		if !ok {
			a = &answer{}
			sub.byTLVExpanded[tlv] = a
			sub.dirty[tlv] = struct{}{}
			dirty = true
		}
		a.refcount += 1
	}
	return dirty
}

func (sub *Subscription) updateAny(tlv Subscribe) {
	var dirtyClass, dirtyType bool

	if tlv.Class != dns.ClassANY {
		i, ok := slices.BinarySearch(sub.classANY, tlv.Class)
		if !ok {
			if &sub.classANY[0] == &sub.config.ClassANY[0] {
				// First adjustment to config's ANY list: splice.
				sub.classANY = make([]uint16, len(sub.config.ClassANY)+1)
				copy(sub.classANY, sub.config.ClassANY[:i])
				copy(sub.classANY[i+1:], sub.config.ClassANY[i:])
				sub.classANY[i] = tlv.Class
			} else {
				sub.classANY = slices.Insert(sub.classANY, i, tlv.Class)
			}
			dirtyClass = true
		}
	}

	if tlv.RRType != dns.TypeANY {
		i, ok := slices.BinarySearch(sub.typeANY, tlv.RRType)
		if !ok {
			if &sub.typeANY[0] == &sub.config.TypeANY[0] {
				sub.typeANY = make([]uint16, len(sub.config.TypeANY)+1)
				copy(sub.typeANY, sub.config.TypeANY[:i])
				copy(sub.typeANY[i+1:], sub.config.TypeANY[i:])
				sub.typeANY[i] = tlv.RRType
			} else {
				sub.typeANY = slices.Insert(sub.typeANY, i, tlv.RRType)
			}
			dirtyType = true
		}
	}

	// If ANY list for either class or type is updated, existing wildcard subscriptions must be re-expanded.
	if dirtyClass || dirtyType {
		for anyTLV := range sub.anyByTLV {
			if dirtyClass && anyTLV.Class == dns.ClassANY {
				sub.add(ExpandSubscribeTLV(anyTLV, []uint16{tlv.Class}, sub.typeANY))
			}
			if dirtyType && anyTLV.RRType == dns.TypeANY {
				sub.add(ExpandSubscribeTLV(anyTLV, sub.classANY, []uint16{tlv.RRType}))
			}
		}
	}
}

func (sub *Subscription) Add(builder *MsgBuilder, id uint16, tlv Subscribe) (err error) {
	sub.mu.Lock()
	defer sub.mu.Unlock()

	if sub.byID == nil {
		return ErrSessionClosed
	}
	if _, ok := sub.byID[id]; ok {
		return ErrDuplicateSub
	}
	if _, ok := sub.byTLV[tlv]; ok {
		return ErrDuplicateSub
	}

	// Response to subscription must be written before subsequent updates
	// otherwise the client may see them out of order.
	builder.SetMsgHeader(MsgHeader{
		ID:       id,
		Response: true,
		Rcode:    dns.RcodeSuccess,
	})
	err = sub.sesh.WriteMsg(builder.Message())
	if err != nil {
		return err
	}

	sub.byID[id] = tlv
	sub.byTLV[tlv] = struct{}{}
	if tlv.Class == dns.ClassANY || tlv.RRType == dns.TypeANY {
		sub.anyByTLV[tlv] = struct{}{}
	}

	if sub.add(ExpandSubscribeTLV(tlv, sub.classANY, sub.typeANY)) {
		sub.updateAny(tlv)
		select {
		case sub.dirtyC <- struct{}{}:
		default:
		}
	}

	return nil
}

func (sub *Subscription) remove(tlvs iter.Seq[Subscribe]) {
	for tlv := range tlvs {
		if a, ok := sub.byTLVExpanded[tlv]; ok {
			a.refcount -= 1
			if a.refcount <= 0 {
				delete(sub.byTLVExpanded, tlv)
				delete(sub.dirty, tlv)
			}
		}
	}
}

func (sub *Subscription) Remove(unTLV Unsubscribe) {
	sub.mu.Lock()
	defer sub.mu.Unlock()

	tlv, ok := sub.byID[unTLV.SubscribeID]
	if !ok {
		return // not subscribed or stopped
	}

	delete(sub.byID, unTLV.SubscribeID)
	delete(sub.byTLV, tlv)
	if tlv.Class == dns.ClassANY || tlv.RRType == dns.TypeANY {
		delete(sub.anyByTLV, tlv)
	}
	sub.remove(ExpandSubscribeTLV(tlv, sub.classANY, sub.typeANY))
}

func (sub *Subscription) Reconfirm(reTLV Reconfirm) {
	h := reTLV.RR.Header()
	tlv := Subscribe{
		Name:   h.Name,
		RRType: h.Rrtype,
		Class:  h.Class,
	}

	sub.mu.RLock()
	defer sub.mu.RUnlock()

	_, ok := sub.byTLVExpanded[tlv]
	if !ok {
		return // not subscribed or stopped
	}

	sub.dirty[tlv] = struct{}{}
	select {
	case sub.dirtyC <- struct{}{}:
	default:
	}
}

// Refresh subscriptions ahead of periodic interval.
func (sub *Subscription) Refresh() {
	sub.mu.RLock()
	defer sub.mu.RUnlock()

	if sub.byID == nil {
		// stopped
		return
	}

	select {
	case sub.refreshC <- struct{}{}:
	default:
	}
}

// IsActive returns whether there are active subscriptions.
func (sub *Subscription) IsActive() (ok bool) {
	sub.mu.RLock()
	ok = len(sub.byID) > 0
	sub.mu.RUnlock()
	return ok
}

func (sub *Subscription) Compact() {
	sub.mu.Lock()
	defer sub.mu.Unlock()

	sub.byID = maps.Clone(sub.byID)
	sub.byTLV = maps.Clone(sub.byTLV)
	sub.byTLVExpanded = maps.Clone(sub.byTLVExpanded)
	for _, a := range sub.byTLVExpanded {
		a.Compact()
	}
	sub.anyByTLV = maps.Clone(sub.anyByTLV)
	sub.dirty = maps.Clone(sub.dirty)
}

// doRefresh periodically refreshes RRs and sends changes to client, if necessary, as long as the session is functional.
func (sub *Subscription) doRefresh() {
	defer func() {
		sub.mu.Lock()
		sub.byID = nil
		sub.byTLVExpanded = nil
		sub.dirty = nil
		close(sub.dirtyC)
		close(sub.refreshC)
		sub.mu.Unlock()
	}()

	updateSeq := sub.loopUpdate(sub.loopChange(sub.loopAnswers(sub.loopDirty())))
	for msg := range updateSeq {
		err := sub.sesh.WriteMsg(msg)
		if err != nil {
			break
		}
	}
}

// loopDirty generates sequence of dirty subscriptions.
func (sub *Subscription) loopDirty() iter.Seq[[]Subscribe] {
	return func(yield func([]Subscribe) bool) {
		var (
			doneC    = sub.sesh.Done()
			dirtyC   chan struct{}
			refreshC chan struct{}
		)
		if sub.config.DebounceDelay > 0 {
			dirtyC = make(chan struct{})
			go func() {
				defer close(dirtyC)
				t := time.NewTimer(sub.config.DebounceDelay)
				for {
					select {
					case <-sub.dirtyC:
					case <-doneC:
						return
					}
					t.Reset(sub.config.DebounceDelay)
					select {
					case <-t.C:
					case <-doneC:
						return
					}
					// Drain after the debounce delay.
					select {
					case <-sub.dirtyC:
					default:
					}
					select {
					case dirtyC <- struct{}{}:
					case <-doneC:
						return
					}
				}
			}()
		} else {
			dirtyC = sub.dirtyC
		}
		if sub.config.RefreshInterval > 0 {
			refreshC = make(chan struct{})
			go func() {
				defer close(refreshC)
				tickC := time.Tick(sub.config.RefreshInterval)
				for {
					select {
					case <-tickC:
					case <-sub.refreshC:
					case <-doneC:
						return
					}
					select {
					case refreshC <- struct{}{}:
					case <-doneC:
						return
					}
				}
			}()
		} else {
			refreshC = sub.refreshC
		}

		var (
			dirty []Subscribe
			ok    bool
		)
		for {
			select {
			case _, ok = <-dirtyC:
				sub.mu.Lock()
				dirty = slices.Grow(dirty, len(sub.dirty))
				dirty = slices.AppendSeq(dirty, maps.Keys(sub.dirty))
				clear(sub.dirty)
				sub.mu.Unlock()
			case _, ok = <-refreshC:
				sub.mu.Lock()
				dirty = slices.Grow(dirty, len(sub.byTLVExpanded))
				dirty = slices.AppendSeq(dirty, maps.Keys(sub.byTLVExpanded))
				clear(sub.dirty) // refresh covers all known TLVs
				sub.mu.Unlock()
			case _, ok = <-doneC:
			}
			if !ok {
				return
			}
			if len(dirty) == 0 {
				continue
			}
			if !yield(dirty) {
				return
			}
			clear(dirty)
			dirty = dirty[:0]
		}
	}
}

// loopAnswers transforms sequence of dirty subscriptions to answers.
func (sub *Subscription) loopAnswers(dirtySeq iter.Seq[[]Subscribe]) iter.Seq[map[Subscribe][]dns.RR] {
	return func(yield func(map[Subscribe][]dns.RR) bool) {
		var (
			queryC  = make(chan Subscribe, 1)
			answerC = make(chan *dns.Msg, 1)
			doneC   = sub.sesh.Done()
		)
		defer close(queryC)

		// Look up dirty subscriptions.
		go func() {
			defer close(answerC)
			var (
				m = &dns.Msg{
					MsgHdr: dns.MsgHdr{
						RecursionDesired: true,
					},
					Question: []dns.Question{{}},
				}
				q = &m.Question[0]
			)
			for tlv := range queryC {
				m.Id = dns.Id()
				q.Name, q.Qclass, q.Qtype = tlv.Name, tlv.Class, tlv.RRType
				select {
				case answerC <- lookup.Do(sub.upstream, sub.sesh.Conn, m):
				case <-doneC:
					return
				}
			}
		}()

		for dirty := range dirtySeq {
			var (
				nxdomain = make(map[Subscribe]struct{}) // avoid fetching same name&class after NXDOMAIN
				answers  = make(map[Subscribe][]dns.RR)
				ok       bool
			)
			for _, tlv := range dirty {
				nxdomainKey := Subscribe{Name: tlv.Name, RRType: dns.TypeANY, Class: tlv.Class}
				if _, ok = nxdomain[nxdomainKey]; ok {
					answers[tlv] = nil
					continue
				}

				var m *dns.Msg
				queryC <- tlv
				select {
				case m, ok = <-answerC:
				case _, ok = <-doneC:
				}
				if !ok {
					return
				}

				switch {
				case m != nil && m.Rcode == dns.RcodeSuccess && len(m.Answer) > 0:
					if m.Answer[0].Header().Rrtype == dns.TypeCNAME {
						// Client is responsible for resolving CNAME: discard aux answers.
						answers[tlv] = m.Answer[:1]
					} else {
						answers[tlv] = m.Answer
					}
				case m != nil && m.Rcode == dns.RcodeNameError:
					nxdomain[nxdomainKey] = struct{}{}
					fallthrough
				default:
					answers[tlv] = nil
				}
			}
			if !yield(answers) {
				return
			}
		}
	}
}

// loopChange transforms sequence of answers to DSO Push Update changelists.
func (sub *Subscription) loopChange(answersSeq iter.Seq[map[Subscribe][]dns.RR]) iter.Seq[[]dns.RR] {
	return func(yield func([]dns.RR) bool) {
		for answers := range answersSeq {
			var changes []dns.RR
			func() {
				sub.mu.RLock()
				defer sub.mu.RUnlock()

				for tlv, rrs := range answers {
					a, ok := sub.byTLVExpanded[tlv]
					if !ok {
						continue
					}

					var changeBuf *[]dns.RR
					a.rrs, changeBuf, _ = ComputeChange(a.rrs, rrs, nil)
					changes = append(changes, *changeBuf...)
				}
			}()
			if len(changes) > 0 {
				if !yield(changes) {
					return
				}
			}
		}
	}
}

var updateMsgPool = NewMsgPool(5 * TLSBlockLen)

// loopUpdate transforms sequence of changes to DSO Push Messages.
func (sub *Subscription) loopUpdate(changeSeq iter.Seq[[]dns.RR]) iter.Seq[[]byte] {
	return func(yield func([]byte) bool) {
		for change := range changeSeq {
			var (
				poolBuf = updateMsgPool.Get()
				builder = NewMsgBuilder(*poolBuf)
				errI    = -1
				bufLen  = -1
			)
			builder.EnableCompression()
			for msg, err := range BuildPushMsg(builder, change) {
				if msg != nil {
					if !yield(msg) {
						break
					}
				} else {
					// builder.Buf is too small for i-th RR.

					i := err.(*PackError).Index
					ok := i != errI
					if ok {
						bufLen = MsgHeaderLen + TLVHeaderLen + dns.Len(change[i])
						ok = bufLen > len(builder.Buf)  // smaller or equal bufLen suggests that error is not related to space
						ok = ok && bufLen <= PushLenMax // cannot exceed RFC limits
					}
					if !ok {
						log.Warningf("oversized RDATA for %v", change[err.(*PackError).Index].Header())
						builder.Finish()
						builder.SetMsgHeader(MsgHeader{0, false, dns.RcodeServerFailure})
						builder.WriteRetryDelay(RetryDelay{})
						yield(builder.Message())
						break
					}

					log.Debugf("large RDATA for %v", change[err.(*PackError).Index].Header())
					errI = i
					if poolBuf != nil {
						// Keep outlier buffer on heap.
						builder.Buf = make([]byte, bufLen)
						copy(builder.Buf, (*poolBuf)[:builder.Off])
						updateMsgPool.Put(poolBuf)
						poolBuf = nil
					} else {
						builder.Buf = slices.Grow(builder.Buf, bufLen-len(builder.Buf))[:bufLen]
					}
				}
			}
			if poolBuf != nil {
				updateMsgPool.Put(poolBuf)
			}
		}
	}
}

func (a *answer) Compact() {
	a.rrs = slices.Compact(a.rrs)
}

// ComputeChange computes DSO Push Update difference between dst and src.
func ComputeChange(dst, src []dns.RR, changeBuf *[]dns.RR) (rrs []dns.RR, outChangeBuf, discardBuf *[]dns.RR) {
	var (
		dstLen = len(dst)
		srcLen = len(src)

		noChange  = func(change []dns.RR) []dns.RR { return nil }
		removeAll = func(change []dns.RR) []dns.RR {
			change = slices.Grow(change, dstLen)[:dstLen]
			for i, rr := range dst {
				rr = dns.Copy(rr)
				rr.Header().Ttl = PushTTLRemove
				change[i] = rr
			}
			return change
		}
		addAll = func(change []dns.RR) []dns.RR {
			change = slices.Grow(change, srcLen)[:srcLen]
			for i, rr := range src {
				change[i] = dns.Copy(rr)
			}
			return change
		}
		replaceAll = func(change []dns.RR) []dns.RR {
			changeLen := dstLen + srcLen
			change = slices.Grow(change, changeLen)[:changeLen]
			for i, rr := range dst {
				rr = dns.Copy(rr)
				rr.Header().Ttl = PushTTLRemove
				change[i] = rr
			}
			for i, rr := range src {
				change[dstLen+i] = dns.Copy(rr)
			}
			return change
		}
		replaceSome = func(change []dns.RR, seen []bool, seenLen int) []dns.RR {
			changeLen := dstLen - seenLen + srcLen - seenLen
			change = slices.Grow(change, changeLen)[:changeLen]
			var k int
			for i, rr := range dst {
				if !seen[i] {
					rr = dns.Copy(rr)
					rr.Header().Ttl = PushTTLRemove
					change[k] = rr
					k++
				}
			}
			for i, rr := range src {
				if !seen[dstLen+i] {
					change[k] = dns.Copy(rr)
					k++
				}
			}
			return change
		}
	)
	var change []dns.RR
	if changeBuf != nil {
		change = *changeBuf
	}
	switch {
	case dstLen == 0 && srcLen == 0:
		change = noChange(change)
	case dstLen == 0 && srcLen > 0:
		change = addAll(change)
	case dstLen > 0 && srcLen == 0:
		change = removeAll(change)
	case dstLen == 1 && srcLen == 1 && dns.IsDuplicate(dst[0], src[0]):
		change = noChange(change)
	case dstLen == 1 && srcLen == 1:
		change = replaceAll(change)
	default:
		var (
			seen    = make([]bool, dstLen+srcLen)
			seenLen = 0 // total # of unchanged RRs
		)
		for dstI, dstRR := range dst {
			for srcI, srcRR := range src {
				if !seen[dstLen+srcI] && dns.IsDuplicate(dstRR, srcRR) {
					seen[dstLen+srcI] = true
					seen[dstI] = true
					seenLen++
					break
				}
			}
		}
		switch {
		case dstLen == srcLen && seenLen == srcLen:
			change = noChange(change)
		case seenLen == 0:
			change = replaceAll(change)
		default:
			change = replaceSome(change, seen, seenLen)
		}
	}
	if changeBuf == nil || cap(change) > cap(*changeBuf) {
		return src, &change, changeBuf
	} else {
		*changeBuf = change
		return src, changeBuf, nil
	}
}

// ExpandSubscribeTLV expands wildcards in the subscription TLV.
func ExpandSubscribeTLV(tlv Subscribe, anyClasses, anyTypes []uint16) iter.Seq[Subscribe] {
	return func(yield func(Subscribe) bool) {
		if tlv.Class != dns.ClassANY {
			buf := [...]uint16{tlv.Class}
			anyClasses = buf[:]
		}
		if tlv.RRType != dns.TypeANY {
			buf := [...]uint16{tlv.RRType}
			anyTypes = buf[:]
		}
		for _, cl := range anyClasses {
			for _, ty := range anyTypes {
				tlv1 := tlv
				tlv1.Class = cl
				tlv1.RRType = ty
				if !yield(tlv1) {
					return
				}
			}
		}
	}
}
