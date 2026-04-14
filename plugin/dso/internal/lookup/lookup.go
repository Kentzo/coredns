package lookup

import (
	"context"
	"net"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/miekg/dns"
)

type writer struct {
	localAddr  net.Addr
	remoteAddr net.Addr
	Msg        *dns.Msg
}

func (w *writer) LocalAddr() net.Addr         { return w.localAddr }
func (w *writer) RemoteAddr() net.Addr        { return w.remoteAddr }
func (w *writer) WriteMsg(m *dns.Msg) error   { w.Msg = m; return nil }
func (w *writer) Write(b []byte) (int, error) { w.Msg = new(dns.Msg); return len(b), w.Msg.Unpack(b) }
func (w *writer) Close() error                { return nil }
func (w *writer) TsigStatus() error           { return nil }
func (w *writer) TsigTimersOnly(_ bool)       {}
func (w *writer) Hijack()                     {}

type Addrer interface {
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

func Do[T Addrer](upstream *dnsserver.Server, w T, m *dns.Msg) *dns.Msg {
	nw := &writer{localAddr: w.LocalAddr(), remoteAddr: w.RemoteAddr()}
	dnsCtx := context.WithValue(context.Background(), dnsserver.Key{}, upstream)
	dnsCtx = context.WithValue(dnsCtx, dnsserver.LoopKey{}, 0)
	upstream.ServeDNS(dnsCtx, nw, m)
	return nw.Msg
}
