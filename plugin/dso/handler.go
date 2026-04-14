package dso

import (
	"context"
	"net"
	"sync/atomic"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/parse"
	"github.com/miekg/dns"
)

type (
	// sharedState is the shared state among all [Handler] that belong to a given [caddy.Instance].
	sharedState struct {
		// RawCfg is all parsed dso declarations grouped by the listen address of underlying [dnsserver.Server].
		RawCfg map[string][]rawConfig

		// Servers maps listening address of [dnsserver.Server] to its corresponding DSO server.
		// atomic.Pointer coordinates concurrent reads in [Handler.ServeDNS] with concurrent writes
		// in [sharedState.onStartup] and [sharedState.onShutdown].
		Servers atomic.Pointer[map[string]*Server]
	}
)

func newSharedState() *sharedState {
	return &sharedState{
		RawCfg: make(map[string][]rawConfig),
	}
}

func (state *sharedState) onStartup() (err error) {
	servers := make(map[string]*Server)
	defer func() {
		if err != nil {
			// Either all requested servers start or none.
			for _, server := range servers {
				server.Shutdown(context.Background(), server.Config.RestartReconnectInterval)
			}
		} else {
			state.Servers.Store(&servers)
		}
	}()

	for addr, raw := range state.RawCfg {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return plugin.Error(Name, err)
		}

		cfg, err := resolveConfig(raw)
		if err != nil {
			return plugin.Error(Name, err)
		}

		server := NewServer(host, cfg)
		err = server.Start()
		if err != nil {
			return plugin.Error(Name, err)
		}
		servers[addr] = server
	}
	return nil
}

func (state *sharedState) onRestart() (err error) {
	servers := state.Servers.Swap(nil)
	if servers != nil {
		for _, server := range *servers {
			server.Shutdown(context.Background(), server.Config.RestartReconnectInterval)
		}
	}
	return nil
}

func (state *sharedState) onShutdown() error {
	servers := state.Servers.Swap(nil)
	if servers != nil {
		for _, server := range *servers {
			server.Shutdown(context.Background(), server.Config.ShutdownReconnectInterval)
		}
	}
	return nil
}

type Handler struct {
	Next plugin.Handler

	state *sharedState
}

func newHandler(state *sharedState) *Handler {
	return &Handler{
		state: state,
	}
}

// ServeDNS implements [plugin.Handler.ServeDNS].
func (h *Handler) ServeDNS(ctx context.Context, w dns.ResponseWriter, m *dns.Msg) (rcode int, err error) {
	upstream := ctx.Value(dnsserver.Key{}).(*dnsserver.Server)
	_, addr := parse.Transport(upstream.Addr)

	servers := h.state.Servers.Load()
	if servers == nil {
		return plugin.NextOrFailure(h.Name(), h.Next, ctx, w, m)
	}
	server := (*servers)[addr]
	server.SetUpstream(upstream)

	return plugin.NextOrFailure(h.Name(), h.Next, ctx, w, m)
}

// Name implements [plugin.Handler.Name].
func (h *Handler) Name() string { return Name }
