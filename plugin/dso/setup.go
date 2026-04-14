package dso

import (
	"slices"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"

	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/parse"
)

const Name = "dso"

var log = clog.NewWithPlugin(Name)

func init() { plugin.Register(Name, setup) }

// sharedStateKey is a key in [caddy.Instance] Storage for [sharedState].
type sharedStateKey struct{}

func setup(c *caddy.Controller) error {
	rawCfg, err := parseConfig(c)
	if err != nil {
		return plugin.Error(Name, err)
	}

	state, ok := c.Get(sharedStateKey{}).(*sharedState)
	if !ok {
		state = newSharedState()
		c.Set(sharedStateKey{}, state)
		c.OnStartup(state.onStartup)
		c.OnRestart(state.onRestart)
		c.OnRestartFailed(state.onStartup)
		c.OnFinalShutdown(state.onShutdown)
	}

	listenPorts := make([]string, 0, len(c.ServerBlockKeys))
	for _, k := range c.ServerBlockKeys {
		_, k = parse.Transport(k)
		_, port, _ := plugin.SplitHostPort(k)
		listenPorts = append(listenPorts, port)
	}
	slices.Sort(listenPorts)
	listenPorts = slices.Compact(listenPorts)

	dnsCfg := dnsserver.GetConfig(c)
	handler := newHandler(state)
	dnsCfg.AddPlugin(func(next plugin.Handler) plugin.Handler {
		// Group raw configs here:
		// - cfg.ListenHosts is set
		// - state.RawCfg must be final by the time OnStartup event is fired
		rawCfg.TsigSecret = dnsCfg.TsigSecret
		rawCfg.TLSConfig = dnsCfg.TLSConfig
		for _, h := range dnsCfg.ListenHosts {
			for _, p := range listenPorts {
				addr := h + ":" + p
				state.RawCfg[addr] = append(state.RawCfg[addr], rawCfg)
			}
		}

		handler.Next = next
		return handler
	})

	return nil
}
