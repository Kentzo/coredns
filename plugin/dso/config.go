package dso

import (
	"cmp"
	"crypto/tls"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

type (
	// rawConfig is [Config] as parsed from Corefile. nil values represent unset options.
	rawConfig struct {
		TCPPort *int
		TLSPort *int

		RestartReconnectInterval  *time.Duration
		ShutdownReconnectInterval *time.Duration
		InactivityTimeout         *time.Duration
		KeepAliveInterval         *time.Duration

		TLSConfig  *tls.Config
		TsigSecret map[string]string

		Push *rawPushConfig
		Log  *rawLogConfig
	}
	// rawPushConfig is [PushConfig] as parsed from Corefile. nil values represent unset options.
	rawPushConfig struct {
		Zones           []string
		ClassANY        []uint16
		TypeANY         []uint16
		RefreshInterval *time.Duration
		DebounceDelay   *time.Duration
	}
	// rawLogConfig is [LogConfig] as parsed from Corefile. nil values represent unset options.
	rawLogConfig struct {
		Incoming *string
		Outgoing *string
	}

	Config struct {
		// TCPPort is port for DSO services that don't require TLS. Set to 0 to disable.
		TCPPort int
		// TLSPort is port for DSO services that require TLS. Set to 0 to disable.
		TLSPort int

		// RestartReconnectInterval is RetryDelay interval for gracefully closed sessions due to Restart.
		RestartReconnectInterval time.Duration
		// ShutdownReconnectInterval is RetryDelay interval for gracefully closed sessions due to Shutdown.
		ShutdownReconnectInterval time.Duration
		// InactivityTimeout is maximum amount of time session can be inactive. Clients can further reduce it.
		InactivityTimeout time.Duration
		// KeepAliveInterval is maximum amount of time session can be without any traffic. Clients can further reduce it.
		KeepAliveInterval time.Duration

		TLSConfig  *tls.Config
		TsigSecret map[string]string

		Push *PushConfig
		Log  *LogConfig
	}
	PushConfig struct {
		Zones           []string      // Zones the handler is authoritative for.
		ClassANY        []uint16      // Sorted list of classes that ClassANY resolves to.
		TypeANY         []uint16      // Sorted list of types that TypeANY resolves to.
		RefreshInterval time.Duration // Periodic refresh interval of subscriptions. Set to 0 to disable.
		DebounceDelay   time.Duration // Delay to tame burst subscriptions. Set to 0 to disable.
	}
	LogConfig struct {
		Incoming string
		Outgoing string
	}
)

var (
	DefaultTCPPort = 0
	DefaultTLSPort = 0

	DefaultCleanupInterval           = 5 * time.Minute
	DefaultRestartReconnectInterval  = 5 * time.Second
	DefaultShutdownReconnectInterval = 15 * time.Second
	DefaultInactivityTimeout         = 1 * time.Minute
	DefaultKeepAliveInterval         = KeepAliveIntervalRecommened * time.Millisecond

	DefaultIncomingLogFormat = `{remote}:{port}: |<- {>id} {/dso/type} {/dso/rcode} {/dso/tlvtype}`
	DefaultOutgoingLogFormat = `{remote}:{port}: |-> {>id} {/dso/type} {/dso/rcode} {/dso/tlvtype}`

	DefaultPushAnyTypes = [...]uint16{
		// Keep sorted!
		dns.TypeA,
		dns.TypeNS,
		dns.TypeCNAME,
		dns.TypeSOA,
		dns.TypePTR,
		dns.TypeTXT,
		dns.TypeAAAA,
		dns.TypeSRV,
	}
	DefaultPushAnyClasses = [...]uint16{
		// Keep sorted!
		dns.ClassINET,
	}
	DefaultPushRefreshInterval       = 1 * time.Minute
	DefaultPushBurstDebounceInterval = 1 * time.Second
)

func parseConfig(c *caddy.Controller) (raw rawConfig, err error) {
	raw = rawConfig{}
	for i := 0; c.Next(); i++ {
		if i > 0 {
			return raw, plugin.ErrOnce
		}

		for c.NextBlock() {
			switch c.Val() {
			case "tcp_port":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return raw, c.ArgErr()
				}
				port, err := strconv.Atoi(args[0])
				if err == nil && port < -1 || port >= 65535 {
					err = fmt.Errorf("outside of allowed range")
				}
				if err != nil {
					return raw, c.Errf("invalid tcp_port value %q: %v", args[0], err)
				}
				raw.TCPPort = &port
			case "tls_port":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return raw, c.ArgErr()
				}
				port, err := strconv.Atoi(args[0])
				if err == nil && port < -1 || port >= 65535 {
					err = fmt.Errorf("outside of allowed range")
				}
				if err != nil {
					return raw, c.Errf("invalid tls_port value %q: %v", args[0], err)
				}
				raw.TLSPort = &port
			case "push":
				raw.Push = &rawPushConfig{
					Zones: plugin.OriginsFromArgsOrServerBlock(c.RemainingArgs(), c.ServerBlockKeys),
				}
				for c.NextBlock() {
					switch c.Val() {
					case "class_any":
						args := c.RemainingArgs()
						if len(args) == 0 {
							return raw, c.ArgErr()
						}
						raw.Push.ClassANY = make([]uint16, 0, len(args))
						for _, a := range args {
							cl, ok := dns.StringToClass[a]
							if !ok {
								return raw, c.Errf("unknown DNS class %q", a)
							}
							raw.Push.ClassANY = append(raw.Push.ClassANY, cl)
						}
						slices.Sort(raw.Push.ClassANY)
					case "type_any":
						args := c.RemainingArgs()
						if len(args) == 0 {
							return raw, c.ArgErr()
						}
						raw.Push.TypeANY = make([]uint16, 0, len(args))
						for _, a := range args {
							t, ok := dns.StringToType[a]
							if !ok {
								return raw, c.Errf("unknown DNS type %q", a)
							}
							raw.Push.TypeANY = append(raw.Push.TypeANY, t)
						}
						slices.Sort(raw.Push.TypeANY)
					case "refresh":
						args := c.RemainingArgs()
						if len(args) != 1 {
							return raw, c.ArgErr()
						}
						v, err := time.ParseDuration(args[0])
						if err == nil && v < 0 {
							err = fmt.Errorf("outside of allowed range")
						}
						if err != nil {
							return raw, c.Errf("invalid push.refresh value %q: %v", args[0], err)
						}
						raw.Push.RefreshInterval = &v
					case "debounce":
						args := c.RemainingArgs()
						if len(args) != 1 {
							return raw, c.ArgErr()
						}
						v, err := time.ParseDuration(args[0])
						if err == nil && v < 0 {
							err = fmt.Errorf("outside of allowed range")
						}
						if err != nil {
							return raw, c.Errf("invalid push.debounce value %q: %v", args[0], err)
						}
						raw.Push.DebounceDelay = &v
					default:
						return raw, c.Errf("unknown property %q", c.Val())
					}
				}
			case "log":
				raw.Log = &rawLogConfig{}
				args := c.RemainingArgs()
				switch len(args) {
				case 0:
				case 1:
					v := strings.ReplaceAll(args[0], "{common}", DefaultIncomingLogFormat)
					raw.Log.Incoming = &v
					v = strings.ReplaceAll(args[0], "{common}", DefaultOutgoingLogFormat)
					raw.Log.Outgoing = &v
				case 2:
					v := strings.ReplaceAll(args[0], "{common}", DefaultIncomingLogFormat)
					raw.Log.Incoming = &v
					v = strings.ReplaceAll(args[1], "{common}", DefaultOutgoingLogFormat)
					raw.Log.Outgoing = &v
				default:
					return raw, c.ArgErr()
				}
				// useLog = true
			default:
				return raw, c.Errf("unknown property %q", c.Val())
			}
		}
	}

	return raw, nil
}

func optMatch[T cmp.Ordered](a, b *T) (*T, error) {
	if a != nil && b != nil && *a != *b {
		return nil, fmt.Errorf("%v != %v", *a, *b)
	} else {
		return cmp.Or(a, b), nil
	}
}

func optMin[T cmp.Ordered](a, b *T) *T {
	if a != nil && b != nil {
		if cmp.Less(*a, *b) {
			return a
		} else {
			return b
		}
	} else {
		return cmp.Or(a, b)
	}
}

func optDedup[T cmp.Ordered](s []T) []T {
	slices.Sort(s)
	return slices.Compact(s)
}

func optDefault[T cmp.Ordered](v *T, d T) T {
	if v != nil {
		return *v
	} else {
		return d
	}
}

// resolveConfig aggregates raw options specified across multiple server blocks for a single [Server].
func resolveConfig(rawCfg []rawConfig) (cfg Config, err error) {
	final := rawConfig{}
	for _, o := range rawCfg {
		if final.TCPPort, err = optMatch(final.TCPPort, o.TCPPort); err != nil {
			return cfg, fmt.Errorf("conflicting DSO over TCP port (%s)", err)
		}
		if final.TLSPort, err = optMatch(final.TLSPort, o.TLSPort); err != nil {
			return cfg, fmt.Errorf("conflicting DSO over TLS port (%s)", err)
		}
		final.RestartReconnectInterval = optMin(final.RestartReconnectInterval, o.RestartReconnectInterval)
		final.ShutdownReconnectInterval = optMin(final.ShutdownReconnectInterval, o.ShutdownReconnectInterval)
		final.InactivityTimeout = optMin(final.InactivityTimeout, o.InactivityTimeout)
		final.KeepAliveInterval = optMin(final.KeepAliveInterval, o.KeepAliveInterval)

		if o.Push != nil {
			if final.Push == nil {
				final.Push = &rawPushConfig{}
			}
			final.Push.Zones = append(final.Push.Zones, o.Push.Zones...)
			final.Push.ClassANY = append(final.Push.ClassANY, o.Push.ClassANY...)
			final.Push.TypeANY = append(final.Push.TypeANY, o.Push.TypeANY...)
			final.Push.RefreshInterval = optMin(final.Push.RefreshInterval, o.Push.RefreshInterval)
			final.Push.DebounceDelay = optMin(final.Push.DebounceDelay, o.Push.DebounceDelay)
		}

		if o.Log != nil {
			if final.Log == nil {
				final.Log = &rawLogConfig{}
			}
			final.Log.Incoming = cmp.Or(final.Log.Incoming, o.Log.Incoming)
			final.Log.Outgoing = cmp.Or(final.Log.Outgoing)
		}
	}

	cfg.TCPPort = optDefault(final.TCPPort, DefaultTCPPort)
	cfg.TLSPort = optDefault(final.TLSPort, DefaultTLSPort)
	cfg.RestartReconnectInterval = optDefault(final.RestartReconnectInterval, DefaultRestartReconnectInterval)
	cfg.ShutdownReconnectInterval = optDefault(final.ShutdownReconnectInterval, DefaultShutdownReconnectInterval)
	cfg.InactivityTimeout = optDefault(final.InactivityTimeout, DefaultInactivityTimeout)
	cfg.KeepAliveInterval = optDefault(final.KeepAliveInterval, DefaultKeepAliveInterval)
	if final.Push != nil {
		cfg.Push = &PushConfig{
			optDedup(final.Push.Zones),
			optDedup(final.Push.ClassANY),
			optDedup(final.Push.TypeANY),
			optDefault(final.Push.RefreshInterval, DefaultPushRefreshInterval),
			optDefault(final.Push.DebounceDelay, DefaultPushBurstDebounceInterval),
		}
	}
	if final.Log != nil {
		cfg.Log = &LogConfig{
			optDefault(final.Log.Incoming, DefaultIncomingLogFormat),
			optDefault(final.Log.Outgoing, DefaultOutgoingLogFormat),
		}
	}

	cfg.TsigSecret = final.TsigSecret
	cfg.TLSConfig = final.TLSConfig.Clone()

	return cfg, nil
}
