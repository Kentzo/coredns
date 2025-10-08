package dso

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

func init() { plugin.Register("dso", setup) }

func setup(c *caddy.Controller) error {
	for _, z := range plugin.OriginsFromArgsOrServerBlock([]string{}, c.ServerBlockKeys) {
		if z != "." {
			return plugin.Error("dso", errors.New("dso must be declared in the . zone"))
		}
	}

	d, err := parse(c)
	if err != nil {
		return plugin.Error("dso", err)
	}

	config := dnsserver.GetConfig(c)
	config.AddPlugin(func(next plugin.Handler) plugin.Handler {
		d.Next = next
		return d
	})
	config.HandleDSO = true

	c.OnStartup(d.OnStartup)
	c.OnRestart(d.OnRestart)
	c.OnRestartFailed(d.OnStartup)
	c.OnFinalShutdown(d.OnFinalShutdown)

	return nil
}

func parse(c *caddy.Controller) (d *DSO, err error) {
	var (
		useLog  bool
		logOpts logOpts = logOpts{
			incoming: DefaultIncomingLogFormat,
			outgoing: DefaultOutgoingLogFormat,
		}
		usePush bool
		dsoOpts dsoOpts = dsoOpts{
			cleanup:  DefaultCleanupInterval,
			restart:  DefaultRestartReconnectInterval,
			shutdown: DefaultShutdownReconnectInterval,
		}
		pushOpts pushOpts = pushOpts{
			refresh:    DefaultPushRefreshInterval,
			anyTypes:   DefaultPushAnyTypes[:],
			anyClasses: DefaultPushAnyClasses[:],
			debounce:   DefaultPushBurstDebounceInterval,
			maxSubs:    DefaultPushMaxSubscriptions,
		}
	)

	for i := 0; c.Next(); i++ {
		if i > 0 {
			return nil, plugin.ErrOnce
		}

		for c.NextBlock() {
			switch c.Val() {
			case "log":
				args := c.RemainingArgs()
				switch len(args) {
				case 0:
				case 1:
					logOpts.incoming = strings.ReplaceAll(args[0], "{common}", DefaultIncomingLogFormat)
					logOpts.outgoing = strings.ReplaceAll(args[0], "{common}", DefaultOutgoingLogFormat)
				case 2:
					logOpts.incoming = strings.ReplaceAll(args[0], "{common}", DefaultIncomingLogFormat)
					logOpts.outgoing = strings.ReplaceAll(args[1], "{common}", DefaultOutgoingLogFormat)
				default:
					return nil, c.ArgErr()
				}
				useLog = true
			case "cleanup":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				dsoOpts.cleanup, err = time.ParseDuration(args[0])
				if err != nil {
					return nil, c.Errf("invalid cleanup value %q: %v", args[0], err)
				}
			case "push":
				usePush = true
				pushOpts.zones = plugin.OriginsFromArgsOrServerBlock(c.RemainingArgs(), c.ServerBlockKeys)
			case "push_refresh":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				pushOpts.refresh, err = time.ParseDuration(args[0])
				if err != nil {
					return nil, c.Errf("invalid push_refresh value %q: %v", args[0], err)
				}
			case "push_any_types":
				args := c.RemainingArgs()
				pushOpts.anyTypes = make([]uint16, 0, len(args))
				for _, a := range args {
					t, ok := dns.StringToType[a]
					if !ok {
						return nil, c.Errf("unknown type %q", t)
					}
					pushOpts.anyTypes = append(pushOpts.anyTypes, t)
				}
			case "push_any_classes":
				args := c.RemainingArgs()
				pushOpts.anyClasses = make([]uint16, 0, len(args))
				for _, a := range args {
					cl, ok := dns.StringToClass[a]
					if !ok {
						return nil, c.Errf("unknown class %q", cl)
					}
					pushOpts.anyClasses = append(pushOpts.anyClasses, cl)
				}
			case "push_burst_debounce":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				pushOpts.debounce, err = time.ParseDuration(args[0])
				if err != nil {
					return nil, c.Errf("invalid push_burst_debounce value %q: %v", args[0], err)
				}
			case "push_max_subs":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				pushOpts.maxSubs, err = strconv.Atoi(args[0])
				if err != nil {
					return nil, c.Errf("invalid push_max_subs value %q: %v", args[0], err)
				}
			default:
				return nil, c.Errf("unknown property %q", c.Val())
			}
		}
	}

	d = New(dsoOpts)
	if usePush {
		d.pushH = newPushHandler(pushOpts)
	}
	if useLog {
		d.logH = newLogHandler(logOpts)
	}
	return d, nil
}

var (
	DefaultCleanupInterval           = 5 * time.Minute
	DefaultRestartReconnectInterval  = 5 * time.Second
	DefaultShutdownReconnectInterval = 15 * time.Second

	DefaultIncomingLogFormat = `{remote}:{port}: |<- {>id} {/dso/type} {/dso/rcode} {/dso/tlvtype}`
	DefaultOutgoingLogFormat = `{remote}:{port}: |-> {>id} {/dso/type} {/dso/rcode} {/dso/tlvtype}`

	DefaultPushAnyTypes = [...]uint16{
		dns.TypeA,
		dns.TypeAAAA,
		dns.TypeCNAME,
		dns.TypeNS,
		dns.TypePTR,
		dns.TypeSOA,
		dns.TypeSRV,
		dns.TypeTXT,
	}
	DefaultPushAnyClasses            = [...]uint16{dns.ClassINET}
	DefaultPushRefreshInterval       = 1 * time.Minute
	DefaultPushBurstDebounceInterval = 1 * time.Second
	DefaultPushMaxSubscriptions      = 4096
)
