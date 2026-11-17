package directdns

import (
	"strconv"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/log"
	"github.com/miekg/dns"
)

func init() { plugin.Register("directdns", setup) }

func setup(c *caddy.Controller) error {
	d := newDirectDNS()
	for c.Next() {
		args := c.RemainingArgs()
		if len(args) == 0 {
			return c.ArgErr()
		}
		for _, zone := range args {
			normalized := dns.Fqdn(zone)
			log.Debugf("[directdns] adding zone: %s (from %s)", normalized, zone)
			d.Zones = append(d.Zones, normalized)
		}
		for c.NextBlock() {
			switch c.Val() {
			case "resolve_ns":
				if !c.NextArg() {
					return c.ArgErr()
				}
				v, err := strconv.ParseBool(c.Val())
				if err != nil {
					return c.Errf("invalid resolve_ns value: %v", err)
				}
				d.ResolveNS = v
			default:
				return c.Errf("unknown property: %s", c.Val())
			}
		}
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		d.Next = next
		log.Debugf("[directdns] plugin instance created")
		return d
	})

	return nil
}
