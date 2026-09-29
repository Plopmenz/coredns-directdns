package directdns

import (
	"context"
	"net"
	"testing"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

func TestIsLocalAddr(t *testing.T) {
	if !isLocalAddr(net.ParseIP("::1")) || !isLocalAddr(net.ParseIP("127.0.0.1")) {
		t.Fatal("loopback must count as local")
	}
	if isLocalAddr(net.ParseIP("2001:db8::1")) || isLocalAddr(nil) {
		t.Fatal("a documentation address or nil must not count as local")
	}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && !isLocalAddr(n.IP) {
			t.Errorf("own interface address %s not treated as local", n.IP)
		}
	}
}

// A name that decodes to this machine goes to the next plugin, never to itself.
type nextRecorder struct{ called bool }

func (n *nextRecorder) Name() string { return "next" }
func (n *nextRecorder) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	n.called = true
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeRefused)
	w.WriteMsg(m)
	return dns.RcodeRefused, nil
}

func TestDirectQueryForSelfIsNotForwarded(t *testing.T) {
	next := &nextRecorder{}
	d := &DirectDNS{Next: next, Zones: []string{"example.org."}}
	for _, name := range []string{"--1.example.org.", "0-0-0-0-0-0-0-1.example.org.", "0000-0-0-0-0-0-0-0001.example.org."} {
		next.called = false
		r := new(dns.Msg)
		r.SetQuestion(name, dns.TypeA)
		rec := dnstest.NewRecorder(&test.ResponseWriter{})
		if _, err := d.ServeDNS(context.Background(), rec, r); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !next.called {
			t.Errorf("%s decodes to ::1 and must go to the next plugin, not be forwarded", name)
		}
	}
}
