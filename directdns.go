package directdns

import (
	"container/list"
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/upstream"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

const cacheMaxEntries = 100000

type DirectDNS struct {
	Next      plugin.Handler
	Zones     []string
	ResolveNS bool

	upstream *upstream.Upstream
	cuts     *cutCache
}

func newDirectDNS() *DirectDNS {
	return &DirectDNS{
		ResolveNS: true,
		upstream:  upstream.New(),
		cuts:      newCutCache(cacheMaxEntries),
	}
}

type cut struct {
	directNS []string
	publicNS []string
	expires  time.Time
}

type cacheEntry struct {
	key   string
	value cut
}

type cutCache struct {
	mu    sync.Mutex
	order *list.List
	items map[string]*list.Element
	max   int
}

func newCutCache(max int) *cutCache {
	return &cutCache{
		order: list.New(),
		items: make(map[string]*list.Element),
		max:   max,
	}
}

func (c *cutCache) get(key string) (cut, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.items[key]
	if !ok {
		return cut{}, false
	}
	entry := el.Value.(*cacheEntry)
	if time.Now().After(entry.value.expires) {
		c.remove(el)
		return cut{}, false
	}
	c.order.MoveToFront(el)
	return entry.value, true
}

func (c *cutCache) add(key string, value cut) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.items[key]; ok {
		el.Value.(*cacheEntry).value = value
		c.order.MoveToFront(el)
		return
	}

	el := c.order.PushFront(&cacheEntry{key: key, value: value})
	c.items[key] = el
	for c.order.Len() > c.max {
		c.remove(c.order.Back())
	}
}

func (c *cutCache) remove(el *list.Element) {
	entry := el.Value.(*cacheEntry)
	delete(c.items, entry.key)
	c.order.Remove(el)
}

type captureWriter struct {
	dns.ResponseWriter
	msg *dns.Msg
}

func (cw *captureWriter) WriteMsg(msg *dns.Msg) error {
	cw.msg = msg.Copy()
	return nil
}

var _ plugin.Handler = &DirectDNS{}

func (directdns *DirectDNS) Name() string { return "directdns" }

func (directdns *DirectDNS) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	queryName := state.Name()
	log.Debugf("[directdns] ServeDNS: query=%s, zones=%v", queryName, directdns.Zones)

	zone := directdns.matchZone(queryName)
	if zone != "" {
		log.Debugf("[directdns] direct match: query=%s, zone=%s", queryName, zone)
		return directdns.handleDirectQuery(ctx, r, w, zone, queryName)
	}

	if directdns.ResolveNS && !r.RecursionDesired {
		if rcode, ok := directdns.tryNSResolve(ctx, w, r); ok {
			return rcode, nil
		}
	}

	log.Debugf("[directdns] no direct match, trying indirect for: %s", queryName)
	return directdns.handleIndirectQuery(ctx, w, r)
}

func (directdns *DirectDNS) handleDirectQuery(ctx context.Context, r *dns.Msg, w dns.ResponseWriter, zone, queryName string) (int, error) {
	log.Debugf("[directdns] handleDirectQuery: query=%s, zone=%s", queryName, zone)
	subdomain := trimZone(queryName, zone)
	log.Debugf("[directdns] subdomain: %q", subdomain)
	if subdomain == "" {
		return plugin.NextOrFailure(directdns.Name(), directdns.Next, ctx, w, r)
	}
	ip := decodeIPv6(subdomain)
	log.Debugf("[directdns] decoded IPv6: %s", ip)
	if !ip.IsValid() {
		return plugin.NextOrFailure(directdns.Name(), directdns.Next, ctx, w, r)
	}

	proto := (&request.Request{W: w, Req: r}).Proto()
	resp, err := forwardToNode(r, ip, proto)
	if err != nil || resp == nil {
		log.Errorf("[directdns] forward to %s failed: %v", ip, err)
		return dns.RcodeServerFailure, nil
	}

	resp.Id = r.Id
	_ = w.WriteMsg(resp)
	return dns.RcodeSuccess, nil
}

func (directdns *DirectDNS) handleIndirectQuery(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	log.Debugf("[directdns] handleIndirectQuery called")
	if directdns.Next == nil {
		log.Debugf("[directdns] Next is nil, returning")
		return plugin.NextOrFailure(directdns.Name(), directdns.Next, ctx, w, r)
	}

	cw := &captureWriter{ResponseWriter: w}
	rcode, err := directdns.Next.ServeDNS(ctx, cw, r)
	if err != nil {
		log.Debugf("[directdns] Next returned error: %v", err)
		return rcode, err
	}
	resp := cw.msg
	if resp == nil {
		log.Debugf("[directdns] Next returned nil response")
		return rcode, nil
	}

	log.Debugf("[directdns] indirect response answer: %v", resp.Answer)
	proto := (&request.Request{W: w, Req: r}).Proto()
	newAnswer, modified := directdns.rewriteCNAMEs(resp, r, proto)
	if modified {
		log.Debugf("[directdns] CNAME rewritten, new answer: %v", newAnswer)
		newResp := new(dns.Msg)
		newResp.SetReply(r)
		newResp.Authoritative = resp.Authoritative
		newResp.Answer = newAnswer
		newResp.Ns = resp.Ns
		newResp.Extra = resp.Extra
		newResp.Rcode = resp.Rcode
		_ = w.WriteMsg(newResp)
		return dns.RcodeSuccess, nil
	}

	log.Debugf("[directdns] no CNAME rewrite, passing through")
	_ = w.WriteMsg(resp)
	return rcode, nil
}

func (directdns *DirectDNS) rewriteCNAMEs(originalResp *dns.Msg, r *dns.Msg, proto string) ([]dns.RR, bool) {
	var newAnswer []dns.RR
	found := false

	for _, rr := range originalResp.Answer {
		if found {
			break
		}
		newAnswer = append(newAnswer, rr)
		cname, ok := rr.(*dns.CNAME)
		if !ok {
			continue
		}

		log.Debugf("[directdns] checking CNAME target: %s", cname.Target)
		targetZone := directdns.matchZone(cname.Target)
		if targetZone == "" {
			log.Debugf("[directdns] CNAME target not in our zones")
			continue
		}

		subdomain := trimZone(cname.Target, targetZone)
		ip := decodeIPv6(subdomain)
		if !ip.IsValid() {
			log.Debugf("[directdns] could not decode IPv6 from subdomain: %s", subdomain)
			continue
		}

		log.Debugf("[directdns] querying IPv6 %s for CNAME target %s", ip, cname.Target)
		ipv6Resp, err := forwardToNode(reqWithName(r, cname.Target), ip, proto)
		if err != nil || ipv6Resp == nil {
			log.Debugf("[directdns] IPv6 query failed: %v", err)
			continue
		}
		if !usableRcode(ipv6Resp) {
			log.Debugf("[directdns] IPv6 query returned rcode %d", ipv6Resp.Rcode)
			continue
		}

		found = true
		newAnswer = append(newAnswer, ipv6Resp.Answer...)
	}

	return newAnswer, found
}

func (directdns *DirectDNS) matchZone(queryName string) string {
	return plugin.Zones(directdns.Zones).Matches(queryName)
}

func trimZone(queryName, zone string) string {
	queryName = dns.Fqdn(queryName)
	zone = dns.Fqdn(zone)
	if !strings.HasSuffix(queryName, zone) {
		return ""
	}
	return strings.TrimSuffix(queryName, zone)
}

func lastLabel(name string) string {
	name = strings.TrimSuffix(name, ".")
	parts := strings.Split(name, ".")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

func decodeIPv6(subdomain string) netip.Addr {
	label := lastLabel(subdomain)
	if label == "" {
		return netip.Addr{}
	}
	ip, err := netip.ParseAddr(strings.ReplaceAll(label, "-", ":"))
	if err != nil || !ip.Is6() {
		return netip.Addr{}
	}
	return ip
}

func reqWithName(req *dns.Msg, name string) *dns.Msg {
	msg := req.Copy()
	if len(msg.Question) > 0 {
		msg.Question[0].Name = dns.Fqdn(name)
	}
	return msg
}

func forwardToNode(req *dns.Msg, ip netip.Addr, network string) (*dns.Msg, error) {
	c := &dns.Client{Net: network, Timeout: 2 * time.Second}
	addr := netip.AddrPortFrom(ip, 53).String()
	resp, _, err := c.Exchange(req, addr)
	if err == nil && resp != nil && resp.Truncated && network == "udp" {
		c.Net = "tcp"
		resp, _, err = c.Exchange(req, addr)
	}
	return resp, err
}

func recursive(st request.Request) request.Request {
	req := st.Req.Copy()
	req.RecursionDesired = true
	return request.Request{W: st.W, Req: req}
}

func usableRcode(resp *dns.Msg) bool {
	if resp == nil {
		return false
	}
	return resp.Rcode == dns.RcodeSuccess || resp.Rcode == dns.RcodeNameError
}

func (d *DirectDNS) tryNSResolve(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, bool) {
	st := request.Request{W: w, Req: r}
	rst := recursive(st)
	qname := dns.CanonicalName(st.Name())

	c, ok := d.findCut(ctx, rst, qname)
	if !ok {
		return 0, false
	}
	if rcode, ok := d.proxyCut(ctx, w, r, c, (&st).Proto(), rst); ok {
		return rcode, true
	}
	return 0, false
}

func (d *DirectDNS) proxyCut(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, c cut, proto string, st request.Request) (int, bool) {
	if len(c.directNS) > 0 {
		direct := d.directAddrs(c)
		if resp, ok := d.tryEndpoints(ctx, r, direct, proto); ok {
			resp.Id = r.Id
			_ = w.WriteMsg(resp)
			return dns.RcodeSuccess, true
		}
	}

	if len(c.publicNS) > 0 {
		addrs := d.resolveNSAddrs(ctx, st, c.publicNS)
		if resp, ok := d.tryEndpoints(ctx, r, addrs, proto); ok {
			resp.Id = r.Id
			_ = w.WriteMsg(resp)
			return dns.RcodeSuccess, true
		}
	}
	return 0, false
}

func (d *DirectDNS) tryEndpoints(ctx context.Context, r *dns.Msg, addrs []netip.Addr, proto string) (*dns.Msg, bool) {
	if len(addrs) == 0 {
		return nil, false
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type res struct {
		msg *dns.Msg
		ok  bool
	}
	ch := make(chan res, len(addrs))
	for _, a := range addrs {
		go func() {
			resp, err := forwardToNode(r, a, proto)
			if err != nil || !usableRcode(resp) {
				ch <- res{}
				return
			}
			select {
			case ch <- res{msg: resp, ok: true}:
			case <-ctx.Done():
			}
		}()
	}
	for i := 0; i < len(addrs); i++ {
		select {
		case rr := <-ch:
			if rr.ok {
				cancel()
				return rr.msg, true
			}
		case <-ctx.Done():
			return nil, false
		}
	}
	return nil, false
}

func (d *DirectDNS) resolveNSAddrs(ctx context.Context, st request.Request, names []string) []netip.Addr {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, name := range names {
		for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := d.upstream.Lookup(ctx, st, name, t)
				if err != nil || resp == nil {
					return
				}
				for _, rr := range resp.Answer {
					var ip net.IP
					switch v := rr.(type) {
					case *dns.A:
						ip = v.A
					case *dns.AAAA:
						ip = v.AAAA
					}
					if ip == nil {
						continue
					}
					a, ok := netip.AddrFromSlice(ip)
					if !ok {
						continue
					}
					a = a.Unmap()
					mu.Lock()
					if !seen[a] {
						seen[a] = true
						out = append(out, a)
					}
					mu.Unlock()
				}
			}()
		}
	}
	wg.Wait()
	return out
}

// findCut walks the name's suffixes from the TLD down and returns the deepest
// directDNS delegation, if any. A recursive NS lookup cannot see a delegation
// whose NS target is in a directDNS zone, because that lookup is routed back to
// this relay. Each level after the TLD is therefore asked of its parent server
// directly, with RD=0.
func (d *DirectDNS) findCut(ctx context.Context, st request.Request, qname string) (cut, bool) {
	suffixes := candidateNames(qname)
	if len(suffixes) == 0 {
		return cut{}, false
	}
	slices.Reverse(suffixes)

	var best cut
	var zoneNS []string
	var servers []netip.Addr

	for i, name := range suffixes {
		c, ok := d.cuts.get(name)
		if !ok {
			if i == 0 {
				c, ok = d.probeCut(ctx, st, name)
			} else {
				if servers == nil {
					servers = d.resolveNSAddrs(ctx, st, zoneNS)
				}
				c, ok = d.probeParent(ctx, servers, name)
			}
			if !ok {
				return cut{}, false
			}
			d.cuts.add(name, c)
		}

		switch {
		case len(c.directNS) > 0:
			best = c
			zoneNS = nil
			servers = append(d.directAddrs(c), d.resolveNSAddrs(ctx, st, c.publicNS)...)
		case len(c.publicNS) > 0:
			zoneNS = c.publicNS
			servers = nil
		}
	}

	return best, len(best.directNS) > 0
}

// probeCut does a recursive NS lookup. It is only safe for public zones (the
// TLD), because a directDNS-delegated name would route the lookup back to this
// relay.
func (d *DirectDNS) probeCut(ctx context.Context, st request.Request, name string) (cut, bool) {
	name = dns.CanonicalName(name)
	resp, err := d.upstream.Lookup(ctx, st, name, dns.TypeNS)
	if err != nil || !usableRcode(resp) {
		return cut{}, false
	}
	return d.cutFrom(resp, name), true
}

// probeParent asks the enclosing zone's authoritative servers, with RD=0,
// whether name is delegated. A non-recursive query returns the parent's
// referral and never contacts the child.
func (d *DirectDNS) probeParent(ctx context.Context, servers []netip.Addr, name string) (cut, bool) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeNS)
	m.RecursionDesired = false
	resp, ok := d.tryEndpoints(ctx, m, servers, "udp")
	if !ok {
		return cut{}, false
	}
	return d.cutFrom(resp, name), true
}

// cutFrom classifies a response's NS records into directDNS and public targets
// and sets the cache expiry. It is shared by both probes so they cannot drift.
func (d *DirectDNS) cutFrom(resp *dns.Msg, name string) cut {
	nss, nsTTL := extractNS(resp, name)
	c := cut{}
	for _, ns := range nss {
		nsName := dns.CanonicalName(ns)
		if z := d.matchZone(nsName); z != "" {
			if ip := decodeIPv6(trimZone(nsName, z)); ip.IsValid() {
				c.directNS = append(c.directNS, nsName)
			}
			continue
		}
		c.publicNS = append(c.publicNS, nsName)
	}

	if len(c.directNS) == 0 && len(c.publicNS) == 0 {
		ttl := negativeTTL(resp)
		if ttl <= 0 {
			ttl = nsTTL
		}
		c.expires = time.Now().Add(ttl)
		return c
	}

	c.expires = time.Now().Add(nsTTL)
	return c
}

func (d *DirectDNS) directAddrs(c cut) []netip.Addr {
	out := make([]netip.Addr, 0, len(c.directNS))
	for _, ns := range c.directNS {
		if z := d.matchZone(ns); z != "" {
			if ip := decodeIPv6(trimZone(ns, z)); ip.IsValid() {
				out = append(out, ip)
			}
		}
	}
	return out
}

func candidateNames(qname string) []string {
	qname = dns.CanonicalName(qname)
	if qname == "" {
		return nil
	}
	offs := dns.Split(qname)
	if len(offs) == 0 {
		return []string{qname}
	}

	seen := map[string]bool{}
	var out []string
	for _, off := range offs {
		name := dns.CanonicalName(qname[off:])
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

func extractNS(resp *dns.Msg, owner string) ([]string, time.Duration) {
	owner = dns.CanonicalName(owner)
	seen := map[string]bool{}
	var out []string
	var ttl uint32
	haveTTL := false
	add := func(rr dns.RR) {
		ns, ok := rr.(*dns.NS)
		if !ok {
			return
		}
		if dns.CanonicalName(ns.Hdr.Name) != owner {
			return
		}
		if !haveTTL || ns.Hdr.Ttl < ttl {
			ttl = ns.Hdr.Ttl
			haveTTL = true
		}
		name := dns.CanonicalName(ns.Ns)
		if seen[name] {
			return
		}
		seen[name] = true
		out = append(out, name)
	}
	for _, rr := range resp.Answer {
		add(rr)
	}
	for _, rr := range resp.Ns {
		add(rr)
	}
	if !haveTTL {
		return out, 0
	}
	return out, time.Duration(ttl) * time.Second
}

func negativeTTL(resp *dns.Msg) time.Duration {
	var ttl uint32
	have := false
	for _, rr := range resp.Ns {
		soa, ok := rr.(*dns.SOA)
		if !ok {
			continue
		}
		t := soa.Minttl
		if soa.Hdr.Ttl < t {
			t = soa.Hdr.Ttl
		}
		if !have || t < ttl {
			ttl = t
			have = true
		}
	}
	if !have {
		return 0
	}
	return time.Duration(ttl) * time.Second
}
