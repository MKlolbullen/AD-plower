package unauth

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/MKlolbullen/AD-plower/internal/config"
)

// DNSResult captures AD-related SRV records for the target domain. The
// deduplicated DC list is the primary output consumed by downstream modules.
type DNSResult struct {
	DCs        []string          `json:"dcs"`
	KDCs       []string          `json:"kdcs"`
	GCs        []string          `json:"gcs"`
	SRVRecords map[string][]string `json:"srv_records"`
}

// srvRecords: the set of SRV FQDN prefixes we query to map out the forest.
// These match what "nltest /dsgetdc:" and impacket's dnsresolver probe.
var srvRecords = []string{
	"_ldap._tcp.dc._msdcs",
	"_kerberos._tcp.dc._msdcs",
	"_ldap._tcp",
	"_kerberos._tcp",
	"_gc._tcp",
	"_kpasswd._tcp",
	"_kerberos._udp",
}

// RunDNSRecon resolves the well-known AD SRV records for the target domain.
// If config.DNSServer is set it is queried directly, otherwise the system
// resolver is used.
func RunDNSRecon(domain string) (*DNSResult, error) {
	if domain == "" {
		return nil, fmt.Errorf("no domain configured")
	}
	res := &DNSResult{SRVRecords: map[string][]string{}}
	dcSet := map[string]struct{}{}
	gcSet := map[string]struct{}{}
	kdcSet := map[string]struct{}{}

	c := new(dns.Client)
	c.Timeout = time.Duration(config.Cfg.TimeoutSecs) * time.Second

	server := config.Cfg.DNSServer
	if server != "" && !strings.Contains(server, ":") {
		server = net.JoinHostPort(server, "53")
	}

	for _, prefix := range srvRecords {
		targets, err := resolveSRV(c, server, prefix+"."+domain)
		if err != nil {
			continue
		}
		res.SRVRecords[prefix] = targets
		for _, t := range targets {
			switch {
			case strings.Contains(prefix, "dc._msdcs"), prefix == "_ldap._tcp":
				dcSet[t] = struct{}{}
			case strings.HasPrefix(prefix, "_gc"):
				gcSet[t] = struct{}{}
			case strings.HasPrefix(prefix, "_kerberos"):
				kdcSet[t] = struct{}{}
			}
		}
	}

	for k := range dcSet {
		res.DCs = append(res.DCs, k)
	}
	for k := range gcSet {
		res.GCs = append(res.GCs, k)
	}
	for k := range kdcSet {
		res.KDCs = append(res.KDCs, k)
	}
	if len(res.DCs) == 0 {
		return res, fmt.Errorf("no DCs found via DNS for %s", domain)
	}
	return res, nil
}

func resolveSRV(c *dns.Client, server, name string) ([]string, error) {
	if server == "" {
		_, addrs, err := net.LookupSRV("", "", name)
		if err != nil {
			return nil, err
		}
		out := make([]string, 0, len(addrs))
		for _, a := range addrs {
			out = append(out, strings.TrimSuffix(a.Target, "."))
		}
		return out, nil
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeSRV)
	r, _, err := c.Exchange(m, server)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ans := range r.Answer {
		if s, ok := ans.(*dns.SRV); ok {
			out = append(out, strings.TrimSuffix(s.Target, "."))
		}
	}
	return out, nil
}
