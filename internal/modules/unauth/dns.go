package unauth

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

type DNSResult struct {
	DCs []string
}

func RunDNSRecon(domain string) (*DNSResult, error) {
	res := &DNSResult{}
	c := new(dns.Client)
	for _, srv := range []string{"_ldap._tcp", "_kerberos._tcp", "_gc._tcp", "_kpasswd._tcp"} {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(srv+"."+domain), dns.TypeSRV)
		r, _, err := c.Exchange(m, net.JoinHostPort("8.8.8.8", "53"))
		if err != nil {
			continue
		}
		for _, ans := range r.Answer {
			if srv, ok := ans.(*dns.SRV); ok {
				res.DCs = append(res.DCs, strings.TrimSuffix(srv.Target, "."))
			}
		}
	}
	if len(res.DCs) == 0 {
		return nil, fmt.Errorf("no DCs found via DNS")
	}
	return res, nil
}
