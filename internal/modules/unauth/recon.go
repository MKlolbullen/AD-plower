package unauth

import (
	"fmt"

	"github.com/MKlolbullen/AD-plower/internal/config"
	"github.com/MKlolbullen/AD-plower/internal/modules/bloodhound"
	"github.com/MKlolbullen/AD-plower/internal/modules/kerberos"
	"github.com/MKlolbullen/AD-plower/internal/workspace"
)

// Summary is the high-level output of a RunUnauthRecon pass — each downstream
// module also persists its own structured result into the workspace.
type Summary struct {
	Domain      string           `json:"domain"`
	DNS         *DNSResult       `json:"dns"`
	LDAP        map[string]*LDAPResult `json:"ldap"`
	SMB         map[string]*SMBResult  `json:"smb"`
	ASREP       int              `json:"asrep_hashes"`
	Errors      map[string]string `json:"errors"`
}

// RunUnauthRecon orchestrates a zero-credential sweep: DNS SRV → LDAP
// anonymous enumeration → SMB null session → AS-REP roast on any users the
// LDAP phase flagged as DONT_REQUIRE_PREAUTH. Every sub-step writes its
// results to the workspace; this function returns an aggregated summary
// for convenience.
func RunUnauthRecon() (*Summary, error) {
	if config.Cfg.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	sum := &Summary{
		Domain: config.Cfg.Domain,
		LDAP:   map[string]*LDAPResult{},
		SMB:    map[string]*SMBResult{},
		Errors: map[string]string{},
	}

	dnsRes, err := RunDNSRecon(config.Cfg.Domain)
	sum.DNS = dnsRes
	if err != nil {
		sum.Errors["dns"] = err.Error()
		if dnsRes == nil || len(dnsRes.DCs) == 0 {
			return sum, err
		}
	}
	workspace.Patch(func(r *workspace.ReconResults) { r.DCs = dnsRes.DCs })

	roastCandidates := map[string]struct{}{}
	for _, dc := range dnsRes.DCs {
		if ld, err := RunLDAPRecon(dc, config.Cfg.Domain); err != nil {
			sum.Errors["ldap:"+dc] = err.Error()
		} else {
			sum.LDAP[dc] = ld
			workspace.Patch(func(r *workspace.ReconResults) {
				r.Users = appendUnique(r.Users, ld.Users)
				r.Computers = appendUnique(r.Computers, ld.Computers)
				r.Groups = appendUnique(r.Groups, ld.Groups)
				for _, t := range ld.Trusts {
					r.Trusts = append(r.Trusts, workspace.TrustInfo{
						Name: t.Partner, Direction: t.Direction, Type: t.Type, Attrs: t.Attrs,
					})
				}
			})
			for _, u := range ld.ASREPRoastable {
				roastCandidates[u] = struct{}{}
			}
		}

		if smb, err := RunSMBNullSession(dc); err != nil {
			sum.Errors["smb:"+dc] = err.Error()
		} else {
			sum.SMB[dc] = smb
			workspace.Patch(func(r *workspace.ReconResults) {
				r.SMBHosts = append(r.SMBHosts, workspace.SMBHost{
					Host:        smb.Host,
					SigningReq:  smb.SigningReq,
					NullSession: smb.NullSession,
					Shares:      smb.Shares,
				})
			})
		}
	}

	if len(roastCandidates) > 0 {
		users := make([]string, 0, len(roastCandidates))
		for u := range roastCandidates {
			users = append(users, u)
		}
		if res, err := kerberos.RunASREPRoast(dnsRes.DCs[0], users); err != nil {
			sum.Errors["asrep"] = err.Error()
		} else {
			sum.ASREP = len(res.Hashes)
		}
	}

	if err := bloodhound.IngestToBloodHound(); err != nil {
		sum.Errors["bloodhound"] = err.Error()
	}
	workspace.Save("unauth_summary", sum)
	return sum, nil
}

func appendUnique(existing, new []string) []string {
	seen := make(map[string]struct{}, len(existing))
	for _, v := range existing {
		seen[v] = struct{}{}
	}
	for _, v := range new {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		existing = append(existing, v)
	}
	return existing
}
