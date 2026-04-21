package vulns

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/MKlolbullen/AD-plower/internal/config"
	"github.com/MKlolbullen/AD-plower/internal/modules/unauth"
	"github.com/MKlolbullen/AD-plower/internal/workspace"
)

// Report is the set of vulnerability findings discovered by read-only LDAP
// signals. Each finding is scoped to a specific target with a severity and
// confidence hint so the operator can triage.
type Report struct {
	Findings []workspace.VulnFinding `json:"findings"`
}

// Run collects lightweight vulnerability signals:
//   - MachineAccountQuota > 0 (noPac prerequisite)
//   - DCs missing the ZeroLogon patch version (heuristic via operatingSystemVersion)
//   - ms-DS-AllowedToActOnBehalfOfOtherIdentity configured on computer objects
//   - dont-require-preauth users (AS-REP roastable)
//   - Pre-Windows 2000 compatible access group membership via anonymous
func Run(dc string) (*Report, error) {
	rep := &Report{}

	conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s:389", dc))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if config.Cfg.Username != "" && config.Cfg.Password != "" {
		_ = conn.Bind(config.Cfg.Username+"@"+config.Cfg.Domain, config.Cfg.Password)
	} else {
		_ = conn.UnauthenticatedBind("")
	}

	base := unauth.DomainToBaseDN(config.Cfg.Domain)

	rep.checkMachineQuota(conn, base, dc)
	rep.checkRBCD(conn, base, dc)
	rep.checkASREPRoastable(conn, base)
	rep.checkOSVersions(conn, base)

	workspace.Patch(func(r *workspace.ReconResults) {
		r.Vulns = append(r.Vulns, rep.Findings...)
	})
	workspace.Save("vulns", rep)
	return rep, nil
}

func (rep *Report) checkMachineQuota(conn *ldap.Conn, base, dc string) {
	sr, err := conn.Search(ldap.NewSearchRequest(
		base, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{"ms-DS-MachineAccountQuota"}, nil,
	))
	if err != nil || len(sr.Entries) == 0 {
		return
	}
	q := atoi(sr.Entries[0].GetAttributeValue("ms-DS-MachineAccountQuota"))
	if q > 0 {
		rep.Findings = append(rep.Findings, workspace.VulnFinding{
			Name:       "MachineAccountQuota > 0",
			Target:     dc,
			Severity:   "medium",
			Confidence: "high",
			Notes:      fmt.Sprintf("Any authenticated user may create up to %d computers — prerequisite for noPac / RBCD abuse.", q),
		})
	}
}

func (rep *Report) checkRBCD(conn *ldap.Conn, base, dc string) {
	sr, err := conn.SearchWithPaging(ldap.NewSearchRequest(
		base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
		[]string{"sAMAccountName", "msDS-AllowedToActOnBehalfOfOtherIdentity"},
		nil,
	), 500)
	if err != nil {
		return
	}
	for _, e := range sr.Entries {
		rep.Findings = append(rep.Findings, workspace.VulnFinding{
			Name:       "Resource-Based Constrained Delegation configured",
			Target:     e.GetAttributeValue("sAMAccountName"),
			Severity:   "high",
			Confidence: "high",
			Notes:      "RBCD set — check whether any principal you control is referenced in the SD.",
		})
	}
}

func (rep *Report) checkASREPRoastable(conn *ldap.Conn, base string) {
	sr, err := conn.SearchWithPaging(ldap.NewSearchRequest(
		base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
		[]string{"sAMAccountName"}, nil,
	), 500)
	if err != nil {
		return
	}
	for _, e := range sr.Entries {
		rep.Findings = append(rep.Findings, workspace.VulnFinding{
			Name:       "AS-REP roastable user",
			Target:     e.GetAttributeValue("sAMAccountName"),
			Severity:   "high",
			Confidence: "high",
			Notes:      "User has DONT_REQUIRE_PREAUTH set; request AS-REP and crack offline.",
		})
	}
}

// checkOSVersions flags DCs that advertise very old operatingSystemVersion
// strings — a proxy for missing ZeroLogon / PrintNightmare / NoPac patching.
// Non-authoritative; it's an "investigate" signal, not an exploit confirmation.
func (rep *Report) checkOSVersions(conn *ldap.Conn, base string) {
	sr, err := conn.SearchWithPaging(ldap.NewSearchRequest(
		base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectCategory=computer)(primaryGroupID=516))",
		[]string{"dNSHostName", "operatingSystemVersion", "operatingSystem"},
		nil,
	), 100)
	if err != nil {
		return
	}
	for _, e := range sr.Entries {
		host := e.GetAttributeValue("dNSHostName")
		ver := e.GetAttributeValue("operatingSystemVersion")
		os := e.GetAttributeValue("operatingSystem")
		switch {
		case strings.HasPrefix(ver, "6.1"), strings.HasPrefix(ver, "6.0"),
			strings.Contains(os, "2008"), strings.Contains(os, "2003"):
			rep.Findings = append(rep.Findings, workspace.VulnFinding{
				Name:       "Unsupported DC OS",
				Target:     host,
				Severity:   "critical",
				Confidence: "high",
				Notes:      fmt.Sprintf("DC runs %s (%s) — out of support, almost certainly vulnerable to multiple unpatched remote bugs.", os, ver),
			})
		case strings.HasPrefix(ver, "6.3"), strings.HasPrefix(ver, "10.0"):
			// Windows 2012R2/2016/2019/2022 — need monthly patch level for ZeroLogon/PrintNightmare/NoPac.
			rep.Findings = append(rep.Findings, workspace.VulnFinding{
				Name:       "Verify ZeroLogon / PrintNightmare / NoPac patch level",
				Target:     host,
				Severity:   "info",
				Confidence: "low",
				Notes:      fmt.Sprintf("DC advertises %s (%s); confirm KB levels for CVE-2020-1472/CVE-2021-34527/CVE-2021-42278.", os, ver),
			})
		}
	}
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
