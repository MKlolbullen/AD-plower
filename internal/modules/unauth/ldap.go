package unauth

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/MKlolbullen/AD-plower/internal/config"
)

// UAC flag bits we care about for roast/pre-auth checks.
const (
	UAC_DONT_REQUIRE_PREAUTH = 0x400000
	UAC_TRUSTED_FOR_DELEGATION = 0x80000
	UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
	UAC_ACCOUNTDISABLE = 0x2
)

// LDAPResult is the common shape returned by anonymous and authenticated
// enumeration. Fields are populated best-effort: an anonymous bind to a
// hardened DC may only return a handful of attributes but the struct still
// contains what we got.
type LDAPResult struct {
	DC               string    `json:"dc"`
	BaseDN           string    `json:"base_dn"`
	Anonymous        bool      `json:"anonymous"`
	Users            []string  `json:"users"`
	Groups           []string  `json:"groups"`
	Computers        []string  `json:"computers"`
	ASREPRoastable   []string  `json:"asrep_roastable"`
	DelegationUsers  []string  `json:"delegation_users"`
	SPNs             []SPN     `json:"spns"`
	Trusts           []LDTrust `json:"trusts"`
	NamingContexts   []string  `json:"naming_contexts"`
	MachineAcctQuota int       `json:"ms_ds_machine_account_quota"`
}

type SPN struct {
	User string `json:"user"`
	SPN  string `json:"spn"`
}

type LDTrust struct {
	Partner   string `json:"partner"`
	Direction int    `json:"direction"`
	Type      int    `json:"type"`
	Attrs     int    `json:"attrs"`
}

// DomainToBaseDN turns "lab.local" into "DC=lab,DC=local".
func DomainToBaseDN(domain string) string {
	parts := strings.Split(domain, ".")
	for i, p := range parts {
		parts[i] = "DC=" + p
	}
	return strings.Join(parts, ",")
}

func dialDC(dc string) (*ldap.Conn, error) {
	to := time.Duration(config.Cfg.TimeoutSecs) * time.Second
	ldap.DefaultTimeout = to
	return ldap.DialURL(fmt.Sprintf("ldap://%s:389", dc))
}

// RunLDAPRecon tries anonymous bind first, then falls back to authenticated
// bind if credentials are configured. Populates as much of LDAPResult as the
// bind level allows.
func RunLDAPRecon(dc, domain string) (*LDAPResult, error) {
	res := &LDAPResult{DC: dc, BaseDN: DomainToBaseDN(domain)}

	conn, err := dialDC(dc)
	if err != nil {
		return nil, fmt.Errorf("ldap dial %s: %w", dc, err)
	}
	defer conn.Close()

	// 1. Root DSE is usually readable even without a bind.
	if rootDSE, err := readRootDSE(conn); err == nil {
		res.NamingContexts = rootDSE
	}

	// 2. Try anonymous bind.
	anonErr := conn.UnauthenticatedBind("")
	if anonErr != nil {
		// Some DCs reject UnauthenticatedBind but accept a true anonymous bind.
		anonErr = conn.Bind("", "")
	}
	if anonErr == nil {
		res.Anonymous = true
	}

	// 3. If we have creds, upgrade to an authenticated bind.
	if config.Cfg.Username != "" && config.Cfg.Password != "" {
		userDN := fmt.Sprintf("%s@%s", config.Cfg.Username, domain)
		if err := conn.Bind(userDN, config.Cfg.Password); err != nil {
			if !res.Anonymous {
				return nil, fmt.Errorf("ldap bind failed: %w", err)
			}
		} else {
			res.Anonymous = false
		}
	}

	// 4. Enumerate users, computers, groups, SPNs, UAC flags.
	if err := enumUsers(conn, res); err != nil {
		return res, err
	}
	enumComputers(conn, res)
	enumGroups(conn, res)
	enumTrusts(conn, res)
	enumMachineQuota(conn, res)
	return res, nil
}

func readRootDSE(conn *ldap.Conn) ([]string, error) {
	sr, err := conn.Search(ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{"namingContexts", "defaultNamingContext"}, nil,
	))
	if err != nil {
		return nil, err
	}
	var nc []string
	for _, e := range sr.Entries {
		nc = append(nc, e.GetAttributeValues("namingContexts")...)
	}
	return nc, nil
}

func enumUsers(conn *ldap.Conn, res *LDAPResult) error {
	sr, err := conn.SearchWithPaging(ldap.NewSearchRequest(
		res.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectCategory=person)(objectClass=user))",
		[]string{"sAMAccountName", "userAccountControl", "servicePrincipalName"},
		nil,
	), 500)
	if err != nil {
		return err
	}
	for _, e := range sr.Entries {
		name := e.GetAttributeValue("sAMAccountName")
		if name == "" {
			continue
		}
		res.Users = append(res.Users, name)

		uac := parseUAC(e.GetAttributeValue("userAccountControl"))
		if uac&UAC_DONT_REQUIRE_PREAUTH != 0 {
			res.ASREPRoastable = append(res.ASREPRoastable, name)
		}
		if uac&(UAC_TRUSTED_FOR_DELEGATION|UAC_TRUSTED_TO_AUTH_FOR_DELEGATION) != 0 {
			res.DelegationUsers = append(res.DelegationUsers, name)
		}
		for _, spn := range e.GetAttributeValues("servicePrincipalName") {
			res.SPNs = append(res.SPNs, SPN{User: name, SPN: spn})
		}
	}
	return nil
}

func enumComputers(conn *ldap.Conn, res *LDAPResult) {
	sr, err := conn.SearchWithPaging(ldap.NewSearchRequest(
		res.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectCategory=computer)",
		[]string{"dNSHostName", "sAMAccountName"},
		nil,
	), 500)
	if err != nil {
		return
	}
	for _, e := range sr.Entries {
		host := e.GetAttributeValue("dNSHostName")
		if host == "" {
			host = e.GetAttributeValue("sAMAccountName")
		}
		if host != "" {
			res.Computers = append(res.Computers, host)
		}
	}
}

func enumGroups(conn *ldap.Conn, res *LDAPResult) {
	sr, err := conn.SearchWithPaging(ldap.NewSearchRequest(
		res.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=group)",
		[]string{"sAMAccountName"},
		nil,
	), 500)
	if err != nil {
		return
	}
	for _, e := range sr.Entries {
		if n := e.GetAttributeValue("sAMAccountName"); n != "" {
			res.Groups = append(res.Groups, n)
		}
	}
}

func enumTrusts(conn *ldap.Conn, res *LDAPResult) {
	sr, err := conn.Search(ldap.NewSearchRequest(
		res.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=trustedDomain)",
		[]string{"trustPartner", "trustDirection", "trustType", "trustAttributes"},
		nil,
	))
	if err != nil {
		return
	}
	for _, e := range sr.Entries {
		res.Trusts = append(res.Trusts, LDTrust{
			Partner:   e.GetAttributeValue("trustPartner"),
			Direction: atoi(e.GetAttributeValue("trustDirection")),
			Type:      atoi(e.GetAttributeValue("trustType")),
			Attrs:     atoi(e.GetAttributeValue("trustAttributes")),
		})
	}
}

func enumMachineQuota(conn *ldap.Conn, res *LDAPResult) {
	sr, err := conn.Search(ldap.NewSearchRequest(
		res.BaseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"ms-DS-MachineAccountQuota"},
		nil,
	))
	if err != nil || len(sr.Entries) == 0 {
		return
	}
	res.MachineAcctQuota = atoi(sr.Entries[0].GetAttributeValue("ms-DS-MachineAccountQuota"))
}

func parseUAC(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func atoi(s string) int { return parseUAC(s) }
