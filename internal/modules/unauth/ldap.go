package unauth

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

type LDAPResult struct {
	Users     []string
	Groups    []string
	Computers []string
}

func RunLDAPRecon(dc, domain string) (*LDAPResult, error) {
	res := &LDAPResult{}
	conn, err := ldap.Dial("tcp", dc+":389")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err = conn.UnauthenticatedBind(); err != nil {
		return nil, fmt.Errorf("anonymous bind failed: %w", err)
	}

	baseDN := "DC=" + strings.ReplaceAll(domain, ".", ",DC=")
	searchReq := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"name", "sAMAccountName", "dNSHostName"},
		nil,
	)

	sr, err := conn.Search(searchReq)
	if err != nil {
		return nil, err
	}

	for _, entry := range sr.Entries {
		if name := entry.GetAttributeValue("sAMAccountName"); name != "" {
			res.Users = append(res.Users, name)
		}
	}
	return res, nil
}
