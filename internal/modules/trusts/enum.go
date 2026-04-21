package trusts

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"

	"github.com/MKlolbullen/AD-plower/internal/config"
	"github.com/MKlolbullen/AD-plower/internal/modules/unauth"
	"github.com/MKlolbullen/AD-plower/internal/workspace"
)

// Trust attribute bits we care about for foreign-domain pivot decisions.
const (
	TrustNonTransitive = 0x00000001
	TrustUplevelOnly   = 0x00000002
	TrustQuarantined   = 0x00000004
	TrustForestXfer    = 0x00000008
	TrustCrossOrg      = 0x00000010
	TrustWithinForest  = 0x00000020
)

// Trust is a single trusted-domain object with the most pentest-relevant
// attributes pulled up for convenience.
type Trust struct {
	Partner           string   `json:"partner"`
	Direction         int      `json:"direction"`
	Type              int      `json:"type"`
	Attributes        int      `json:"attributes"`
	Transitive        bool     `json:"transitive"`
	WithinForest      bool     `json:"within_forest"`
	ForestTransitive  bool     `json:"forest_transitive"`
	Notes             []string `json:"notes"`
}

// RunEnum enumerates trustedDomain objects from the target DC and attaches
// them to the workspace. Works with anonymous bind on many older DCs, but an
// authenticated bind surfaces additional attributes.
func RunEnum(dc string) ([]Trust, error) {
	if dc == "" {
		return nil, fmt.Errorf("trusts: dc required")
	}
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

	sr, err := conn.Search(ldap.NewSearchRequest(
		unauth.DomainToBaseDN(config.Cfg.Domain),
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=trustedDomain)",
		[]string{"trustPartner", "trustDirection", "trustType", "trustAttributes"},
		nil,
	))
	if err != nil {
		return nil, err
	}
	var out []Trust
	for _, e := range sr.Entries {
		attrs := atoi(e.GetAttributeValue("trustAttributes"))
		t := Trust{
			Partner:          e.GetAttributeValue("trustPartner"),
			Direction:        atoi(e.GetAttributeValue("trustDirection")),
			Type:             atoi(e.GetAttributeValue("trustType")),
			Attributes:       attrs,
			Transitive:       attrs&TrustNonTransitive == 0,
			WithinForest:     attrs&TrustWithinForest != 0,
			ForestTransitive: attrs&TrustForestXfer != 0,
		}
		if attrs&TrustQuarantined != 0 {
			t.Notes = append(t.Notes, "quarantined (SID filtering)")
		}
		if t.ForestTransitive {
			t.Notes = append(t.Notes, "forest-transitive — cross-forest TGT pivots possible")
		}
		out = append(out, t)
	}

	workspace.Patch(func(r *workspace.ReconResults) {
		for _, t := range out {
			r.Trusts = append(r.Trusts, workspace.TrustInfo{
				Name: t.Partner, Direction: t.Direction, Type: t.Type, Attrs: t.Attributes,
			})
		}
	})
	workspace.Save("trusts", out)
	return out, nil
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
