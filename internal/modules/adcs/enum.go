package adcs

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/MKlolbullen/AD-plower/internal/config"
	"github.com/MKlolbullen/AD-plower/internal/modules/unauth"
	"github.com/MKlolbullen/AD-plower/internal/workspace"
)

// Finding describes an AD CS certificate template together with the
// configuration flags that make it abusable (ESC1/4/8 etc.).
type Finding struct {
	Template           string   `json:"template"`
	Flags              int      `json:"flags"`
	AuthorizedSigs     int      `json:"authorized_signatures"`
	EnrolleeSuppliesSubject bool `json:"enrollee_supplies_subject"`   // ESC1 signal
	ManagerApproval    bool     `json:"manager_approval_required"`
	AnyPurposeEKU      bool     `json:"any_purpose_eku"`             // ESC2 signal
	ClientAuthEKU      bool     `json:"client_auth_eku"`
	LowPrivWriteOwner  bool     `json:"low_priv_write_owner"`        // ESC4 hint (heuristic)
	SecurityDescriptor string   `json:"security_descriptor"`
	Escalation         []string `json:"suspected_escalations"`
}

// CA represents a single Enrollment Service object.
type CA struct {
	Name      string    `json:"name"`
	DNSName   string    `json:"dns_name"`
	Templates []string  `json:"templates"`
	Findings  []Finding `json:"findings"`
}

// Template OIDs we inspect when classifying findings.
const (
	EnrolleeSuppliesSubjectFlag = 0x00000001
	ManagerApprovalFlag         = 0x00000002
	ClientAuthOID               = "1.3.6.1.5.5.7.3.2"
	AnyPurposeOID               = "2.5.29.37.0"
	SmartCardLogonOID           = "1.3.6.1.4.1.311.20.2.2"
	PKINITKPClientAuthOID       = "1.3.6.1.5.2.3.4"
)

// RunEnum queries the configuration NC to discover Enterprise CAs and their
// published certificate templates. Requires an authenticated bind — AD CS
// objects live under CN=Configuration and are rarely anonymously readable.
func RunEnum(dc string) ([]CA, error) {
	if config.Cfg.Username == "" {
		return nil, fmt.Errorf("adcs enum requires authenticated credentials")
	}
	conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s:389", dc))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.Bind(config.Cfg.Username+"@"+config.Cfg.Domain, config.Cfg.Password); err != nil {
		return nil, fmt.Errorf("bind: %w", err)
	}

	baseDN := unauth.DomainToBaseDN(config.Cfg.Domain)
	configNC := "CN=Configuration," + baseDN

	cas, err := enumCAs(conn, configNC)
	if err != nil {
		return nil, err
	}
	tmpls, err := enumTemplates(conn, configNC)
	if err != nil {
		return cas, err
	}
	for i := range cas {
		for _, pub := range cas[i].Templates {
			if f, ok := tmpls[strings.ToLower(pub)]; ok {
				cas[i].Findings = append(cas[i].Findings, f)
			}
		}
	}

	workspace.Patch(func(r *workspace.ReconResults) {
		for _, ca := range cas {
			r.ADCSCAs = append(r.ADCSCAs, workspace.ADCSEntry{
				CAName: ca.Name, DNSName: ca.DNSName, Templates: ca.Templates,
			})
		}
	})
	workspace.Save("adcs", cas)
	return cas, nil
}

func enumCAs(conn *ldap.Conn, configNC string) ([]CA, error) {
	sr, err := conn.Search(ldap.NewSearchRequest(
		"CN=Enrollment Services,CN=Public Key Services,CN=Services,"+configNC,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=pKIEnrollmentService)",
		[]string{"cn", "dNSHostName", "certificateTemplates"},
		nil,
	))
	if err != nil {
		return nil, err
	}
	var cas []CA
	for _, e := range sr.Entries {
		cas = append(cas, CA{
			Name:      e.GetAttributeValue("cn"),
			DNSName:   e.GetAttributeValue("dNSHostName"),
			Templates: e.GetAttributeValues("certificateTemplates"),
		})
	}
	return cas, nil
}

func enumTemplates(conn *ldap.Conn, configNC string) (map[string]Finding, error) {
	sr, err := conn.Search(ldap.NewSearchRequest(
		"CN=Certificate Templates,CN=Public Key Services,CN=Services,"+configNC,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=pKICertificateTemplate)",
		[]string{"cn", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag", "msPKI-RA-Signature", "pKIExtendedKeyUsage"},
		nil,
	))
	if err != nil {
		return nil, err
	}
	out := map[string]Finding{}
	for _, e := range sr.Entries {
		name := e.GetAttributeValue("cn")
		f := Finding{Template: name}
		f.Flags = atoi(e.GetAttributeValue("msPKI-Certificate-Name-Flag"))
		enrFlags := atoi(e.GetAttributeValue("msPKI-Enrollment-Flag"))
		f.AuthorizedSigs = atoi(e.GetAttributeValue("msPKI-RA-Signature"))
		f.EnrolleeSuppliesSubject = f.Flags&EnrolleeSuppliesSubjectFlag != 0
		f.ManagerApproval = enrFlags&ManagerApprovalFlag != 0
		for _, oid := range e.GetAttributeValues("pKIExtendedKeyUsage") {
			switch oid {
			case AnyPurposeOID:
				f.AnyPurposeEKU = true
			case ClientAuthOID, SmartCardLogonOID, PKINITKPClientAuthOID:
				f.ClientAuthEKU = true
			}
		}
		classify(&f)
		out[strings.ToLower(name)] = f
	}
	return out, nil
}

func classify(f *Finding) {
	if f.EnrolleeSuppliesSubject && f.ClientAuthEKU && !f.ManagerApproval && f.AuthorizedSigs == 0 {
		f.Escalation = append(f.Escalation, "ESC1")
	}
	if f.AnyPurposeEKU {
		f.Escalation = append(f.Escalation, "ESC2")
	}
}

func atoi(s string) int {
	n := 0
	neg := false
	for i, c := range s {
		if i == 0 && c == '-' {
			neg = true
			continue
		}
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	if neg {
		return -n
	}
	return n
}
