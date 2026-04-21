package unauth

import (
	"fmt"
	"strings"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/mslsad"
	"github.com/jfjallid/go-smb/dcerpc/smbtransport"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"

	"github.com/MKlolbullen/AD-plower/internal/config"
	"github.com/MKlolbullen/AD-plower/internal/workspace"
)

// RIDResult is a RID -> resolved principal map produced by RID cycling
// against the LSA pipe on a DC. Useful when anonymous LDAP is locked down
// but LSA still accepts null-session lookups on legacy installs.
type RIDResult struct {
	DomainSID string            `json:"domain_sid"`
	Names     map[int]string    `json:"names"`
	Types     map[int]string    `json:"types"`
	Errors    map[int]string    `json:"errors"`
}

// RunRIDBrute performs LSA-based RID cycling on dc for RIDs in [start,end].
// Authenticates null-session by default; falls back to configured creds if
// the server rejects anonymous LSAR bind.
func RunRIDBrute(dc string, start, end int) (*RIDResult, error) {
	if dc == "" {
		return nil, fmt.Errorf("ridbrute: dc required")
	}
	if end < start || (end-start) > 10000 {
		return nil, fmt.Errorf("ridbrute: invalid range (max 10k RIDs per run)")
	}
	opts := smb.Options{
		Host: dc,
		Port: 445,
		Initiator: &spnego.NTLMInitiator{
			User:     config.Cfg.Username,
			Password: config.Cfg.Password,
			Hash:     hexHash(config.Cfg.NTHash),
			Domain:   config.Cfg.Domain,
		},
	}
	session, err := smb.NewConnection(opts)
	if err != nil {
		return nil, err
	}
	defer session.Close()

	const share = "IPC$"
	if err := session.TreeConnect(share); err != nil {
		return nil, err
	}
	defer session.TreeDisconnect(share)

	f, err := session.OpenFile(share, mslsad.MSRPCLsaRpcPipe)
	if err != nil {
		return nil, err
	}
	defer f.CloseFile()

	tr, err := smbtransport.NewSMBTransport(f)
	if err != nil {
		return nil, err
	}
	bind, err := dcerpc.Bind(tr, mslsad.MSRPCUuidLsaRpc, mslsad.MSRPCLsaRpcMajorVersion, mslsad.MSRPCLsaRpcMinorVersion, dcerpc.MSRPCUuidNdr)
	if err != nil {
		return nil, err
	}
	rpccon := mslsad.NewRPCCon(bind)

	domInfo, err := rpccon.GetPrimaryDomainInfo()
	if err != nil {
		return nil, err
	}
	domainSID := domInfo.Sid.ToString()

	res := &RIDResult{
		DomainSID: domainSID,
		Names:     map[int]string{},
		Types:     map[int]string{},
		Errors:    map[int]string{},
	}

	sids := make([]string, 0, end-start+1)
	for rid := start; rid <= end; rid++ {
		sids = append(sids, fmt.Sprintf("%s-%d", domainSID, rid))
	}
	trans, err := rpccon.LsarLookupSids2(mslsad.LsapLookupWksta, sids)
	if err != nil {
		return res, err
	}
	for i, t := range trans.TranslatedNames {
		rid := start + i
		if t.Name == "" {
			res.Errors[rid] = "unresolved"
			continue
		}
		res.Names[rid] = t.Name
		res.Types[rid] = sidTypeString(uint32(t.Use))
	}

	workspace.Patch(func(r *workspace.ReconResults) {
		for _, name := range res.Names {
			if !strings.Contains(name, "$") { // skip computer accounts
				r.Users = append(r.Users, name)
			}
		}
	})
	workspace.Save("ridbrute", res)
	return res, nil
}

func sidTypeString(t uint32) string {
	switch t {
	case 1:
		return "user"
	case 2:
		return "group"
	case 4:
		return "alias"
	case 5:
		return "well-known-group"
	case 6:
		return "deleted"
	case 7:
		return "invalid"
	case 8:
		return "unknown"
	case 9:
		return "computer"
	}
	return fmt.Sprintf("type-%d", t)
}
