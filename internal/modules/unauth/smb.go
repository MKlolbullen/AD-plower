package unauth

import (
	"fmt"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
	"github.com/jfjallid/go-smb/dcerpc/smbtransport"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"

	"github.com/MKlolbullen/AD-plower/internal/config"
)

// SMBResult describes the security posture we discovered on a single host:
// whether it requires signing, whether a null session was accepted, and the
// enumerated share list if SRVSVC responded.
type SMBResult struct {
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	NullSession bool     `json:"null_session"`
	SigningReq  bool     `json:"signing_required"`
	Shares      []string `json:"shares"`
	ShareDetail []Share  `json:"share_detail"`
	Username    string   `json:"auth_username"`
}

type Share struct {
	Name    string `json:"name"`
	Comment string `json:"comment"`
	Type    string `json:"type"`
}

func smbOptions(dc string, user, pass, ntHash string) smb.Options {
	return smb.Options{
		Host: dc,
		Port: 445,
		Initiator: &spnego.NTLMInitiator{
			User:     user,
			Password: pass,
			Hash:     hexHash(ntHash),
			Domain:   config.Cfg.Domain,
		},
	}
}

func hexHash(s string) []byte {
	if s == "" {
		return nil
	}
	b := make([]byte, 0, len(s)/2)
	v := 0
	for i, c := range s {
		d := 0
		switch {
		case c >= '0' && c <= '9':
			d = int(c - '0')
		case c >= 'a' && c <= 'f':
			d = int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = int(c-'A') + 10
		default:
			return nil
		}
		if i%2 == 0 {
			v = d << 4
		} else {
			b = append(b, byte(v|d))
		}
	}
	return b
}

// RunSMBNullSession attempts an anonymous SMB session against dc and, on
// success, enumerates shares through the SRVSVC RPC pipe. It also records
// whether signing is required — an input to downstream relaying decisions.
func RunSMBNullSession(dc string) (*SMBResult, error) {
	return runSMBEnum(dc, "", "", "", true)
}

// RunSMBAuthed uses the configured credentials to perform authenticated SMB
// enumeration.
func RunSMBAuthed(dc string) (*SMBResult, error) {
	return runSMBEnum(dc, config.Cfg.Username, config.Cfg.Password, config.Cfg.NTHash, false)
}

func runSMBEnum(dc, user, pass, hash string, allowNull bool) (*SMBResult, error) {
	res := &SMBResult{Host: dc, Port: 445}
	opts := smbOptions(dc, user, pass, hash)

	session, err := smb.NewConnection(opts)
	if err != nil {
		return res, fmt.Errorf("smb connect %s: %w", dc, err)
	}
	defer session.Close()

	res.SigningReq = session.IsSigningRequired()
	if session.IsAuthenticated() {
		res.NullSession = allowNull && user == "" && pass == "" && hash == ""
		res.Username = session.GetAuthUsername()
	}

	const share = "IPC$"
	if err := session.TreeConnect(share); err != nil {
		return res, fmt.Errorf("tree connect IPC$: %w", err)
	}
	defer session.TreeDisconnect(share)

	f, err := session.OpenFile(share, mssrvs.MSRPCSrvSvcPipe)
	if err != nil {
		return res, fmt.Errorf("open srvsvc pipe: %w", err)
	}
	defer f.CloseFile()

	tr, err := smbtransport.NewSMBTransport(f)
	if err != nil {
		return res, err
	}
	bind, err := dcerpc.Bind(tr, mssrvs.MSRPCUuidSrvSvc, mssrvs.MSRPCSrvSvcMajorVersion, mssrvs.MSRPCSrvSvcMinorVersion, dcerpc.MSRPCUuidNdr)
	if err != nil {
		return res, err
	}
	rpccon := mssrvs.NewRPCCon(bind)
	shares, err := rpccon.NetShareEnumAll(dc)
	if err != nil {
		return res, err
	}
	for _, sh := range shares {
		res.Shares = append(res.Shares, sh.Name)
		res.ShareDetail = append(res.ShareDetail, Share{Name: sh.Name, Comment: sh.Comment, Type: sh.Type})
	}
	return res, nil
}
