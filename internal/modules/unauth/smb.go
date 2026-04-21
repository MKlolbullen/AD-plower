package unauth

import (
	"fmt"
	"github.com/MKlolbullen/AD-plower/internal/config"

	"github.com/jfjallid/go-smb/smb"
)

type SMBResult struct {
	Shares []string
}

func RunSMBNullSession(dc string) (*SMBResult, error) {
	res := &SMBResult{}
	options := smb.Options{
		Host:        dc,
		Port:        445,
		User:        "",
		Password:    "",
		Domain:      config.Cfg.Domain,
		Workstation: "WORKSTATION",
	}
	conn, err := smb.NewConnection(options)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	shares, err := conn.ListShares()
	if err == nil {
		res.Shares = shares
	}
	fmt.Printf("✅ SMB null on %s → %d shares visible\n", dc, len(res.Shares))
	return res, nil
}
