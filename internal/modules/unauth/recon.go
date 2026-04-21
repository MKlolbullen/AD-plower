package unauth

import (
	"fmt"
	"github.com/MKlolbullen/AD-plower/internal/config"
	"github.com/MKlolbullen/AD-plower/internal/modules/bloodhound"
	"github.com/MKlolbullen/AD-plower/internal/modules/kerberos"
	"github.com/MKlolbullen/AD-plower/internal/workspace"
)

func RunUnauthRecon() {
	fmt.Println("🚀 Starting unauthenticated recon...")

	dnsRes, err := RunDNSRecon(config.Cfg.Domain)
	if err != nil {
		fmt.Printf("DNS failed: %v\n", err)
		return
	}
	fmt.Printf("✅ Found DCs: %v\n", dnsRes.DCs)

	for _, dc := range dnsRes.DCs {
		_, _ = RunLDAPRecon(dc, config.Cfg.Domain)
		if _, err := RunSMBNullSession(dc); err != nil {
			fmt.Printf("SMB null on %s skipped: %v\n", dc, err)
		}
	}

	if _, err := kerberos.RunASREPRoast(dnsRes.DCs[0]); err != nil {
		fmt.Printf("AS-REP roast skipped: %v\n", err)
	}

	workspace.SaveRecon("unauth", map[string]any{"dns_dcs": dnsRes.DCs})
	if err := bloodhound.IngestToBloodHound(); err != nil {
		fmt.Printf("BloodHound ingest skipped: %v\n", err)
	}
	fmt.Println("✅ Unauth recon + BloodHound complete")
}
