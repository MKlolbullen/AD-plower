package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/MKlolbullen/AD-plower/internal/config"
	"github.com/MKlolbullen/AD-plower/internal/modules/adcs"
	"github.com/MKlolbullen/AD-plower/internal/modules/bloodhound"
	"github.com/MKlolbullen/AD-plower/internal/modules/kerberos"
	"github.com/MKlolbullen/AD-plower/internal/modules/password"
	"github.com/MKlolbullen/AD-plower/internal/modules/trusts"
	"github.com/MKlolbullen/AD-plower/internal/modules/unauth"
	"github.com/MKlolbullen/AD-plower/internal/modules/vulns"
	"github.com/MKlolbullen/AD-plower/internal/workspace"
)

// StartMCPServer boots the Model Context Protocol server over stdio. Every
// AD-Plower module is registered as a tool so Claude (or any MCP host) can
// drive the engagement autonomously — set target, run recon, decide the
// next pivot based on the returned JSON evidence.
func StartMCPServer() error {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "ad-plower",
		Title:   "AD-Plower Active Directory pentesting MCP",
		Version: "0.2.0",
	}, nil)

	registerTargetTools(server)
	registerReconTools(server)
	registerKerberosTools(server)
	registerCredTools(server)
	registerADCSTools(server)
	registerVulnTools(server)
	registerBloodHoundTools(server)
	registerWorkspaceTools(server)

	log.Printf("ad-plower MCP server ready (stdio)")
	return server.Run(context.Background(), &mcp.StdioTransport{})
}

// --- helpers ---------------------------------------------------------------

func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

func jsonResult(v any) *mcp.CallToolResult {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return textResult(fmt.Sprintf("marshal error: %v", err))
	}
	return textResult(string(b))
}

func errResult(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
	}
}

// currentDC returns the first DC we know about, or the Target field as a
// fallback when the operator supplied a bare IP.
func currentDC() string {
	snap := workspace.Snapshot()
	if len(snap.DCs) > 0 {
		return snap.DCs[0]
	}
	if config.Cfg.Target != "" {
		return config.Cfg.Target
	}
	return ""
}

// --- target / session configuration ---------------------------------------

type setTargetInput struct {
	Domain      string `json:"domain,omitempty" jsonschema:"AD domain (e.g. lab.local)"`
	Target      string `json:"target,omitempty" jsonschema:"DC IP / hostname / CIDR"`
	Username    string `json:"username,omitempty" jsonschema:"Optional username"`
	Password    string `json:"password,omitempty" jsonschema:"Optional password"`
	NTHash      string `json:"nt_hash,omitempty" jsonschema:"Optional NT hash (hex)"`
	DC          string `json:"dc,omitempty" jsonschema:"Explicit DC hostname"`
	DNSServer   string `json:"dns_server,omitempty" jsonschema:"Override DNS resolver"`
	Workspace   string `json:"workspace,omitempty" jsonschema:"Output directory"`
	BHNeo4jURI  string `json:"bh_neo4j_uri,omitempty" jsonschema:"Neo4j URI for BloodHound ingest"`
	BHNeo4jUser string `json:"bh_neo4j_user,omitempty" jsonschema:"Neo4j user"`
	BHNeo4jPass string `json:"bh_neo4j_pass,omitempty" jsonschema:"Neo4j password"`
	BHCEEnabled *bool  `json:"bh_ce_enabled,omitempty" jsonschema:"Enable BloodHound CE ingest"`
	Threads     int    `json:"threads,omitempty" jsonschema:"Worker threads for bulk modules"`
}

func registerTargetTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "set_target",
		Description: "Configure domain, target IP/range and optional credentials. Safe to call multiple times; only non-empty fields are applied.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in setTargetInput) (*mcp.CallToolResult, any, error) {
		if in.Domain != "" {
			config.Cfg.Domain = in.Domain
		}
		if in.Target != "" {
			config.Cfg.Target = in.Target
		}
		if in.Username != "" {
			config.Cfg.Username = in.Username
		}
		if in.Password != "" {
			config.Cfg.Password = in.Password
		}
		if in.NTHash != "" {
			config.Cfg.NTHash = in.NTHash
		}
		if in.DC != "" {
			config.Cfg.DC = in.DC
		}
		if in.DNSServer != "" {
			config.Cfg.DNSServer = in.DNSServer
		}
		if in.Workspace != "" {
			config.Cfg.Workspace = in.Workspace
		}
		if in.BHNeo4jURI != "" {
			config.Cfg.BHNeo4jURI = in.BHNeo4jURI
		}
		if in.BHNeo4jUser != "" {
			config.Cfg.BHNeo4jUser = in.BHNeo4jUser
		}
		if in.BHNeo4jPass != "" {
			config.Cfg.BHNeo4jPass = in.BHNeo4jPass
		}
		if in.BHCEEnabled != nil {
			config.Cfg.BHCEEnabled = *in.BHCEEnabled
		}
		if in.Threads > 0 {
			config.Cfg.Threads = in.Threads
		}
		config.ApplyDefaults()
		return jsonResult(map[string]any{
			"domain":    config.Cfg.Domain,
			"target":    config.Cfg.Target,
			"username":  config.Cfg.Username,
			"workspace": config.Cfg.Workspace,
			"bh_ce":     config.Cfg.BHCEEnabled,
			"ts":        time.Now().UTC().Format(time.RFC3339),
		}), nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_config",
		Description: "Return the active AD-Plower configuration (credentials are redacted in the output).",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		c := config.Cfg
		if c.Password != "" {
			c.Password = "***"
		}
		if c.NTHash != "" {
			c.NTHash = "***"
		}
		return jsonResult(c), nil, nil
	})
}

// --- recon tools -----------------------------------------------------------

func registerReconTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "run_unauth_recon",
		Description: "Run the full zero-credential pass: DNS SRV → anonymous LDAP → SMB null session → AS-REP roast → BloodHound ingest.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		sum, err := unauth.RunUnauthRecon()
		if err != nil && sum == nil {
			return errResult(err), nil, nil
		}
		return jsonResult(sum), nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "run_dns_recon",
		Description: "Resolve AD SRV records for the configured domain (DCs, KDCs, GCs).",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		res, err := unauth.RunDNSRecon(config.Cfg.Domain)
		if err != nil && res == nil {
			return errResult(err), nil, nil
		}
		return jsonResult(res), nil, nil
	})

	type ldapInput struct {
		DC string `json:"dc,omitempty" jsonschema:"Override DC hostname (falls back to discovered DCs)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "run_ldap_enum",
		Description: "Enumerate users, groups, computers, SPNs, trusts and ms-DS-MachineAccountQuota via LDAP. Uses an authenticated bind if credentials are set.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in ldapInput) (*mcp.CallToolResult, any, error) {
		dc := in.DC
		if dc == "" {
			dc = currentDC()
		}
		if dc == "" {
			return errResult(fmt.Errorf("no DC configured — call run_dns_recon or set_target first")), nil, nil
		}
		res, err := unauth.RunLDAPRecon(dc, config.Cfg.Domain)
		if err != nil {
			return errResult(err), nil, nil
		}
		return jsonResult(res), nil, nil
	})

	type smbInput struct {
		Host       string `json:"host,omitempty" jsonschema:"Target host (defaults to first known DC)"`
		Authed     bool   `json:"authenticated,omitempty" jsonschema:"Use configured creds instead of null session"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "run_smb_enum",
		Description: "Connect to SMB (445), record signing requirement, and attempt SRVSVC NetShareEnumAll.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in smbInput) (*mcp.CallToolResult, any, error) {
		host := in.Host
		if host == "" {
			host = currentDC()
		}
		if host == "" {
			return errResult(fmt.Errorf("no host configured")), nil, nil
		}
		var (
			res *unauth.SMBResult
			err error
		)
		if in.Authed {
			res, err = unauth.RunSMBAuthed(host)
		} else {
			res, err = unauth.RunSMBNullSession(host)
		}
		if err != nil {
			return errResult(err), nil, nil
		}
		return jsonResult(res), nil, nil
	})

	type ridInput struct {
		DC    string `json:"dc,omitempty" jsonschema:"DC hostname"`
		Start int    `json:"start" jsonschema:"Starting RID"`
		End   int    `json:"end" jsonschema:"Ending RID (<= start+10000)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "run_rid_bruteforce",
		Description: "LSA RID cycling via \\PIPE\\lsarpc. Resolves RIDs in [start,end] to principal names.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in ridInput) (*mcp.CallToolResult, any, error) {
		dc := in.DC
		if dc == "" {
			dc = currentDC()
		}
		res, err := unauth.RunRIDBrute(dc, in.Start, in.End)
		if err != nil && res == nil {
			return errResult(err), nil, nil
		}
		return jsonResult(res), nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "enum_trusts",
		Description: "Enumerate trustedDomain objects and classify forest-transitive / quarantined / within-forest trusts.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in ldapInput) (*mcp.CallToolResult, any, error) {
		dc := in.DC
		if dc == "" {
			dc = currentDC()
		}
		res, err := trusts.RunEnum(dc)
		if err != nil {
			return errResult(err), nil, nil
		}
		return jsonResult(res), nil, nil
	})
}

// --- kerberos --------------------------------------------------------------

func registerKerberosTools(s *mcp.Server) {
	type asrepInput struct {
		DC    string   `json:"dc,omitempty" jsonschema:"DC hostname"`
		Users []string `json:"users,omitempty" jsonschema:"Usernames to test (falls back to the users discovered in the workspace)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "run_asrep_roast",
		Description: "Issue pre-auth-less AS-REQs for the supplied users. Returns hashcat -m 18200 strings for any roastable accounts.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in asrepInput) (*mcp.CallToolResult, any, error) {
		dc := in.DC
		if dc == "" {
			dc = currentDC()
		}
		users := in.Users
		if len(users) == 0 {
			users = workspace.Snapshot().Users
		}
		if len(users) == 0 {
			return errResult(fmt.Errorf("no users supplied and workspace is empty — run LDAP enum first")), nil, nil
		}
		res, err := kerberos.RunASREPRoast(dc, users)
		if err != nil {
			return errResult(err), nil, nil
		}
		return jsonResult(res), nil, nil
	})

	type roastInput struct {
		DC string `json:"dc,omitempty" jsonschema:"DC hostname"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "run_kerberoast",
		Description: "Discover SPN-bound users via LDAP and request TGS tickets (hashcat -m 13100). Requires valid credentials.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in roastInput) (*mcp.CallToolResult, any, error) {
		dc := in.DC
		if dc == "" {
			dc = currentDC()
		}
		res, err := kerberos.RunKerberoast(dc)
		if err != nil {
			return errResult(err), nil, nil
		}
		return jsonResult(res), nil, nil
	})
}

// --- credentials -----------------------------------------------------------

func registerCredTools(s *mcp.Server) {
	type sprayInput struct {
		DC            string   `json:"dc,omitempty" jsonschema:"DC hostname"`
		Users         []string `json:"users,omitempty" jsonschema:"Usernames to try (or leave empty and use user_file)"`
		Passwords     []string `json:"passwords,omitempty" jsonschema:"Passwords to spray across users"`
		UserFile      string   `json:"user_file,omitempty" jsonschema:"Path to newline-delimited user list"`
		PasswordFile  string   `json:"password_file,omitempty" jsonschema:"Path to newline-delimited password list"`
		DelaySeconds  int      `json:"delay_seconds,omitempty" jsonschema:"Sleep between rounds to avoid lockouts"`
		StopOnSuccess bool     `json:"stop_on_success,omitempty" jsonschema:"Abort after first valid credential"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "run_password_spray",
		Description: "Low-and-slow LDAP-bind password spray: one password across all users, then sleep, next password. Hits are stored as valid credentials in the workspace.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in sprayInput) (*mcp.CallToolResult, any, error) {
		dc := in.DC
		if dc == "" {
			dc = currentDC()
		}
		res, err := password.RunSpray(password.SprayOptions{
			DC:            dc,
			Users:         in.Users,
			Passwords:     in.Passwords,
			UserFile:      in.UserFile,
			PasswordFile:  in.PasswordFile,
			DelayBetween:  time.Duration(in.DelaySeconds) * time.Second,
			StopOnSuccess: in.StopOnSuccess,
		})
		if err != nil {
			return errResult(err), nil, nil
		}
		return jsonResult(res), nil, nil
	})
}

// --- ADCS ------------------------------------------------------------------

func registerADCSTools(s *mcp.Server) {
	type adcsInput struct {
		DC string `json:"dc,omitempty" jsonschema:"DC hostname"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "run_adcs_enum",
		Description: "Enumerate Enterprise CAs + published certificate templates. Flags ESC1/ESC2 signal based on template flags.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in adcsInput) (*mcp.CallToolResult, any, error) {
		dc := in.DC
		if dc == "" {
			dc = currentDC()
		}
		res, err := adcs.RunEnum(dc)
		if err != nil {
			return errResult(err), nil, nil
		}
		return jsonResult(res), nil, nil
	})
}

// --- vulns -----------------------------------------------------------------

func registerVulnTools(s *mcp.Server) {
	type vulnInput struct {
		DC string `json:"dc,omitempty" jsonschema:"DC hostname"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "run_vuln_scan",
		Description: "Read-only LDAP-driven vuln sweep: MachineAccountQuota, RBCD, AS-REP roastables, stale DC OS versions.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in vulnInput) (*mcp.CallToolResult, any, error) {
		dc := in.DC
		if dc == "" {
			dc = currentDC()
		}
		res, err := vulns.Run(dc)
		if err != nil {
			return errResult(err), nil, nil
		}
		return jsonResult(res), nil, nil
	})
}

// --- BloodHound ------------------------------------------------------------

func registerBloodHoundTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "ingest_bloodhound",
		Description: "Push the current workspace bundle (domains, DCs, users, trusts, SPNs, roasted accounts) into the configured Neo4j instance.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		if err := bloodhound.IngestToBloodHound(); err != nil {
			return errResult(err), nil, nil
		}
		return textResult("ingested into BloodHound"), nil, nil
	})
}

// --- workspace -------------------------------------------------------------

func registerWorkspaceTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_results",
		Description: "Return the complete current recon bundle as JSON.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		return jsonResult(workspace.Snapshot()), nil, nil
	})

	type moduleInput struct {
		Module string `json:"module" jsonschema:"Module name (e.g. adcs, trusts, spray)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_module_output",
		Description: "Return the most recent output for a single module (see .Modules map in get_results).",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in moduleInput) (*mcp.CallToolResult, any, error) {
		snap := workspace.Snapshot()
		v, ok := snap.Modules[in.Module]
		if !ok {
			return errResult(fmt.Errorf("no output for module %q", in.Module)), nil, nil
		}
		return jsonResult(v), nil, nil
	})
}
