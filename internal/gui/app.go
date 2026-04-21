// Package gui implements the Wails binding layer for AD-Plower. Every method
// on App is reflected as a Promise-returning function in the frontend
// (window.go.gui.App.<Name>). Keep the surface area small and well-typed:
// the frontend is the operator's dashboard, not a second CLI.
package gui

import (
	"context"
	"fmt"
	"time"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"

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

// App is the root Wails binding. A single instance is constructed in main.go
// and its Startup method is wired into options.App.OnStartup so the Wails
// runtime context is captured here — that context is required to emit
// frontend events.
type App struct {
	ctx context.Context
}

func New() *App { return &App{} }

// Startup is invoked by Wails once the window is ready. We hold onto the
// context so module runners can emit log / updated events back to the UI.
func (a *App) Startup(ctx context.Context) {
	a.ctx = ctx
	config.Load()
	config.ApplyDefaults()
	workspace.LoadResults()
	a.log("gui", "AD-Plower GUI ready")
}

// --- helpers ---------------------------------------------------------------

func (a *App) log(scope, msg string) {
	if a.ctx == nil {
		return
	}
	wruntime.EventsEmit(a.ctx, "log", LogEvent{
		Time:  time.Now().UTC().Format(time.RFC3339),
		Scope: scope,
		Msg:   msg,
	})
}

func (a *App) emitUpdated() {
	if a.ctx == nil {
		return
	}
	wruntime.EventsEmit(a.ctx, "results:updated", workspace.Snapshot())
}

// LogEvent is the payload format for the "log" runtime event.
type LogEvent struct {
	Time  string `json:"time"`
	Scope string `json:"scope"`
	Msg   string `json:"msg"`
}

// TargetInput mirrors the set_target MCP tool. Every field is optional so the
// frontend can partially update configuration as the operator types.
type TargetInput struct {
	Domain      string `json:"domain"`
	Target      string `json:"target"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	NTHash      string `json:"ntHash"`
	DC          string `json:"dc"`
	DNSServer   string `json:"dnsServer"`
	Workspace   string `json:"workspace"`
	BHNeo4jURI  string `json:"bhNeo4jUri"`
	BHNeo4jUser string `json:"bhNeo4jUser"`
	BHNeo4jPass string `json:"bhNeo4jPass"`
	BHCEEnabled *bool  `json:"bhCeEnabled"`
	Threads     int    `json:"threads"`
}

// --- configuration ---------------------------------------------------------

func (a *App) SetTarget(in TargetInput) map[string]any {
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
	a.log("config", fmt.Sprintf("target updated: domain=%q dc=%q user=%q", config.Cfg.Domain, config.Cfg.DC, config.Cfg.Username))
	return a.GetConfig()
}

// GetConfig returns the currently active configuration with secrets redacted.
func (a *App) GetConfig() map[string]any {
	return map[string]any{
		"domain":      config.Cfg.Domain,
		"target":      config.Cfg.Target,
		"username":    config.Cfg.Username,
		"password":    maskSet(config.Cfg.Password),
		"ntHash":      maskSet(config.Cfg.NTHash),
		"dc":          config.Cfg.DC,
		"dnsServer":   config.Cfg.DNSServer,
		"workspace":   config.Cfg.Workspace,
		"bhNeo4jUri":  config.Cfg.BHNeo4jURI,
		"bhNeo4jUser": config.Cfg.BHNeo4jUser,
		"bhCeEnabled": config.Cfg.BHCEEnabled,
		"threads":     config.Cfg.Threads,
	}
}

func maskSet(s string) string {
	if s == "" {
		return ""
	}
	return "***"
}

// --- module runners --------------------------------------------------------

// FirstDC returns a best-effort DC target: a discovered DC first, then the
// explicit DC from config, then the freeform Target field.
func (a *App) FirstDC() string {
	if snap := workspace.Snapshot(); len(snap.DCs) > 0 {
		return snap.DCs[0]
	}
	if config.Cfg.DC != "" {
		return config.Cfg.DC
	}
	return config.Cfg.Target
}

func (a *App) RunUnauthRecon() (*unauth.Summary, error) {
	a.log("unauth", "running full zero-cred recon")
	sum, err := unauth.RunUnauthRecon()
	a.emitUpdated()
	if err != nil && sum == nil {
		a.log("unauth", "error: "+err.Error())
		return nil, err
	}
	a.log("unauth", fmt.Sprintf("done: dcs=%d asrep=%d errors=%d", len(sum.DNS.DCs), sum.ASREP, len(sum.Errors)))
	return sum, nil
}

func (a *App) RunDNSRecon() (*unauth.DNSResult, error) {
	a.log("dns", "resolving SRV records")
	res, err := unauth.RunDNSRecon(config.Cfg.Domain)
	if err != nil && res == nil {
		a.log("dns", "error: "+err.Error())
		return nil, err
	}
	workspace.Patch(func(r *workspace.ReconResults) { r.DCs = res.DCs })
	a.emitUpdated()
	a.log("dns", fmt.Sprintf("dcs=%v", res.DCs))
	return res, nil
}

func (a *App) RunLDAPEnum(dc string) (*unauth.LDAPResult, error) {
	if dc == "" {
		dc = a.FirstDC()
	}
	a.log("ldap", "enumerating @ "+dc)
	res, err := unauth.RunLDAPRecon(dc, config.Cfg.Domain)
	a.emitUpdated()
	if err != nil {
		a.log("ldap", "error: "+err.Error())
		return nil, err
	}
	a.log("ldap", fmt.Sprintf("users=%d computers=%d trusts=%d", len(res.Users), len(res.Computers), len(res.Trusts)))
	return res, nil
}

type SMBEnumArgs struct {
	Host          string `json:"host"`
	Authenticated bool   `json:"authenticated"`
}

func (a *App) RunSMBEnum(args SMBEnumArgs) (*unauth.SMBResult, error) {
	host := args.Host
	if host == "" {
		host = a.FirstDC()
	}
	a.log("smb", "enumerating @ "+host)
	var (
		res *unauth.SMBResult
		err error
	)
	if args.Authenticated {
		res, err = unauth.RunSMBAuthed(host)
	} else {
		res, err = unauth.RunSMBNullSession(host)
	}
	a.emitUpdated()
	if err != nil {
		a.log("smb", "error: "+err.Error())
		return nil, err
	}
	a.log("smb", fmt.Sprintf("signing=%v shares=%d", res.SigningReq, len(res.Shares)))
	return res, nil
}

type RIDArgs struct {
	DC    string `json:"dc"`
	Start int    `json:"start"`
	End   int    `json:"end"`
}

func (a *App) RunRIDBrute(args RIDArgs) (*unauth.RIDResult, error) {
	dc := args.DC
	if dc == "" {
		dc = a.FirstDC()
	}
	a.log("ridbrute", fmt.Sprintf("cycling RIDs %d..%d on %s", args.Start, args.End, dc))
	res, err := unauth.RunRIDBrute(dc, args.Start, args.End)
	a.emitUpdated()
	if err != nil && res == nil {
		a.log("ridbrute", "error: "+err.Error())
		return nil, err
	}
	a.log("ridbrute", fmt.Sprintf("resolved=%d errors=%d", len(res.Names), len(res.Errors)))
	return res, nil
}

type ASREPArgs struct {
	DC    string   `json:"dc"`
	Users []string `json:"users"`
}

func (a *App) RunASREPRoast(args ASREPArgs) (*kerberos.ASREPResult, error) {
	dc := args.DC
	if dc == "" {
		dc = a.FirstDC()
	}
	users := args.Users
	if len(users) == 0 {
		users = workspace.Snapshot().Users
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("no users to roast — run LDAP enum first")
	}
	a.log("asrep", fmt.Sprintf("roasting %d candidates", len(users)))
	res, err := kerberos.RunASREPRoast(dc, users)
	a.emitUpdated()
	if err != nil {
		a.log("asrep", "error: "+err.Error())
		return nil, err
	}
	a.log("asrep", fmt.Sprintf("roastable=%d", len(res.Hashes)))
	return res, nil
}

func (a *App) RunKerberoast(dc string) (*kerberos.KerberoastResult, error) {
	if dc == "" {
		dc = a.FirstDC()
	}
	a.log("kerberoast", "requesting TGS for SPN users")
	res, err := kerberos.RunKerberoast(dc)
	a.emitUpdated()
	if err != nil {
		a.log("kerberoast", "error: "+err.Error())
		return nil, err
	}
	a.log("kerberoast", fmt.Sprintf("spns=%d hashes=%d", len(res.SPNs), len(res.Hashes)))
	return res, nil
}

type SprayArgs struct {
	DC            string   `json:"dc"`
	Users         []string `json:"users"`
	Passwords     []string `json:"passwords"`
	UserFile      string   `json:"userFile"`
	PasswordFile  string   `json:"passwordFile"`
	DelaySeconds  int      `json:"delaySeconds"`
	StopOnSuccess bool     `json:"stopOnSuccess"`
}

func (a *App) RunSpray(args SprayArgs) (*password.SprayResult, error) {
	dc := args.DC
	if dc == "" {
		dc = a.FirstDC()
	}
	a.log("spray", fmt.Sprintf("spraying %d users × %d passwords", len(args.Users), len(args.Passwords)))
	res, err := password.RunSpray(password.SprayOptions{
		DC:            dc,
		Users:         args.Users,
		Passwords:     args.Passwords,
		UserFile:      args.UserFile,
		PasswordFile:  args.PasswordFile,
		DelayBetween:  time.Duration(args.DelaySeconds) * time.Second,
		StopOnSuccess: args.StopOnSuccess,
	})
	a.emitUpdated()
	if err != nil {
		a.log("spray", "error: "+err.Error())
		return nil, err
	}
	a.log("spray", fmt.Sprintf("tested=%d hits=%d locked=%d", res.Tested, len(res.Found), len(res.Locked)))
	return res, nil
}

func (a *App) RunADCSEnum(dc string) ([]adcs.CA, error) {
	if dc == "" {
		dc = a.FirstDC()
	}
	a.log("adcs", "enumerating CAs + templates")
	res, err := adcs.RunEnum(dc)
	a.emitUpdated()
	if err != nil {
		a.log("adcs", "error: "+err.Error())
		return nil, err
	}
	a.log("adcs", fmt.Sprintf("cas=%d", len(res)))
	return res, nil
}

func (a *App) RunTrusts(dc string) ([]trusts.Trust, error) {
	if dc == "" {
		dc = a.FirstDC()
	}
	a.log("trusts", "enumerating trustedDomain objects")
	res, err := trusts.RunEnum(dc)
	a.emitUpdated()
	if err != nil {
		a.log("trusts", "error: "+err.Error())
		return nil, err
	}
	a.log("trusts", fmt.Sprintf("trusts=%d", len(res)))
	return res, nil
}

func (a *App) RunVulns(dc string) (*vulns.Report, error) {
	if dc == "" {
		dc = a.FirstDC()
	}
	a.log("vulns", "LDAP-driven vuln sweep")
	res, err := vulns.Run(dc)
	a.emitUpdated()
	if err != nil {
		a.log("vulns", "error: "+err.Error())
		return nil, err
	}
	a.log("vulns", fmt.Sprintf("findings=%d", len(res.Findings)))
	return res, nil
}

func (a *App) IngestBloodHound() error {
	a.log("bloodhound", "ingesting into Neo4j")
	if err := bloodhound.IngestToBloodHound(); err != nil {
		a.log("bloodhound", "error: "+err.Error())
		return err
	}
	a.log("bloodhound", "ok")
	return nil
}

// GetResults returns the live workspace snapshot. The frontend calls this on
// mount and in response to results:updated events.
func (a *App) GetResults() workspace.ReconResults {
	return workspace.Snapshot()
}
