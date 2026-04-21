package workspace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/MKlolbullen/AD-plower/internal/config"
)

// ReconResults is the aggregate evidence bundle emitted for a single target.
// Each module writes into its own field; the fully populated struct is what
// BloodHound/Neo4j ingest and the TUI dashboard render from.
type ReconResults struct {
	Domain      string            `json:"domain"`
	DCs         []string          `json:"dcs"`
	Users       []string          `json:"users"`
	Groups      []string          `json:"groups"`
	Computers   []string          `json:"computers"`
	Trusts      []TrustInfo       `json:"trusts"`
	SPNs        []SPNInfo         `json:"spns"`
	SMBHosts    []SMBHost         `json:"smb_hosts"`
	ASREPHashes map[string]string `json:"asrep_hashes"`
	TGSHashes   map[string]string `json:"tgs_hashes"`
	ValidCreds  []Cred            `json:"valid_creds"`
	ADCSCAs     []ADCSEntry       `json:"adcs_cas"`
	Vulns       []VulnFinding     `json:"vulns"`
	Modules     map[string]any    `json:"modules"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

type TrustInfo struct {
	Name      string `json:"name"`
	Direction int    `json:"direction"`
	Type      int    `json:"type"`
	Attrs     int    `json:"attrs"`
}

type SPNInfo struct {
	User string `json:"user"`
	SPN  string `json:"spn"`
}

type SMBHost struct {
	Host           string   `json:"host"`
	SigningReq     bool     `json:"signing_required"`
	NullSession    bool     `json:"null_session"`
	Shares         []string `json:"shares"`
	OSInfo         string   `json:"os"`
	DomainJoined   string   `json:"domain"`
}

type Cred struct {
	User     string `json:"user"`
	Password string `json:"password"`
	Hash     string `json:"hash"`
	Source   string `json:"source"`
}

type ADCSEntry struct {
	CAName    string   `json:"ca_name"`
	DNSName   string   `json:"dns_name"`
	Templates []string `json:"templates"`
}

type VulnFinding struct {
	Name       string `json:"name"`
	Target     string `json:"target"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	Notes      string `json:"notes"`
}

var (
	mu             sync.Mutex
	CurrentResults = ReconResults{Modules: map[string]any{}, ASREPHashes: map[string]string{}, TGSHashes: map[string]string{}}
)

// Save merges a module's structured output into the current results and
// persists the full bundle to disk atomically.
func Save(module string, data any) {
	mu.Lock()
	defer mu.Unlock()
	if CurrentResults.Modules == nil {
		CurrentResults.Modules = map[string]any{}
	}
	CurrentResults.Modules[module] = data
	CurrentResults.Domain = config.Cfg.Domain
	CurrentResults.UpdatedAt = time.Now()
	persistLocked()
}

// Patch applies a mutation to CurrentResults under the shared lock and
// persists. Use this when you need to append to typed slices rather than
// writing into the freeform Modules map.
func Patch(f func(r *ReconResults)) {
	mu.Lock()
	defer mu.Unlock()
	f(&CurrentResults)
	CurrentResults.UpdatedAt = time.Now()
	persistLocked()
}

func persistLocked() {
	if config.Cfg.Workspace == "" {
		return
	}
	b, err := json.MarshalIndent(CurrentResults, "", "  ")
	if err != nil {
		return
	}
	path := filepath.Join(config.Cfg.Workspace, "recon.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

// LoadResults reads the persisted bundle back into CurrentResults. Missing
// files are treated as a fresh start.
func LoadResults() {
	mu.Lock()
	defer mu.Unlock()
	path := filepath.Join(config.Cfg.Workspace, "recon.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	_ = json.Unmarshal(data, &CurrentResults)
	if CurrentResults.Modules == nil {
		CurrentResults.Modules = map[string]any{}
	}
	if CurrentResults.ASREPHashes == nil {
		CurrentResults.ASREPHashes = map[string]string{}
	}
	if CurrentResults.TGSHashes == nil {
		CurrentResults.TGSHashes = map[string]string{}
	}
}

// Snapshot returns a shallow copy of CurrentResults. Intended for
// tui/dashboards and MCP responses so callers don't hold the mutex.
func Snapshot() ReconResults {
	mu.Lock()
	defer mu.Unlock()
	return CurrentResults
}

// SaveRecon kept for backward compatibility with older call sites.
func SaveRecon(module string, data map[string]any) { Save(module, data) }
