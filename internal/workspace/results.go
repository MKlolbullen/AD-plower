package workspace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"github.com/MKlolbullen/AD-plower/internal/config"
)

type ReconResults struct {
	DCs       []string         `json:"dcs"`
	LDAP      map[string]any   `json:"ldap"`
	SMBShares []string         `json:"smb_shares"`
	Domain    string           `json:"domain"`
}

var CurrentResults ReconResults

func SaveRecon(module string, data map[string]any) {
	CurrentResults.DCs = append(CurrentResults.DCs, data["dns_dcs"].([]string)...)
	b, _ := json.MarshalIndent(CurrentResults, "", "  ")
	os.WriteFile(filepath.Join(config.Cfg.Workspace, "recon.json"), b, 0644)
}

func LoadResults() {
	data, _ := os.ReadFile(filepath.Join(config.Cfg.Workspace, "recon.json"))
	json.Unmarshal(data, &CurrentResults)
}
