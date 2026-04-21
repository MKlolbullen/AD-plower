package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

// Config holds all runtime configuration for AD-Plower. Values can come from
// config.yaml, env vars (prefix ADPOWER_), TUI input, or MCP tool calls.
type Config struct {
	// Target
	Domain   string `mapstructure:"domain"`
	Target   string `mapstructure:"target"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	NTHash   string `mapstructure:"nt_hash"`

	// DC / KDC
	DC         string `mapstructure:"dc"`
	KDC        string `mapstructure:"kdc"`
	DNSServer  string `mapstructure:"dns_server"`

	// Workspace
	Workspace string `mapstructure:"workspace"`

	// BloodHound / Neo4j
	BHNeo4jURI  string `mapstructure:"bh_neo4j_uri"`
	BHNeo4jUser string `mapstructure:"bh_neo4j_user"`
	BHNeo4jPass string `mapstructure:"bh_neo4j_pass"`
	BHCEEnabled bool   `mapstructure:"bh_ce_enabled"`

	// Tuning
	Threads     int `mapstructure:"threads"`
	TimeoutSecs int `mapstructure:"timeout_secs"`

	// Wordlists / input files
	UserList     string `mapstructure:"user_list"`
	PasswordList string `mapstructure:"password_list"`
}

var Cfg Config

func Load() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("$HOME/.adplower")
	viper.SetEnvPrefix("ADPOWER")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		fmt.Fprintln(os.Stderr, "No config.yaml found, using defaults + env")
	}
	if err := viper.Unmarshal(&Cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Config error: %v\n", err)
	}
	ApplyDefaults()
}

// ApplyDefaults fills in sane defaults for any unset fields. Safe to call
// multiple times; callers (TUI / MCP) invoke it after mutating fields.
func ApplyDefaults() {
	if Cfg.BHNeo4jURI == "" {
		Cfg.BHNeo4jURI = "bolt://localhost:7687"
	}
	if Cfg.BHNeo4jUser == "" {
		Cfg.BHNeo4jUser = "neo4j"
	}
	if Cfg.Threads == 0 {
		Cfg.Threads = 10
	}
	if Cfg.TimeoutSecs == 0 {
		Cfg.TimeoutSecs = 10
	}
	ws := Cfg.Workspace
	if ws == "" {
		home, _ := os.UserHomeDir()
		dom := Cfg.Domain
		if dom == "" {
			dom = "default"
		}
		ws = filepath.Join(home, ".adplower", dom)
	}
	Cfg.Workspace = ws
	_ = os.MkdirAll(ws, 0o755)
}
