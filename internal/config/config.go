package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

type Config struct {
	Domain      string `mapstructure:"domain"`
	Target      string `mapstructure:"target"`
	Username    string `mapstructure:"username"`
	Password    string `mapstructure:"password"`
	Workspace   string `mapstructure:"workspace"`
	BHNeo4jURI  string `mapstructure:"bh_neo4j_uri"`
	BHNeo4jUser string `mapstructure:"bh_neo4j_user"`
	BHNeo4jPass string `mapstructure:"bh_neo4j_pass"`
	BHCEEnabled bool   `mapstructure:"bh_ce_enabled"`
}

var Cfg Config

func Load() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.SetEnvPrefix("ADPOWER")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		fmt.Println("No config.yaml found, using defaults")
	}

	if err := viper.Unmarshal(&Cfg); err != nil {
		fmt.Printf("Config error: %v\n", err)
	}

	if Cfg.BHNeo4jURI == "" {
		Cfg.BHNeo4jURI = "bolt://localhost:7687"
	}
	if Cfg.Workspace == "" {
		Cfg.Workspace = filepath.Join(os.Getenv("HOME"), ".adplower", Cfg.Domain)
	}
	os.MkdirAll(Cfg.Workspace, 0755)
	fmt.Printf("✅ Workspace ready: %s\n", Cfg.Workspace)
}
