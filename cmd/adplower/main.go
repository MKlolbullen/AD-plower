package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/MKlolbullen/AD-plower/internal/config"
	"github.com/MKlolbullen/AD-plower/internal/tui"
)

var rootCmd = &cobra.Command{
	Use:   "adplower",
	Short: "AD-Plower - faster, meaner AD pentest tool",
}
var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Start MCP server for Claude (Model Context Protocol)",
	Run: func(cmd *cobra.Command, args []string) {
		config.Load()
		mcp.StartMCPServer()
	},
}

func init() {
	rootCmd.AddCommand(startCmd, mcpCmd)
}
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Launch TUI (auto/semi/manual)",
	Run: func(cmd *cobra.Command, args []string) {
		config.Load()
		tui.StartTUI()
	},
}

func init() {
	rootCmd.AddCommand(startCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
