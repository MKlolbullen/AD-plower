package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/MKlolbullen/AD-plower/internal/config"
	"github.com/MKlolbullen/AD-plower/internal/mcp"
	"github.com/MKlolbullen/AD-plower/internal/modules/adcs"
	"github.com/MKlolbullen/AD-plower/internal/modules/kerberos"
	"github.com/MKlolbullen/AD-plower/internal/modules/password"
	"github.com/MKlolbullen/AD-plower/internal/modules/trusts"
	"github.com/MKlolbullen/AD-plower/internal/modules/unauth"
	"github.com/MKlolbullen/AD-plower/internal/modules/vulns"
	"github.com/MKlolbullen/AD-plower/internal/tui"
	"github.com/MKlolbullen/AD-plower/internal/workspace"
)

var rootCmd = &cobra.Command{
	Use:   "adplower",
	Short: "AD-Plower — faster, meaner Active Directory pentesting framework",
	Long: `AD-Plower is a Go-based Active Directory pentesting framework.

Zero-credential → authed enumeration → roasting → BloodHound ingest, all
drivable from a Bubble Tea TUI, the command line, or an MCP host such as
Claude Desktop.`,
}

func addSharedFlags(c *cobra.Command) {
	c.PersistentFlags().StringVar(&config.Cfg.Domain, "domain", "", "AD domain (e.g. lab.local)")
	c.PersistentFlags().StringVar(&config.Cfg.Target, "target", "", "DC IP / hostname / CIDR")
	c.PersistentFlags().StringVar(&config.Cfg.Username, "user", "", "Username")
	c.PersistentFlags().StringVar(&config.Cfg.Password, "password", "", "Password")
	c.PersistentFlags().StringVar(&config.Cfg.NTHash, "nthash", "", "NT hash (hex)")
	c.PersistentFlags().StringVar(&config.Cfg.DC, "dc", "", "Explicit DC hostname")
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Launch the interactive TUI",
	RunE: func(cmd *cobra.Command, args []string) error {
		config.Load()
		config.ApplyDefaults()
		return tui.StartTUI()
	},
}

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Start the MCP server over stdio for Claude / other MCP hosts",
	RunE: func(cmd *cobra.Command, args []string) error {
		config.Load()
		config.ApplyDefaults()
		return mcp.StartMCPServer()
	},
}

var reconCmd = &cobra.Command{
	Use:   "recon",
	Short: "Run the full unauthenticated recon pass and print a summary",
	RunE: func(cmd *cobra.Command, args []string) error {
		config.Load()
		config.ApplyDefaults()
		sum, err := unauth.RunUnauthRecon()
		if err != nil && sum == nil {
			return err
		}
		fmt.Printf("domain=%s dcs=%v users=%d asrep=%d errors=%d\n",
			sum.Domain, sum.DNS.DCs, len(workspace.Snapshot().Users),
			sum.ASREP, len(sum.Errors))
		return nil
	},
}

var kerberoastCmd = &cobra.Command{
	Use:   "kerberoast",
	Short: "Authenticated SPN discovery + TGS requests",
	RunE: func(cmd *cobra.Command, args []string) error {
		config.Load()
		config.ApplyDefaults()
		res, err := kerberos.RunKerberoast(firstDCOrTarget())
		if err != nil {
			return err
		}
		fmt.Printf("spns=%d hashes=%d\n", len(res.SPNs), len(res.Hashes))
		return nil
	},
}

var asrepCmd = &cobra.Command{
	Use:   "asrep [user1,user2,...]",
	Short: "AS-REP roast the given users (or discovered roastables)",
	RunE: func(cmd *cobra.Command, args []string) error {
		config.Load()
		config.ApplyDefaults()
		var users []string
		if len(args) > 0 {
			users = strings.Split(args[0], ",")
		} else {
			users = workspace.Snapshot().Users
		}
		res, err := kerberos.RunASREPRoast(firstDCOrTarget(), users)
		if err != nil {
			return err
		}
		for u, h := range res.Hashes {
			fmt.Printf("%s %s\n", u, h)
		}
		return nil
	},
}

var sprayCmd = &cobra.Command{
	Use:   "spray",
	Short: "Password spray via authenticated LDAP bind",
	RunE: func(cmd *cobra.Command, args []string) error {
		config.Load()
		config.ApplyDefaults()
		res, err := password.RunSpray(password.SprayOptions{
			DC:           firstDCOrTarget(),
			UserFile:     config.Cfg.UserList,
			PasswordFile: config.Cfg.PasswordList,
		})
		if err != nil {
			return err
		}
		fmt.Printf("tested=%d hits=%d locked=%d\n", res.Tested, len(res.Found), len(res.Locked))
		for _, c := range res.Found {
			fmt.Printf("HIT %s:%s\n", c.User, c.Password)
		}
		return nil
	},
}

var adcsCmd = &cobra.Command{
	Use:   "adcs",
	Short: "Enumerate AD CS Enterprise CAs and templates",
	RunE: func(cmd *cobra.Command, args []string) error {
		config.Load()
		config.ApplyDefaults()
		cas, err := adcs.RunEnum(firstDCOrTarget())
		if err != nil {
			return err
		}
		for _, c := range cas {
			fmt.Printf("CA %s @ %s (%d templates)\n", c.Name, c.DNSName, len(c.Templates))
			for _, f := range c.Findings {
				if len(f.Escalation) > 0 {
					fmt.Printf("  %s → %v\n", f.Template, f.Escalation)
				}
			}
		}
		return nil
	},
}

var trustsCmd = &cobra.Command{
	Use:   "trusts",
	Short: "Enumerate trustedDomain objects",
	RunE: func(cmd *cobra.Command, args []string) error {
		config.Load()
		config.ApplyDefaults()
		res, err := trusts.RunEnum(firstDCOrTarget())
		if err != nil {
			return err
		}
		for _, t := range res {
			fmt.Printf("%s dir=%d type=%d attrs=0x%x notes=%v\n", t.Partner, t.Direction, t.Type, t.Attributes, t.Notes)
		}
		return nil
	},
}

var vulnsCmd = &cobra.Command{
	Use:   "vulns",
	Short: "Run the LDAP-driven vuln sweep",
	RunE: func(cmd *cobra.Command, args []string) error {
		config.Load()
		config.ApplyDefaults()
		rep, err := vulns.Run(firstDCOrTarget())
		if err != nil {
			return err
		}
		for _, f := range rep.Findings {
			fmt.Printf("[%s] %s @ %s — %s\n", f.Severity, f.Name, f.Target, f.Notes)
		}
		return nil
	},
}

func firstDCOrTarget() string {
	if snap := workspace.Snapshot(); len(snap.DCs) > 0 {
		return snap.DCs[0]
	}
	if config.Cfg.DC != "" {
		return config.Cfg.DC
	}
	return config.Cfg.Target
}

func init() {
	addSharedFlags(rootCmd)
	rootCmd.AddCommand(startCmd, mcpCmd, reconCmd, kerberoastCmd, asrepCmd, sprayCmd, adcsCmd, trustsCmd, vulnsCmd)
	sprayCmd.Flags().StringVar(&config.Cfg.UserList, "users", "", "Path to user list")
	sprayCmd.Flags().StringVar(&config.Cfg.PasswordList, "passwords", "", "Path to password list")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
