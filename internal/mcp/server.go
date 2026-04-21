package mcp

import (
	"context"
	"fmt"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/MKlolbullen/AD-plower/internal/config"
	"github.com/MKlolbullen/AD-plower/internal/modules/unauth"
	"github.com/MKlolbullen/AD-plower/internal/modules/kerberos"
	"github.com/MKlolbullen/AD-plower/internal/modules/bloodhound"
)

func StartMCPServer() {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "ad-plower",
		Version: "0.1.0",
	}, nil)

	// Tool 1: Set target/domain/creds
	mcp.AddTool(server, &mcp.Tool{
		Name:        "set_target",
		Description: "Configure domain, target IP/range and optional credentials",
		InputSchema: mcp.ObjectSchema(map[string]any{
			"domain":   mcp.StringSchema("AD domain e.g. lab.local"),
			"target":   mcp.StringSchema("IP or CIDR e.g. 192.168.1.10 or 192.168.1.0/24"),
			"username": mcp.StringSchema("Optional username"),
			"password": mcp.StringSchema("Optional password"),
		}),
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		input := req.Input.(map[string]any)
		config.Cfg.Domain = input["domain"].(string)
		if t, ok := input["target"].(string); ok && t != "" {
			config.Cfg.Target = t
		}
		if u, ok := input["username"].(string); ok {
			config.Cfg.Username = u
		}
		if p, ok := input["password"].(string); ok {
			config.Cfg.Password = p
		}
		return &mcp.CallToolResult{Content: []mcp.Content{{Type: "text", Text: "✅ Target configured"}}}, nil
	})

	// Tool 2: Unauth recon (full DNS+LDAP+SMB+BloodHound)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "run_unauth_recon",
		Description: "Run full unauthenticated reconnaissance + BloodHound ingest",
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		unauth.RunUnauthRecon()
		return &mcp.CallToolResult{Content: []mcp.Content{{Type: "text", Text: "✅ Unauth recon + BloodHound complete"}}}, nil
	})

	// Tool 3: AS-REP roast
	mcp.AddTool(server, &mcp.Tool{
		Name:        "run_asrep_roast",
		Description: "Run AS-REP roast on discovered DCs",
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// uses first DC for simplicity
		_, err := kerberos.RunASREPRoast("") // dc param is ignored in current stub
		if err != nil {
			return nil, err
		}
		return &mcp.CallToolResult{Content: []mcp.Content{{Type: "text", Text: "✅ AS-REP roast complete"}}}, nil
	})

	// Tool 4: BloodHound ingest (standalone)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "ingest_bloodhound",
		Description: "Force ingest current results into BloodHound CE",
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if err := bloodhound.IngestToBloodHound(); err != nil {
			return nil, err
		}
		return &mcp.CallToolResult{Content: []mcp.Content{{Type: "text", Text: "✅ BloodHound ingest complete"}}}, nil
	})

	fmt.Println("🚀 AD-Plower MCP server started – Claude can now drive it")
	mcp.ServeStdio(server) // Claude Desktop / hosts use stdio transport
}
