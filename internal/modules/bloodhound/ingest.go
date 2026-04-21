package bloodhound

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/MKlolbullen/AD-plower/internal/config"
	"github.com/MKlolbullen/AD-plower/internal/workspace"
)

// IngestToBloodHound pushes the current workspace snapshot into Neo4j as a
// lightweight approximation of BloodHound CE's schema. The goal isn't to
// replace a collector — it's to have enough graph data to navigate from
// AD-Plower's own findings in BloodHound queries.
func IngestToBloodHound() error {
	if !config.Cfg.BHCEEnabled {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	driver, err := neo4j.NewDriverWithContext(config.Cfg.BHNeo4jURI, neo4j.BasicAuth(config.Cfg.BHNeo4jUser, config.Cfg.BHNeo4jPass, ""))
	if err != nil {
		return err
	}
	defer driver.Close(ctx)

	session := driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	snap := workspace.Snapshot()
	domain := strings.ToUpper(snap.Domain)

	// Domain root
	if _, err := session.Run(ctx, `MERGE (d:Domain {name:$d}) SET d.objectid=$d RETURN d`,
		map[string]any{"d": domain}); err != nil {
		return err
	}

	for _, dc := range snap.DCs {
		if _, err := session.Run(ctx, `
			MERGE (c:Computer {name:$name})
			SET c.domain=$domain, c.dc=true
			MERGE (d:Domain {name:$domain})
			MERGE (c)-[:MemberOf]->(d)`,
			map[string]any{"name": strings.ToUpper(dc), "domain": domain}); err != nil {
			return err
		}
	}
	for _, u := range snap.Users {
		if _, err := session.Run(ctx, `
			MERGE (u:User {name:$name})
			SET u.domain=$domain
			MERGE (d:Domain {name:$domain})
			MERGE (u)-[:MemberOf]->(d)`,
			map[string]any{"name": strings.ToUpper(u) + "@" + domain, "domain": domain}); err != nil {
			return err
		}
	}
	for _, c := range snap.Computers {
		if _, err := session.Run(ctx, `
			MERGE (c:Computer {name:$name})
			SET c.domain=$domain
			MERGE (d:Domain {name:$domain})
			MERGE (c)-[:MemberOf]->(d)`,
			map[string]any{"name": strings.ToUpper(c), "domain": domain}); err != nil {
			return err
		}
	}
	for _, t := range snap.Trusts {
		partner := strings.ToUpper(t.Name)
		if partner == "" {
			continue
		}
		rel := "TrustedBy"
		// 1=inbound, 2=outbound, 3=bidirectional
		switch t.Direction {
		case 2:
			rel = "TrustsOutbound"
		case 3:
			rel = "TrustsBidirectional"
		}
		if _, err := session.Run(ctx, fmt.Sprintf(`
			MERGE (a:Domain {name:$a})
			MERGE (b:Domain {name:$b})
			MERGE (a)-[:%s]->(b)`, rel),
			map[string]any{"a": domain, "b": partner}); err != nil {
			return err
		}
	}
	for _, s := range snap.SPNs {
		if _, err := session.Run(ctx, `
			MERGE (u:User {name:$user})
			SET u.hasspn=true
			MERGE (s:SPN {name:$spn})
			MERGE (u)-[:HasSPN]->(s)`,
			map[string]any{"user": strings.ToUpper(s.User) + "@" + domain, "spn": s.SPN}); err != nil {
			return err
		}
	}
	for u := range snap.ASREPHashes {
		if _, err := session.Run(ctx, `
			MERGE (u:User {name:$user}) SET u.dontreqpreauth=true, u.roasted=true`,
			map[string]any{"user": strings.ToUpper(u) + "@" + domain}); err != nil {
			return err
		}
	}
	return nil
}
