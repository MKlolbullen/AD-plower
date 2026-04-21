package bloodhound

import (
	"context"
	"fmt"
	"github.com/MKlolbullen/AD-plower/internal/config"
	"github.com/MKlolbullen/AD-plower/internal/workspace"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func IngestToBloodHound() error {
	if !config.Cfg.BHCEEnabled {
		return nil
	}
	driver, err := neo4j.NewDriver(config.Cfg.BHNeo4jURI, neo4j.BasicAuth(config.Cfg.BHNeo4jUser, config.Cfg.BHNeo4jPass, ""))
	if err != nil {
		return err
	}
	defer driver.Close(context.Background())

	session := driver.NewSession(context.Background(), neo4j.SessionConfig{})
	defer session.Close(context.Background())

	results := workspace.CurrentResults
	for _, dc := range results.DCs {
		_, _ = session.Run(`
			MERGE (d:Domain {name: $domain})
			MERGE (c:Computer {name: $dc})
			MERGE (c)-[:MemberOf]->(d)
		`, map[string]any{"domain": config.Cfg.Domain, "dc": dc})
	}
	fmt.Println("✅ BloodHound graph ingested")
	return nil
}
