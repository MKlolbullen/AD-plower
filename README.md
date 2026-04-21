# AD-Plower

**AD-Plower** — faster, meaner Active Directory pentesting framework in Go,
inspired by [linWinPwn](https://github.com/lefayjey/linWinPwn). Native speed,
a Bubble Tea TUI, direct BloodHound CE ingest, and a first-class **Model
Context Protocol (MCP) server** so Claude (or any MCP host) can drive an
end-to-end engagement autonomously.

## GUI Preview

![AD-Plower Target Configuration](https://github.com/MKlolbullen/AD-plower/raw/main/assets/image.jpg)
*Target Configuration Screen*

![AD-Plower Live Recon Dashboard](https://github.com/MKlolbullen/AD-plower/raw/main/assets/image-2.jpg)
*Live Recon Dashboard*

![AD-Plower BloodHound Integration](https://github.com/MKlolbullen/AD-plower/raw/main/assets/image-3.jpg)
*BloodHound Integration View*

## Features

### Enumeration
- **DNS SRV recon** — locates DCs, KDCs and GCs (`_ldap._tcp.dc._msdcs`, `_kerberos._tcp`, `_gc._tcp`, ...)
- **LDAP enumeration** (anonymous + authenticated) — users, groups, computers,
  SPNs, trusts, `ms-DS-MachineAccountQuota`, AS-REP roastable and delegation-
  flagged accounts
- **SMB null session** + signing-required detection, SRVSVC `NetShareEnumAll`
  share enumeration
- **LSA RID brute force** — resolve RIDs to principal names via `\PIPE\lsarpc`
- **Trust enumeration** — `trustedDomain` objects, forest-transitive / quarantine detection

### Attacks
- **AS-REP roast** — hashcat-ready `-m 18200` hashes for users flagged with
  `DONT_REQUIRE_PREAUTH`
- **Kerberoasting** — LDAP SPN discovery + TGS requests, `-m 13100` hashcat output
- **Password spraying** — low-and-slow LDAP-bind spray with lockout-aware
  delays and `stop_on_success`

### Certificate Services
- **AD CS enumeration** — `pKIEnrollmentService` discovery, published
  templates, heuristic ESC1 / ESC2 classification

### Vulnerability sweep (read-only)
- MachineAccountQuota > 0 (noPac prerequisite)
- Resource-Based Constrained Delegation (`msDS-AllowedToActOnBehalfOfOtherIdentity`)
- AS-REP roastable users
- Stale DC OS versions — ZeroLogon / PrintNightmare / NoPac triage

### Integrations
- **BloodHound CE** — direct Neo4j ingest of domain / DC / user / trust /
  SPN / roasted-user nodes
- **Claude MCP** — every module registered as an MCP tool over stdio
- **TUI** — Bubble Tea target config + module picker + live dashboard
- **Workspace** — per-module JSON evidence and atomic persistence

## Install

```bash
git clone https://github.com/MKlolbullen/AD-plower.git
cd AD-plower
go mod tidy
go build -o adplower ./cmd/adplower
```

Requires Go 1.25+.

## CLI

```bash
./adplower start                           # Bubble Tea TUI
./adplower recon    --domain lab.local     # full unauth pass
./adplower asrep    --domain lab.local users,svc_sql
./adplower kerberoast --domain lab.local --user alice --password hunter2
./adplower spray    --domain lab.local --users ./users.txt --passwords ./pw.txt
./adplower adcs     --domain lab.local --user alice --password hunter2
./adplower trusts   --domain lab.local
./adplower vulns    --domain lab.local
./adplower mcp                             # MCP over stdio for Claude
```

Every subcommand accepts `--domain`, `--target`, `--user`, `--password`,
`--nthash`, `--dc`. Config can also live in `./config.yaml` or
`~/.adplower/config.yaml` — see `config.example.yaml`.

## Claude Desktop / MCP hosts

Register AD-Plower as a stdio MCP server. Example
`~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ad-plower": {
      "command": "/absolute/path/to/adplower",
      "args": ["mcp"],
      "env": {
        "ADPOWER_BH_CE_ENABLED": "true",
        "ADPOWER_BH_NEO4J_URI": "bolt://localhost:7687",
        "ADPOWER_BH_NEO4J_USER": "neo4j",
        "ADPOWER_BH_NEO4J_PASS": "bloodhoundcommunityedition"
      }
    }
  }
}
```

### Exposed MCP tools

| Tool                   | Purpose                                                            |
|------------------------|--------------------------------------------------------------------|
| `set_target`           | Configure domain / DC / creds / BloodHound                         |
| `get_config`           | Inspect the effective configuration (secrets redacted)             |
| `run_unauth_recon`     | DNS → anon LDAP → SMB null → AS-REP → BloodHound                   |
| `run_dns_recon`        | Resolve AD SRV records                                             |
| `run_ldap_enum`        | Users, groups, computers, SPNs, trusts, MachineAccountQuota        |
| `run_smb_enum`         | Null / authed SMB, signing check, share enum                       |
| `run_rid_bruteforce`   | LSA RID cycling via `\PIPE\lsarpc`                                 |
| `enum_trusts`          | trustedDomain objects with classification notes                    |
| `run_asrep_roast`      | AS-REP roast, hashcat `-m 18200`                                   |
| `run_kerberoast`       | SPN enum + TGS, hashcat `-m 13100`                                 |
| `run_password_spray`   | LDAP-bind spray with lockout-aware delay                           |
| `run_adcs_enum`        | Enterprise CA + template enum with ESC1/ESC2 signal                |
| `run_vuln_scan`        | MachineQuota / RBCD / roastable / stale DC sweep                   |
| `ingest_bloodhound`    | Push workspace to Neo4j                                            |
| `get_results`          | Full JSON evidence bundle                                          |
| `get_module_output`    | JSON for a single named module                                     |

A typical Claude-driven run looks like:

1. `set_target` → `{ "domain": "lab.local", "target": "10.0.0.10" }`
2. `run_unauth_recon`
3. Inspect `get_results`; if roastable users appear, run `run_asrep_roast`
4. If a valid credential is already available, `run_kerberoast` +
   `run_adcs_enum` + `run_vuln_scan`
5. `ingest_bloodhound` to let the operator pivot in BloodHound CE

## Workspace

Every module writes into `$workspace/recon.json` with atomic renames, and
each module's raw output lands under the `modules.<name>` sub-object so
evidence is preserved across runs.

## Safety

AD-Plower is built for authorized testing. It never exploits trust boundaries
that weren't explicitly requested, the vulnerability sweep is strictly
read-only, and the password spray defaults to one password per round with a
configurable delay. Always work within the scope of the engagement.

## License

See the repository root for licensing information.
