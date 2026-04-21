# AD-Plower

**AD-Plower** — Faster, meaner Active Directory pentesting framework rewritten in Go.

Native speed. Modern TUI + planned Wails GUI. Full Claude MCP for autonomous agentic attacks. Direct BloodHound CE integration.

## GUI Preview

![AD-Plower Target Configuration](https://github.com/MKlolbullen/AD-plower/raw/main/assets/image.jpg)
*Target Configuration Screen*

![AD-Plower Live Recon Dashboard](https://github.com/MKlolbullen/AD-plower/raw/main/assets/image-2.jpg)
*Live Recon Dashboard*

![AD-Plower BloodHound Integration](https://github.com/MKlolbullen/AD-plower/raw/main/assets/image-3.jpg)
*BloodHound Integration View*

## Features

- **Unauth Recon**: DNS SRV, anonymous LDAP, SMB null sessions
- **Kerberos Attacks**: AS-REP roasting
- **Password Attacks**: Password spraying
- **BloodHound CE**: Automatic graph ingestion
- **Claude MCP**: Full agentic control via Model Context Protocol
- **TUI**: Bubble Tea interface with target config + live dashboard
- **Workspace**: Auto evidence + JSON export

## Quick Start

```bash
git clone https://github.com/MKlolbullen/AD-plower.git
cd AD-plower
go mod tidy
