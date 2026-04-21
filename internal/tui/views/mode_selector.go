package views

import (
	"fmt"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/MKlolbullen/AD-plower/internal/modules/adcs"
	"github.com/MKlolbullen/AD-plower/internal/modules/kerberos"
	"github.com/MKlolbullen/AD-plower/internal/modules/password"
	"github.com/MKlolbullen/AD-plower/internal/modules/trusts"
	"github.com/MKlolbullen/AD-plower/internal/modules/unauth"
	"github.com/MKlolbullen/AD-plower/internal/modules/vulns"
	"github.com/MKlolbullen/AD-plower/internal/tui/theme"
	"github.com/MKlolbullen/AD-plower/internal/workspace"
)

type ModeSelector struct {
	list   list.Model
	status string
	Done   bool
}

type listItem struct{ title, desc, id string }

func (i listItem) Title() string       { return i.title }
func (i listItem) Description() string { return i.desc }
func (i listItem) FilterValue() string { return i.title }

func NewModeSelector() ModeSelector {
	items := []list.Item{
		listItem{id: "auto", title: "Auto recon", desc: "DNS → LDAP → SMB → AS-REP → BloodHound"},
		listItem{id: "ldap", title: "LDAP enumeration", desc: "Anonymous + authed users/groups/computers/trusts"},
		listItem{id: "smb", title: "SMB null session", desc: "Signing check + share enumeration"},
		listItem{id: "asrep", title: "AS-REP roast", desc: "Users with DONT_REQUIRE_PREAUTH"},
		listItem{id: "kerberoast", title: "Kerberoast", desc: "SPN TGS requests — needs creds"},
		listItem{id: "spray", title: "Password spray", desc: "Low-and-slow LDAP bind spray"},
		listItem{id: "adcs", title: "AD CS enum", desc: "Enrollment services + ESC1/ESC2 hints"},
		listItem{id: "trusts", title: "Trust enum", desc: "trustedDomain objects + notes"},
		listItem{id: "vulns", title: "Vuln sweep", desc: "MachineQuota, RBCD, roastables, stale OS"},
	}
	l := list.New(items, list.NewDefaultDelegate(), 70, 22)
	l.Title = "AD-Plower — pick a module"
	return ModeSelector{list: l}
}

func (m ModeSelector) Init() tea.Cmd { return nil }

func (m ModeSelector) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)

	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "esc", "ctrl+c":
			m.Done = true
			return m, tea.Quit
		case "enter":
			item := m.list.SelectedItem().(listItem)
			m.status = theme.Mode.Render("→ Launching ") + item.title
			go runModule(item.id)
		}
	}
	return m, cmd
}

func (m ModeSelector) View() string {
	s := theme.Title.Render("AD-PLOWER") + "\n\n" + m.list.View()
	if m.status != "" {
		s += "\n" + m.status + "\n"
	}
	return s
}

// runModule dispatches into the relevant module. Any output is written to the
// workspace; errors are surfaced via the dashboard.
func runModule(id string) {
	snap := workspace.Snapshot()
	dc := firstDC(snap)
	switch id {
	case "auto":
		_, _ = unauth.RunUnauthRecon()
	case "ldap":
		if dc != "" {
			_, _ = unauth.RunLDAPRecon(dc, snap.Domain)
		}
	case "smb":
		if dc != "" {
			_, _ = unauth.RunSMBNullSession(dc)
		}
	case "asrep":
		if dc != "" {
			_, _ = kerberos.RunASREPRoast(dc, snap.Users)
		}
	case "kerberoast":
		if dc != "" {
			_, _ = kerberos.RunKerberoast(dc)
		}
	case "spray":
		if dc != "" {
			_, _ = password.RunSpray(password.SprayOptions{DC: dc, Users: snap.Users})
		}
	case "adcs":
		if dc != "" {
			_, _ = adcs.RunEnum(dc)
		}
	case "trusts":
		if dc != "" {
			_, _ = trusts.RunEnum(dc)
		}
	case "vulns":
		if dc != "" {
			_, _ = vulns.Run(dc)
		}
	default:
		fmt.Printf("unknown module: %s\n", id)
	}
}

func firstDC(s workspace.ReconResults) string {
	if len(s.DCs) > 0 {
		return s.DCs[0]
	}
	return ""
}
