package views

import (
	"fmt"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/MKlolbullen/AD-plower/internal/tui/theme"
	"github.com/MKlolbullen/AD-plower/internal/workspace"
)

type Dashboard struct {
	table table.Model
}

func NewDashboard() Dashboard {
	workspace.LoadResults()
	snap := workspace.Snapshot()
	columns := []table.Column{
		{Title: "Category", Width: 22},
		{Title: "Value", Width: 55},
	}
	rows := []table.Row{
		{"Domain", snap.Domain},
		{"DCs", fmt.Sprintf("%d %v", len(snap.DCs), snap.DCs)},
		{"Users", fmt.Sprintf("%d", len(snap.Users))},
		{"Computers", fmt.Sprintf("%d", len(snap.Computers))},
		{"Groups", fmt.Sprintf("%d", len(snap.Groups))},
		{"Trusts", fmt.Sprintf("%d", len(snap.Trusts))},
		{"SMB hosts", fmt.Sprintf("%d", len(snap.SMBHosts))},
		{"ADCS CAs", fmt.Sprintf("%d", len(snap.ADCSCAs))},
		{"AS-REP hashes", fmt.Sprintf("%d", len(snap.ASREPHashes))},
		{"TGS hashes", fmt.Sprintf("%d", len(snap.TGSHashes))},
		{"Valid creds", fmt.Sprintf("%d", len(snap.ValidCreds))},
		{"Vuln findings", fmt.Sprintf("%d", len(snap.Vulns))},
	}
	t := table.New(table.WithColumns(columns), table.WithRows(rows), table.WithFocused(true), table.WithHeight(len(rows)+1))
	return Dashboard{table: t}
}

func (d Dashboard) Init() tea.Cmd { return nil }

func (d Dashboard) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	d.table, cmd = d.table.Update(msg)
	if msg, ok := msg.(tea.KeyMsg); ok {
		switch msg.String() {
		case "esc", "q", "ctrl+c":
			return d, tea.Quit
		}
	}
	return d, cmd
}

func (d Dashboard) View() string {
	return theme.Title.Render("AD-PLOWER DASHBOARD") + "\n\n" + d.table.View() + "\n\n" + theme.Mode.Render("q/esc to exit")
}
