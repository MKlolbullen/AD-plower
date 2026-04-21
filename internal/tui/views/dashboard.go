package views

import (
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/table"
	"github.com/MKlolbullen/AD-plower/internal/tui"
	"github.com/MKlolbullen/AD-plower/internal/workspace"
)

type Dashboard struct {
	table table.Model
}

func NewDashboard() Dashboard {
	workspace.LoadResults()
	columns := []table.Column{
		{Title: "Category", Width: 20},
		{Title: "Value", Width: 55},
	}
	rows := []table.Row{
		{"DCs", fmt.Sprintf("%v", workspace.CurrentResults.DCs)},
		{"SMB Shares", fmt.Sprintf("%d", len(workspace.CurrentResults.SMBShares))},
		{"BloodHound", "✅ Ingested"},
	}
	t := table.New(table.WithColumns(columns), table.WithRows(rows), table.WithFocused(true))
	return Dashboard{table: t}
}

func (d Dashboard) Init() tea.Cmd { return nil }

func (d Dashboard) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	d.table, cmd = d.table.Update(msg)
	if msg, ok := msg.(tea.KeyMsg); ok && msg.Type == tea.KeyEsc {
		return d, tea.Quit
	}
	return d, cmd
}

func (d Dashboard) View() string {
	return tui.TitleStyle.Render("AD-PLOWER DASHBOARD") + "\n\n" + d.table.View() + "\n\n" + tui.ModeStyle.Render("Esc to exit")
}
