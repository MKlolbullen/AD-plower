package tui

import (
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/MKlolbullen/AD-plower/internal/tui/views"
)

type Model struct {
	modeSelector views.ModeSelector
	dashboard    views.Dashboard
	state        string // "selector" or "dashboard"
}

func InitialModel() Model {
	return Model{
		modeSelector: views.NewModeSelector(),
		state:        "selector",
	}
}

func (m Model) Init() tea.Cmd { return nil }

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.state == "dashboard" {
		return m.dashboard.Update(msg)
	}
	return m.modeSelector.Update(msg)
}

func (m Model) View() string {
	if m.state == "dashboard" {
		return m.dashboard.View()
	}
	return m.modeSelector.View()
}

func StartTUI() {
	p := tea.NewProgram(InitialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("TUI error: %v\n", err)
	}
}
