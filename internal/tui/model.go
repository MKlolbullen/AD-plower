package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/MKlolbullen/AD-plower/internal/tui/views"
)

// Model drives the top-level TUI state machine: target config → mode picker
// → live dashboard. Each view returns a Done flag so we can advance without
// leaking tea.Quit upwards.
type Model struct {
	targetConfig views.TargetConfig
	modeSelector views.ModeSelector
	dashboard    views.Dashboard
	state        string
}

func InitialModel() Model {
	return Model{
		targetConfig: views.NewTargetConfig(),
		state:        "target",
	}
}

func (m Model) Init() tea.Cmd { return m.targetConfig.Init() }

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m.state {
	case "target":
		updated, cmd := m.targetConfig.Update(msg)
		m.targetConfig = updated.(views.TargetConfig)
		if m.targetConfig.Done {
			m.state = "selector"
			m.modeSelector = views.NewModeSelector()
			return m, m.modeSelector.Init()
		}
		return m, cmd
	case "selector":
		updated, cmd := m.modeSelector.Update(msg)
		m.modeSelector = updated.(views.ModeSelector)
		if m.modeSelector.Done {
			m.state = "dashboard"
			m.dashboard = views.NewDashboard()
			return m, m.dashboard.Init()
		}
		return m, cmd
	case "dashboard":
		updated, cmd := m.dashboard.Update(msg)
		m.dashboard = updated.(views.Dashboard)
		return m, cmd
	}
	return m, nil
}

func (m Model) View() string {
	switch m.state {
	case "target":
		return m.targetConfig.View()
	case "dashboard":
		return m.dashboard.View()
	default:
		return m.modeSelector.View()
	}
}

// StartTUI runs the Bubble Tea program until the user quits. It's the entry
// point for `adplower start`.
func StartTUI() error {
	p := tea.NewProgram(InitialModel(), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
