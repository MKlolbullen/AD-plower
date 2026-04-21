package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/MKlolbullen/AD-plower/internal/tui/views"
)

type Model struct {
	targetConfig views.TargetConfig
	modeSelector views.ModeSelector
	dashboard    views.Dashboard
	state        string // "target" | "selector" | "dashboard"
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
		var cmd tea.Cmd
		m.targetConfig, cmd = m.targetConfig.Update(msg).(views.TargetConfig)
		if m.targetConfig.done {
			m.state = "selector"
			m.modeSelector = views.NewModeSelector()
			return m, nil
		}
		return m, cmd
	case "dashboard":
		return m.dashboard.Update(msg)
	default:
		return m.modeSelector.Update(msg)
	}
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
