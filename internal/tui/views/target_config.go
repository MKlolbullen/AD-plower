package views

import (
	"fmt"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/MKlolbullen/AD-plower/internal/config"
	"github.com/MKlolbullen/AD-plower/internal/tui"
)

type TargetConfig struct {
	inputs  []textinput.Model
	focused int
	done    bool
}

func NewTargetConfig() TargetConfig {
	inputs := make([]textinput.Model, 4)
	for i := range inputs {
		inputs[i] = textinput.New()
		inputs[i].Prompt = "→ "
		inputs[i].CharLimit = 100
	}
	inputs[0].Placeholder = "Domain (e.g. lab.local)"
	inputs[1].Placeholder = "Target IP/range (e.g. 192.168.1.10 or 192.168.1.0/24)"
	inputs[2].Placeholder = "Username (optional)"
	inputs[3].Placeholder = "Password (optional)"

	inputs[0].Focus()
	return TargetConfig{inputs: inputs}
}

func (m TargetConfig) Init() tea.Cmd { return textinput.Blink }

func (m TargetConfig) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			return m, tea.Quit
		case "tab", "shift+tab":
			m.focused = (m.focused + 1) % len(m.inputs)
			for i := range m.inputs {
				m.inputs[i].Blur()
			}
			m.inputs[m.focused].Focus()
			return m, nil
		case "enter":
			if m.focused == len(m.inputs)-1 {
				config.Cfg.Domain = m.inputs[0].Value()
				config.Cfg.Target = m.inputs[1].Value()
				config.Cfg.Username = m.inputs[2].Value()
				config.Cfg.Password = m.inputs[3].Value()
				m.done = true
				return m, tea.Quit
			}
			m.focused++
			for i := range m.inputs {
				m.inputs[i].Blur()
			}
			m.inputs[m.focused].Focus()
		}
	}
	m.inputs[m.focused], cmd = m.inputs[m.focused].Update(msg)
	return m, cmd
}

func (m TargetConfig) View() string {
	s := tui.TitleStyle.Render("AD-PLOWER — TARGET CONFIG") + "\n\n"
	for i, input := range m.inputs {
		s += input.View() + "\n"
		if i == m.focused {
			s += tui.ModeStyle.Render("   ↑↓ Tab • Enter to next • Ctrl+C quit") + "\n"
		}
	}
	return s
}
