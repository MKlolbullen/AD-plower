package views

import (
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/MKlolbullen/AD-plower/internal/config"
	"github.com/MKlolbullen/AD-plower/internal/tui/theme"
)

type TargetConfig struct {
	inputs  []textinput.Model
	focused int
	Done    bool
}

func NewTargetConfig() TargetConfig {
	inputs := make([]textinput.Model, 4)
	for i := range inputs {
		inputs[i] = textinput.New()
		inputs[i].Prompt = "→ "
		inputs[i].CharLimit = 200
	}
	inputs[0].Placeholder = "Domain (e.g. lab.local)"
	inputs[1].Placeholder = "Target IP / CIDR / DC hostname"
	inputs[2].Placeholder = "Username (optional)"
	inputs[3].Placeholder = "Password (optional)"
	inputs[3].EchoMode = textinput.EchoPassword
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
		case "tab", "shift+tab", "down", "up":
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
				config.ApplyDefaults()
				m.Done = true
				return m, nil
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
	s := theme.Title.Render("AD-PLOWER — TARGET CONFIG") + "\n\n"
	for i, input := range m.inputs {
		s += input.View() + "\n"
		if i == m.focused {
			s += theme.Mode.Render("   Tab/Shift+Tab • Enter advances • Esc quits") + "\n"
		}
	}
	return s
}
