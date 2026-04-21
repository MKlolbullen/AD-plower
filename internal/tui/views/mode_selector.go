package views

import (
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/list"
	"github.com/MKlolbullen/AD-plower/internal/modules/unauth"
	"github.com/MKlolbullen/AD-plower/internal/tui"
)

type ModeSelector struct {
	list list.Model
}

type listItem struct{ title, desc string }

func (i listItem) Title() string       { return i.title }
func (i listItem) Description() string { return i.desc }
func (i listItem) FilterValue() string { return i.title }

func NewModeSelector() ModeSelector {
	items := []list.Item{
		listItem{title: "Auto", desc: "Full autonomous recon + exploitation"},
		listItem{title: "Semi", desc: "Guided with your approval at each step"},
		listItem{title: "Manual", desc: "Pick your own modules"},
	}
	l := list.New(items, list.NewDefaultDelegate(), 70, 15)
	l.Title = "AD-Plower - Choose your poison"
	return ModeSelector{list: l}
}

func (m ModeSelector) Init() tea.Cmd { return nil }

func (m ModeSelector) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)

	if msg, ok := msg.(tea.KeyMsg); ok && msg.Type == tea.KeyEnter {
		selected := m.list.SelectedItem().(listItem).title
		fmt.Printf(tui.SuccessStyle.Render("→ Launching ") + selected + " mode\n")

		unauth.RunUnauthRecon()
		return m, tea.Quit
	}
	return m, cmd
}

func (m ModeSelector) View() string {
	return tui.TitleStyle.Render("AD-PLOWER") + "\n\n" + m.list.View()
}
