package tui

import "github.com/charmbracelet/lipgloss"

var (
	TitleStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF00FF")).Bold(true)
	ModeStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FFFF")).Bold(true)
	SuccessStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00"))
	ErrorStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000"))
)
