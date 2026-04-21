package theme

import "github.com/charmbracelet/lipgloss"

var (
	Title   = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF00FF")).Bold(true)
	Mode    = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FFFF")).Bold(true)
	Success = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00"))
	Error   = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000"))
	Warn    = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFAA00"))
	Muted   = lipgloss.NewStyle().Foreground(lipgloss.Color("#888888"))
)
