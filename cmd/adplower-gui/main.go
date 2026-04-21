// adplower-gui is the Wails-based desktop front-end for AD-Plower.
//
// Build prerequisites:
//
//	go install github.com/wailsapp/wails/v2/cmd/wails@latest
//	(cd frontend && npm install && npm run build)
//
// From the project root, run `wails build` for a production binary or
// `wails dev` for a hot-reload development session. `go build` alone works
// too, provided the frontend has been built into frontend/dist first — the
// embed directive below requires at least a placeholder index.html, which is
// shipped in the repo.
package main

import (
	"embed"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"

	"github.com/MKlolbullen/AD-plower/internal/gui"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := gui.New()

	err := wails.Run(&options.App{
		Title:            "AD-Plower",
		Width:            1280,
		Height:           820,
		MinWidth:         900,
		MinHeight:        600,
		BackgroundColour: options.NewRGB(14, 16, 22),
		AssetServer:      &assetserver.Options{Assets: assets},
		OnStartup:        app.Startup,
		Bind:             []any{app},
	})
	if err != nil {
		panic(err)
	}
}
