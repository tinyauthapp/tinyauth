package assets

import (
	"embed"
)

// Frontend
//
//go:embed dist
var FrontendAssets embed.FS

// Migrations
//
//go:embed migrations/sqlite/*.sql
var Migrations embed.FS
