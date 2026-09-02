// Package kubeupgradecheck exists only to embed the catalog.
//
// go:embed cannot reach outside its own package directory, and the catalog belongs at the
// top of the repository where a contributor adding an add-on will actually look for it. So
// the embed lives here, at the root, and internal/catalog reads it through this variable.
package kubeupgradecheck

import "embed"

// CatalogFS is the rule catalog, shipped inside the binary so the tool needs no network and
// no extra files.
//
//go:embed all:catalog
var CatalogFS embed.FS
