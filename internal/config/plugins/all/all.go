// Package all blank-imports every built-in plugin so a single import
// from main / tests pulls the entire registry into the binary. Mirrors
// the Terraform provider blank-import pattern and lib/pq drivers.
package all

//go:generate go run ../../../tools/docgen -o ../../../../site/doc/config-reference.md

import (
	// Agent provider packages register their agentprovider.Provider in
	// init; the init below validates the whole registry.
	_ "github.com/denoland/clawpatrol/internal/config/plugins/agents/claude"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/agents/codex"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/agents/openaisdk"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/approvers" // register built-in plugin
	_ "github.com/denoland/clawpatrol/internal/config/plugins/credentials"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/endpoints"
	// Facet packages register their facet runtime only. The single
	// `rule` block plugin is registered by config/plugins/rules and
	// infers the family from each rule's endpoint set at validate
	// time.
	_ "github.com/denoland/clawpatrol/internal/config/plugins/facets/https"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/facets/k8s"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/facets/sql"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/facets/ssh"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/rules"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/tunnels"

	"github.com/denoland/clawpatrol/internal/agentprovider"
)

// Every import above has finished its init by the time this runs, so
// the whole registry (config plugins + agent providers) is populated.
// A declaration that breaks a security check stops the process here.
func init() { agentprovider.MustValidate() }
