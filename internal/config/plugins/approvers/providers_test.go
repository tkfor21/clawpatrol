package approvers

// The approver resolves model families through the agent provider
// registry. Importing plugins/all here would be an import cycle (all
// imports approvers), so register just the providers these tests use.
import (
	_ "github.com/denoland/clawpatrol/internal/config/plugins/agents/claude"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/agents/openaisdk"
)
