//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// prepareWholeMachineEnv prepares `clawpatrol run` on a --whole-machine
// device. There is no daemon, so the pushdown is fetched straight from
// the gateway (wholeMachineEnvVars).
func prepareWholeMachineEnv(cmd []string) error {
	return prepareAgentEnv(cmd, func() {
		if os.Getenv("CLAWPATROL_NO_ENV") != "1" {
			applyEnvPushdownVars(wholeMachineEnvVars(defaultClawpatrolDir()))
		}
	})
}

// prepareSudoUserEnv runs in the invoking user's process on the sudo
// path, before the env is captured for the root helper (DEV-16). It
// fetches the pushdown here, preferring the daemon's ENV command (the
// daemon is already up), so the shim sees the placeholders and writes
// its files as this user.
func prepareSudoUserEnv(cmd []string) error {
	return prepareAgentEnv(cmd, func() {
		vars, err := envPushdownVars(filepath.Join(defaultClawpatrolDir(), "ca.crt"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "[clawpatrol] env pushdown: %v (continuing without injected credentials)\n", err)
		}
		applyEnvPushdownVars(vars)
	})
}

// captureSudoUserEnv prepares the agent env in this (the invoking
// user's) process and returns it for the root helper (DEV-16). Taking
// the capture here, after prepareSudoUserEnv, makes "strip before
// capture" structural (R4-03).
func captureSudoUserEnv(cmd []string) ([]string, error) {
	if err := prepareSudoUserEnv(cmd); err != nil {
		return nil, err
	}
	return os.Environ(), nil
}
