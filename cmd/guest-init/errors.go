//go:build linux

package main

import "errors"

var (
	ErrReadCmdline        = errors.New("read cmdline")
	ErrMissingDNS         = errors.New("missing matchlock.dns")
	ErrWriteResolvConf    = errors.New("write resolv.conf")
	ErrBringUpInterface   = errors.New("bring up interface")
	ErrStartGuestFused    = errors.New("start guest-fused")
	ErrWorkspaceMount     = errors.New("check workspace mount")
	ErrWorkspaceMountWait = errors.New("workspace mount timeout")
	ErrExecGuestAgent     = errors.New("exec guest-agent")
)
