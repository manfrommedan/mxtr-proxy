//go:build !windows

package main

import "syscall"

// oNoFollow is syscall.O_NOFOLLOW on POSIX systems where it exists. We use it
// to refuse to open a symlink at the target path of PSK/cloak/cert state
// files, defending against an attacker pre-creating a symlink to redirect
// our writes.
const oNoFollow = syscall.O_NOFOLLOW
