//go:build windows

package main

// Windows has no direct O_NOFOLLOW equivalent at the open(2) layer; symlink
// semantics are different (Developer Mode required to create them, no
// world-writable /tmp by default). Symlink-attack defence is therefore
// less applicable here. Set to 0 so the open call still works; rely on
// O_EXCL alone to refuse pre-existing targets.
const oNoFollow = 0
