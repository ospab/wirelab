//go:build !linux

package main

import "log"

// The censor needs Linux packet sockets; on other systems only the rule
// engine builds, for its tests.
func main() { log.Fatal("wl-censor runs on Linux only") }
