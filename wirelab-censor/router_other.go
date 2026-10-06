//go:build !linux

package main

import (
	"errors"
	"net"
)

func route(_, _, _, _ string, _, _ *net.IPNet) error {
	return errors.New("router mode needs Linux packet sockets; on this system only -replay works")
}
