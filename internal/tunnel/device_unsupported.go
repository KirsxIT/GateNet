//go:build !linux

package tunnel

import (
	"errors"
	"net"
)

func Start(string, string, string, int) (net.IP, func() error, error) {
	return nil, nil, errors.New("WireGuard gateway mode is supported on Linux only")
}

func Reload(string, string, string) error {
	return errors.New("WireGuard gateway mode is supported on Linux only")
}
