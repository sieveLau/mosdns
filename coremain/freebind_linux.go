//go:build !windows
// +build !windows

package coremain

import (
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
)

// ListenTCPWithFreebind creates a TCP listener with the IP_FREEBIND option set.
func ListenTCPWithFreebind(address string, freebind bool) (net.Listener, error) {
	var afinet int
	var addr syscall.Sockaddr

	// Determine if the address is IPv4 or IPv6
	ip := net.ParseIP(strings.Split(address, ":")[0])
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", address)
	}

	// Select IPv4 or IPv6 socket type based on parsed IP
	if ip.To4() != nil {
		afinet = syscall.AF_INET

		// Resolve the address to sockaddr for IPv4
		tcpAddr, err := net.ResolveTCPAddr("tcp4", address)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve address: %v", err)
		}

		// Construct the IPv4 sockaddr
		sa := &syscall.SockaddrInet4{Port: tcpAddr.Port}
		copy(sa.Addr[:], tcpAddr.IP.To4())
		addr = sa

	} else {
		afinet = syscall.AF_INET6

		// Resolve the address to sockaddr for IPv6
		tcpAddr, err := net.ResolveTCPAddr("tcp6", address)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve address: %v", err)
		}

		// Construct the IPv6 sockaddr
		sa := &syscall.SockaddrInet6{Port: tcpAddr.Port}
		copy(sa.Addr[:], tcpAddr.IP.To16())
		addr = sa
	}

	// Create TCP socket
	fd, err := syscall.Socket(afinet, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create socket: %v", err)
	}

	// Set the IP_FREEBIND option
	if freebind {
		if err := syscall.SetsockoptInt(fd, syscall.SOL_IP, syscall.IP_FREEBIND, 1); err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("failed to set IP_FREEBIND: %v", err)
		}
	}

	// Bind the socket
	if err := syscall.Bind(fd, addr); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to bind socket: %v", err)
	}

	// Listen on the socket
	if err := syscall.Listen(fd, syscall.SOMAXCONN); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to listen on socket: %v", err)
	}

	// Convert the file descriptor to net.Listener
	file := os.NewFile(uintptr(fd), "")
	listener, err := net.FileListener(file)
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to convert socket to listener: %v", err)
	}

	return listener, nil
}

// ListenUDPWithFreebind creates a UDP packet connection with the IP_FREEBIND option set.
func ListenUDPWithFreebind(address string, freebind bool) (net.PacketConn, error) {
	var afinet int
	var addr syscall.Sockaddr

	// Determine if the address is IPv4 or IPv6
	ip := net.ParseIP(strings.Split(address, ":")[0])
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", address)
	}

	// Select IPv4 or IPv6 socket type based on parsed IP
	if ip.To4() != nil {
		afinet = syscall.AF_INET

		// Resolve the address to sockaddr for IPv4
		udpAddr, err := net.ResolveUDPAddr("udp4", address)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve address: %v", err)
		}

		// Construct the IPv4 sockaddr
		sa := &syscall.SockaddrInet4{Port: udpAddr.Port}
		copy(sa.Addr[:], udpAddr.IP.To4())
		addr = sa

	} else {
		afinet = syscall.AF_INET6

		// Resolve the address to sockaddr for IPv6
		udpAddr, err := net.ResolveUDPAddr("udp6", address)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve address: %v", err)
		}

		// Construct the IPv6 sockaddr
		sa := &syscall.SockaddrInet6{Port: udpAddr.Port}
		copy(sa.Addr[:], udpAddr.IP.To16())
		addr = sa
	}

	// Create UDP socket
	fd, err := syscall.Socket(afinet, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create socket: %v", err)
	}

	// Set the IP_FREEBIND option
	if freebind {
		if err := syscall.SetsockoptInt(fd, syscall.SOL_IP, syscall.IP_FREEBIND, 1); err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("failed to set IP_FREEBIND: %v", err)
		}
	}

	// Bind the socket
	if err := syscall.Bind(fd, addr); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to bind socket: %v", err)
	}

	// Convert the file descriptor to net.PacketConn
	file := os.NewFile(uintptr(fd), "")
	packetConn, err := net.FilePacketConn(file)
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to convert socket to packet connection: %v", err)
	}

	return packetConn, nil
}