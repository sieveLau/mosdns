//go:build !windows
// +build !windows

package coremain

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

// ListenTCPWithFreebind creates a TCP listener with the IP_FREEBIND option set.
func ListenTCPWithFreebind(address string, freebind bool) (net.Listener, error) {
	// Resolve the address, automatically handles both IPv4 and IPv6
	tcpAddr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address: %v", err)
	}

	var afinet int
	var addr syscall.Sockaddr
	if tcpAddr.IP.To4() != nil {
		afinet = syscall.AF_INET

		// Construct the IPv4 sockaddr
		sa := &syscall.SockaddrInet4{Port: tcpAddr.Port}
		copy(sa.Addr[:], tcpAddr.IP.To4())
		addr = sa
	} else {
		afinet = syscall.AF_INET6

		// Construct the IPv6 sockaddr
		sa := &syscall.SockaddrInet6{Port: tcpAddr.Port}
		copy(sa.Addr[:], tcpAddr.IP.To16())
		addr = sa
	}

	// Create the TCP socket
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
	// Resolve the address, automatically handles both IPv4 and IPv6
	udpAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address: %v", err)
	}

	// Determine if the address is IPv4 or IPv6
	var afinet int
	var addr syscall.Sockaddr
	if udpAddr.IP.To4() != nil {
		afinet = syscall.AF_INET

		// Construct the IPv4 sockaddr
		sa := &syscall.SockaddrInet4{Port: udpAddr.Port}
		copy(sa.Addr[:], udpAddr.IP.To4())
		addr = sa
	} else {
		afinet = syscall.AF_INET6

		// Construct the IPv6 sockaddr
		sa := &syscall.SockaddrInet6{Port: udpAddr.Port}
		copy(sa.Addr[:], udpAddr.IP.To16())
		addr = sa
	}

	// Create the UDP socket
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
