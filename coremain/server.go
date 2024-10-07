/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package coremain

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/sieveLau/mosdns/v4-maintenance/pkg/server"
	"github.com/sieveLau/mosdns/v4-maintenance/pkg/server/dns_handler"
	"github.com/sieveLau/mosdns/v4-maintenance/pkg/server/http_handler"
	"go.uber.org/zap"
)

const defaultQueryTimeout = time.Second * 5
const (
	defaultIdleTimeout = time.Second * 10
)

func (m *Mosdns) startServers(cfg *ServerConfig) error {
	if len(cfg.Listeners) == 0 {
		return errors.New("no server listener is configured")
	}
	if len(cfg.Exec) == 0 {
		return errors.New("empty entry")
	}

	entry := m.execs[cfg.Exec]
	if entry == nil {
		return fmt.Errorf("cannot find entry %s", cfg.Exec)
	}

	queryTimeout := defaultQueryTimeout
	if cfg.Timeout > 0 {
		queryTimeout = time.Duration(cfg.Timeout) * time.Second
	}

	dnsHandlerOpts := dns_handler.EntryHandlerOpts{
		Logger:             m.logger,
		Entry:              entry,
		QueryTimeout:       queryTimeout,
		RecursionAvailable: true,
	}
	dnsHandler, err := dns_handler.NewEntryHandler(dnsHandlerOpts)
	if err != nil {
		return fmt.Errorf("failed to init entry handler, %w", err)
	}

	for _, lc := range cfg.Listeners {
		if err := m.startServerListener(lc, dnsHandler); err != nil {
			return err
		}
	}
	return nil
}

// ListenTCPWithFreebind creates a TCP listener with the IP_FREEBIND option set.
func ListenTCPWithFreebind(address string) (net.Listener, error) {
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
	if err := syscall.SetsockoptInt(fd, syscall.SOL_IP, syscall.IP_FREEBIND, 1); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to set IP_FREEBIND: %v", err)
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
func ListenUDPWithFreebind(address string) (net.PacketConn, error) {
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
	if err := syscall.SetsockoptInt(fd, syscall.SOL_IP, syscall.IP_FREEBIND, 1); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to set IP_FREEBIND: %v", err)
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

func (m *Mosdns) startServerListener(cfg *ServerListenerConfig, dnsHandler dns_handler.Handler) error {
	if len(cfg.Addr) == 0 {
		return errors.New("no address to bind")
	}

	m.logger.Info("starting server", zap.String("proto", cfg.Protocol), zap.String("addr", cfg.Addr))

	idleTimeout := defaultIdleTimeout
	if cfg.IdleTimeout > 0 {
		idleTimeout = time.Duration(cfg.IdleTimeout) * time.Second
	}

	httpOpts := http_handler.HandlerOpts{
		DNSHandler:  dnsHandler,
		Path:        cfg.URLPath,
		SrcIPHeader: cfg.GetUserIPFromHeader,
		Logger:      m.logger,
	}

	httpHandler, err := http_handler.NewHandler(httpOpts)
	if err != nil {
		return fmt.Errorf("failed to init http handler, %w", err)
	}

	opts := server.ServerOpts{
		DNSHandler:  dnsHandler,
		HttpHandler: httpHandler,
		Cert:        cfg.Cert,
		Key:         cfg.Key,
		IdleTimeout: idleTimeout,
		Logger:      m.logger,
	}
	s := server.NewServer(opts)

	// helper func for proxy protocol listener
	requirePP := func(_ net.Addr) (proxyproto.Policy, error) {
		return proxyproto.REQUIRE, nil
	}

	var run func() error
	switch cfg.Protocol {
	case "", "udp":
		var conn net.PacketConn
		var err error
		if cfg.IP_FREEBIND {
			conn, err = ListenUDPWithFreebind(cfg.Addr)
		} else {
			conn, err = net.ListenPacket("udp", cfg.Addr)
		}
		if err != nil {
			return err
		}
		run = func() error { return s.ServeUDP(conn) }
	case "tcp":
		var l net.Listener
		var err error
		if cfg.IP_FREEBIND {
			l, err = ListenTCPWithFreebind(cfg.Addr)
		} else {
			l, err = net.Listen("tcp", cfg.Addr)
		}
		if err != nil {
			return err
		}
		if cfg.ProxyProtocol {
			l = &proxyproto.Listener{Listener: l, Policy: requirePP}
		}
		run = func() error { return s.ServeTCP(l) }
	case "tls", "dot":
		var l net.Listener
		var err error
		if cfg.IP_FREEBIND {
			l, err = ListenTCPWithFreebind(cfg.Addr)
		} else {
			l, err = net.Listen("tcp", cfg.Addr)
		}
		if err != nil {
			return err
		}
		if cfg.ProxyProtocol {
			l = &proxyproto.Listener{Listener: l, Policy: requirePP}
		}
		run = func() error { return s.ServeTLS(l) }
	case "http":
		var l net.Listener
		var err error
		if cfg.IP_FREEBIND {
			l, err = ListenTCPWithFreebind(cfg.Addr)
		} else {
			l, err = net.Listen("tcp", cfg.Addr)
		}
		if err != nil {
			return err
		}
		if cfg.ProxyProtocol {
			l = &proxyproto.Listener{Listener: l, Policy: requirePP}
		}
		run = func() error { return s.ServeHTTP(l) }
	case "https", "doh":
		var l net.Listener
		var err error
		if cfg.IP_FREEBIND {
			l, err = ListenTCPWithFreebind(cfg.Addr)
		} else {
			l, err = net.Listen("tcp", cfg.Addr)
		}
		if err != nil {
			return err
		}
		if cfg.ProxyProtocol {
			l = &proxyproto.Listener{Listener: l, Policy: requirePP}
		}
		run = func() error { return s.ServeHTTPS(l) }
	default:
		return fmt.Errorf("unknown protocol: [%s]", cfg.Protocol)
	}

	m.sc.Attach(func(done func(), closeSignal <-chan struct{}) {
		defer done()
		errChan := make(chan error, 1)
		go func() {
			errChan <- run()
		}()
		select {
		case err := <-errChan:
			m.sc.SendCloseSignal(fmt.Errorf("server exited, %w", err))
		case <-closeSignal:
		}
	})

	return nil
}
