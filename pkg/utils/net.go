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

package utils

import (
	"fmt"
	"net"
	"net/netip"
)

var privateIPBlocks []*net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927 link-local
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Errorf("parse error on %q: %v", cidr, err))
		}
		privateIPBlocks = append(privateIPBlocks, block)
	}
}


// GetIPFromAddr returns a net.IP from the given net.Addr.
// addr can be *net.TCPAddr, *net.UDPAddr, *net.IPNet, *net.IPAddr
// Will return nil otherwise.
func GetIPFromAddr(addr net.Addr) (ip net.IP) {
	switch v := addr.(type) {
	case *net.TCPAddr:
		return v.IP
	case *net.UDPAddr:
		return v.IP
	case *net.IPNet:
		return v.IP
	case *net.IPAddr:
		return v.IP
	}
	return nil
}

// GetAddrFromAddr returns netip.Addr from net.Addr.
// See also: GetIPFromAddr.
func GetAddrFromAddr(addr net.Addr) netip.Addr {
	a, _ := netip.AddrFromSlice(GetIPFromAddr(addr))
	return a
}

// SplitSchemeAndHost splits addr to protocol and host.
func SplitSchemeAndHost(addr string) (protocol, host string) {
	if protocol, host, ok := SplitString2(addr, "://"); ok {
		return protocol, host
	} else {
		return "", addr
	}
}

func GetAddrFromIP(ip net.IP) netip.Addr {
	addr, err := netip.ParseAddr(ip.String())
    if err != nil {
        return netip.Addr{}
    }
    return addr
}

func IsPrivateIP(ip netip.Addr) bool {
	if ip.Is4In6() {
		ip = ip.Unmap()
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	for _, block := range privateIPBlocks {
		if block.Contains(net.IP(ip.AsSlice())) {
			return true
		}
	}
	return false
}