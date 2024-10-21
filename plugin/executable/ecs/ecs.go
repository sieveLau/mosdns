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

package ecs

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/miekg/dns"
	"github.com/sieveLau/mosdns/v4-maintenance/coremain"
	"github.com/sieveLau/mosdns/v4-maintenance/pkg/dnsutils"
	"github.com/sieveLau/mosdns/v4-maintenance/pkg/executable_seq"
	"github.com/sieveLau/mosdns/v4-maintenance/pkg/query_context"
	"github.com/sieveLau/mosdns/v4-maintenance/pkg/utils"
)

const PluginType = "ecs"

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
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })

	coremain.RegNewPersetPluginFunc("_no_ecs", func(bp *coremain.BP) (coremain.Plugin, error) {
		return &noECS{BP: bp}, nil
	})
}

func isPrivateIP(ip netip.Addr) bool {
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

var _ coremain.ExecutablePlugin = (*ecsPlugin)(nil)

type Args struct {
	// Automatically append client address as ecs.
	// If this is true, pre-set addresses will not be used.
	Auto bool `yaml:"auto"`

	// Filter out private addresses in ecs
	NoPrivate bool `yaml:"no_private"`

	// force overwrite existing ecs
	ForceOverwrite bool `yaml:"force_overwrite"`

	// mask for ecs
	Mask4 int `yaml:"mask4"` // default 24
	Mask6 int `yaml:"mask6"` // default 48

	// pre-set address
	IPv4 string `yaml:"ipv4"`
	IPv6 string `yaml:"ipv6"`
}

func (a *Args) Init() error {
	if ok := utils.CheckNumRange(a.Mask4, 0, 32); !ok {
		return fmt.Errorf("invalid mask4 %d, should between 0~32", a.Mask4)
	}
	if ok := utils.CheckNumRange(a.Mask6, 0, 128); !ok {
		return fmt.Errorf("invalid mask6 %d, should between 0~128", a.Mask6)
	}
	utils.SetDefaultNum(&a.Mask4, 24)
	utils.SetDefaultNum(&a.Mask6, 48)
	return nil
}

type ecsPlugin struct {
	*coremain.BP
	args       *Args
	ipv4, ipv6 netip.Addr
}

func Init(bp *coremain.BP, args interface{}) (p coremain.Plugin, err error) {
	return newPlugin(bp, args.(*Args))
}

func newPlugin(bp *coremain.BP, args *Args) (p *ecsPlugin, err error) {
	if err := args.Init(); err != nil {
		return nil, err
	}

	ep := new(ecsPlugin)
	ep.BP = bp
	ep.args = args

	if len(args.IPv4) != 0 {
		addr, err := netip.ParseAddr(args.IPv4)
		if err != nil {
			return nil, fmt.Errorf("invaild ipv4 address, %w", err)
		}
		if !addr.Is4() {
			return nil, fmt.Errorf("%s is not a ipv4 address", args.IPv4)
		}
		if isPrivateIP(addr) {
			bp.L().Warn(fmt.Sprintf("%s is a private address and should not be used as client subnet", addr.String()))
			if !args.NoPrivate {
				ep.ipv4 = addr
			}
		} else {
			ep.ipv4 = addr
		}
	}

	if len(args.IPv6) != 0 {
		addr, err := netip.ParseAddr(args.IPv6)
		if err != nil {
			return nil, fmt.Errorf("invaild ipv6 address, %w", err)
		}
		if !addr.Is6() {
			return nil, fmt.Errorf("%s is not a ipv6 address", args.IPv6)
		}
		if isPrivateIP(addr) {
			bp.L().Warn(fmt.Sprintf("%s is a private address and should not be used as client subnet", addr.String()))
			if !args.NoPrivate {
				ep.ipv6 = addr
			}
		} else {
			ep.ipv6 = addr
		}
	}

	return ep, nil
}

// Exec tries to append ECS to qCtx.Q().
func (e *ecsPlugin) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	upgraded, replacedECS, oldECS := e.addECS(qCtx)
	err := executable_seq.ExecChainNode(ctx, qCtx, next)
	if err != nil {
		return err
	}

	setRScopePrefix := func(r *dns.Msg) {
		if newECS := dnsutils.GetMsgECS(r); newECS != nil {
			oldECS.SourceScope = newECS.SourceScope
		}
	}

	if r := qCtx.R(); r != nil {
		if upgraded { // if query is non EDNS0, remove the entire EDNS0 section
			dnsutils.RemoveEDNS0(r)
		} else if oldECS == nil { // if query has no ECS, remove only the ECS
			dnsutils.RemoveMsgECS(r)
		} else if replacedECS { // if query has ECS, replace the response's ECS with the query's
			// with scope prefix set to the response's one
			setRScopePrefix(r)
			dnsutils.AddECS(r.IsEdns0(), oldECS, true)
		}
	}
	return nil
}

func cloneECS(q *dns.Msg) *dns.EDNS0_SUBNET {
	if ecs := dnsutils.GetMsgECS(q); ecs != nil {
		newECS := *ecs
		return &newECS
	}
	return nil
}

// addECS adds a *dns.EDNS0_SUBNET record to q.
// upgraded: Whether the addECS upgraded the q to a EDNS0 enabled query.
// overwrited: Whether the addECS added a *dns.EDNS0_SUBNET to q that didn't
// have a *dns.EDNS0_SUBNET before.
// oldECS: A CLONE of the original *dns.EDNS0_SUBNET, nil if none
// RFC 7871, if the client queries with ecs, we must response with one
func (e *ecsPlugin) addECS(qCtx *query_context.Context) (upgraded bool, overwrited bool, originECS *dns.EDNS0_SUBNET) {
	q := qCtx.Q()
	opt := q.IsEdns0()
	hasECS := opt != nil && dnsutils.GetECS(opt) != nil
	var oldECS *dns.EDNS0_SUBNET = nil
	if hasECS {
		oldECS = cloneECS(q)
		// Argument args.ForceOverwrite is disabled. q already has an edns0 subnet. Skip it.
		// RFC 7871, source prefix 0 should not be replaced
		if !e.args.ForceOverwrite || oldECS.SourceNetmask == 0 {
			return false, false, oldECS
		}
	} // if the query has no ECS, oldECS is nil

	var ecs *dns.EDNS0_SUBNET
	if e.args.Auto { // use client ip
		clientAddr := qCtx.ReqMeta().ClientAddr
		if !clientAddr.IsValid() || (isPrivateIP(clientAddr) && e.args.NoPrivate) {
			// Not replacing ECS, return nil
			return false, false, oldECS
		}

		switch {
		case clientAddr.Is4():
			ecs = dnsutils.NewEDNS0Subnet(clientAddr.AsSlice(), uint8(e.args.Mask4), false)
		case clientAddr.Is4In6():
			ecs = dnsutils.NewEDNS0Subnet(clientAddr.Unmap().AsSlice(), uint8(e.args.Mask4), false)
		case clientAddr.Is6():
			ecs = dnsutils.NewEDNS0Subnet(clientAddr.AsSlice(), uint8(e.args.Mask6), true)
		}
	} else { // use preset ip
		switch {
		case checkQueryType(q, dns.TypeA):
			if e.ipv4.IsValid() {
				ecs = dnsutils.NewEDNS0Subnet(e.ipv4.AsSlice(), uint8(e.args.Mask4), false)
			} else if e.ipv6.IsValid() {
				ecs = dnsutils.NewEDNS0Subnet(e.ipv6.AsSlice(), uint8(e.args.Mask6), true)
			}

		case checkQueryType(q, dns.TypeAAAA):
			if e.ipv6.IsValid() {
				ecs = dnsutils.NewEDNS0Subnet(e.ipv6.AsSlice(), uint8(e.args.Mask6), true)
			} else if e.ipv4.IsValid() {
				ecs = dnsutils.NewEDNS0Subnet(e.ipv4.AsSlice(), uint8(e.args.Mask4), false)
			}
		}
	}

	if ecs != nil {
		if opt == nil {
			upgraded = true
			opt = dnsutils.UpgradeEDNS0(q)
		}
		overwrited = dnsutils.AddECS(opt, ecs, true)
		return upgraded, overwrited, oldECS
	}
	return false, false, oldECS
}

func checkQueryType(m *dns.Msg, typ uint16) bool {
	if len(m.Question) > 0 && m.Question[0].Qtype == typ {
		return true
	}
	return false
}

type noECS struct {
	*coremain.BP
}

var _ coremain.ExecutablePlugin = (*noECS)(nil)

// Should be transparent to the client,
// remove ecs from query to upstream, and add back to response if present
func (n *noECS) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	q := qCtx.Q()
	// get a copy before request
	oldECS := cloneECS(q)
	if oldECS != nil {
		dnsutils.RemoveMsgECS(q)
	}
	if err := executable_seq.ExecChainNode(ctx, qCtx, next); err != nil {
		return err
	}
	setRScopePrefix := func(r *dns.Msg) {
		if newECS := dnsutils.GetMsgECS(r); newECS != nil {
			oldECS.SourceScope = newECS.SourceScope
		}
	}
	r := qCtx.R()
	if r != nil {
		if oldECS == nil { // if query have no ECS, remove it from response
			dnsutils.RemoveMsgECS(r)
			return nil
		}
		// query has ECS
		ropt := r.IsEdns0()
		if ropt == nil { // if response has no ECS, create the OPT section
			ropt = new(dns.OPT)
			dnsutils.AddECS(ropt, oldECS, true) // replace response's ECS with ours
			r.Extra = append(r.Extra, ropt)
		} else {
			setRScopePrefix(r)                  // if response has ECS, set oldECS scope prefix
			dnsutils.AddECS(ropt, oldECS, true) // replace response's ECS with ours
		}
	}
	return nil
}
