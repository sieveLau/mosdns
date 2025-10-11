/*
 * Copyright (C) 2020-2022, IrineSistiana
 * Author: Sieve Lau (sievelau@gmail.com)
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
package rfchosts

import (
	"context"
	"io"
	"os"
	"strings"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/hostsfile"
	"github.com/miekg/dns"

	"github.com/sieveLau/mosdns/v4-maintenance/coremain"
	"github.com/sieveLau/mosdns/v4-maintenance/pkg/executable_seq"
	"github.com/sieveLau/mosdns/v4-maintenance/pkg/query_context"
)

// PluginType is the name of executable used in the config file.
const PluginType = "rfc_hosts"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

var _ coremain.ExecutablePlugin = (*hostsPlugin)(nil)

type Args struct {
	HostsFilePath []string `yaml:"hosts_path"`
}

type hostsPlugin struct {
	*coremain.BP
	hr *upstream.HostsResolver
}

func Init(bp *coremain.BP, args interface{}) (p coremain.Plugin, err error) {
	return newHostsContainer(bp, args.(*Args))
}

func newHostsContainer(bp *coremain.BP, args *Args) (*hostsPlugin, error) {
	storage, err := hostsfile.NewDefaultStorage(
		context.TODO(),
		&hostsfile.DefaultStorageConfig{},
	)
	if err != nil {
		return nil, err
	}

	for _, path := range args.HostsFilePath {
		// Open the file, construct a io.Reader, and parse it
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		// f implements io.Reader
		var r io.Reader = f

		err = hostsfile.Parse(context.TODO(), storage, r, nil)
		if err != nil {
			return nil, err
		}
	}

	return &hostsPlugin{
		BP: bp,
		hr: upstream.NewHostsResolver(storage),
	}, nil
}

func (hp *hostsPlugin) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	var network string
	qname := qCtx.Q().Question[0].Name                            // be careful, when constructing response, Name must be fqdn (with dot ending)
	searchName := strings.ToLower(strings.TrimSuffix(qname, ".")) // but in hosts file, search name is usually without dot

	// hosts file only supports A and AAAA queries
	switch qCtx.Q().Question[0].Qtype {
	case dns.TypeA:
		network = "ip4"
	case dns.TypeAAAA:
		network = "ip6"
	default: // for other types, let the next executable node handle it
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	// now either A or AAAA is waiting for the result
	addrs, err := hp.hr.LookupNetIP(ctx, network, searchName)
	if err != nil {
		return err
	}

	// if no addresses are found, it means no record in hosts matches, so continue to the next executable node
	if len(addrs) == 0 {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	// otherwise, we have a result, so create a reply and return it
	r := new(dns.Msg)
	r.SetReply(qCtx.Q())
	r.RecursionAvailable = true
	switch network {
	case "ip4":
		for _, ip := range addrs {
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    10,
				},
				A: ip.AsSlice(),
			}
			r.Answer = append(r.Answer, rr)
		}
	case "ip6":
		for _, ip := range addrs {
			rr := &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    10,
				},
				AAAA: ip.AsSlice(),
			}
			r.Answer = append(r.Answer, rr)
		}
	}
	qCtx.SetResponse(r)
	return nil
}

func (hr *hostsPlugin) Close() error {
	return nil
}
