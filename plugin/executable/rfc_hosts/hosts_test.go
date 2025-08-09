package rfchosts

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/sieveLau/mosdns/v4-maintenance/pkg/query_context"
	"github.com/stretchr/testify/assert"
)

func TestGoodLoading(t *testing.T) {
	p, err := newHostsContainer(nil, &Args{HostsFilePath: []string{"testdata/hosts"}})
	assert.NoError(t, err)
	assert.NotNil(t, p)
}

func TestBadLoading(t *testing.T) {
	p, err := newHostsContainer(nil, &Args{HostsFilePath: []string{"testdata/hosts_fake"}})
	assert.Error(t, err)
	assert.Nil(t, p)
}

func TestV4Hosts(t *testing.T) {
	p, _ := newHostsContainer(nil, &Args{HostsFilePath: []string{"testdata/hosts"}})

	q := new(dns.Msg)
	q.SetQuestion("test.a.b.com.", dns.TypeA)

	qCtx := query_context.NewContext(q, nil)
	p.Exec(context.TODO(), qCtx, nil)
	assert.Equal(t, 1, len(qCtx.R().Answer))
	assert.Equal(t, qCtx.R().Answer[0].Header().Name, "test.a.b.com.")
	assert.Equal(t, qCtx.R().Answer[0].Header().Rrtype, dns.TypeA)
	assert.Equal(t, qCtx.R().Answer[0].Header().Ttl, uint32(10))
	assert.Equal(t, qCtx.R().Answer[0].(*dns.A).A, net.ParseIP("127.0.0.1").To4())
}

func TestV6Hosts(t *testing.T) {
	p, _ := newHostsContainer(nil, &Args{HostsFilePath: []string{"testdata/hosts"}})

	q := new(dns.Msg)
	q.SetQuestion("test6.a.b.com.", dns.TypeAAAA)

	qCtx := query_context.NewContext(q, nil)
	p.Exec(context.TODO(), qCtx, nil)
	assert.Equal(t, 1, len(qCtx.R().Answer))
	assert.Equal(t, qCtx.R().Answer[0].Header().Name, "test6.a.b.com.")
	assert.Equal(t, qCtx.R().Answer[0].Header().Rrtype, dns.TypeAAAA)
	assert.Equal(t, qCtx.R().Answer[0].Header().Ttl, uint32(10))
	assert.Equal(t, qCtx.R().Answer[0].(*dns.AAAA).AAAA, net.ParseIP("::1").To16())
}

func TestNilHosts(t *testing.T) {
	p, _ := newHostsContainer(nil, &Args{HostsFilePath: []string{"testdata/hosts"}})

	q := new(dns.Msg)
	q.SetQuestion("nil.a.b.com.", dns.TypeA)

	qCtx := query_context.NewContext(q, nil)
	p.Exec(context.TODO(), qCtx, nil)
	assert.Nil(t, qCtx.R())
}

func TestMultipleHosts(t *testing.T) {
	p, _ := newHostsContainer(nil, &Args{HostsFilePath: []string{"testdata/hosts"}})

	q := new(dns.Msg)
	q.SetQuestion("multi.a.b.com.", dns.TypeA)

	qCtx := query_context.NewContext(q, nil)
	p.Exec(context.TODO(), qCtx, nil)
	assert.Equal(t, 2, len(qCtx.R().Answer))
	assert.Equal(t, qCtx.R().Answer[0].Header().Name, "multi.a.b.com.")
	assert.Equal(t, qCtx.R().Answer[1].Header().Name, "multi.a.b.com.")
}
