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

package cache

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/golang/snappy"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sieveLau/mosdns/v4-maintenance/coremain"
	"github.com/sieveLau/mosdns/v4-maintenance/pkg/cache"
	"github.com/sieveLau/mosdns/v4-maintenance/pkg/cache/mem_cache"
	"github.com/sieveLau/mosdns/v4-maintenance/pkg/cache/redis_cache"
	"github.com/sieveLau/mosdns/v4-maintenance/pkg/dnsutils"
	"github.com/sieveLau/mosdns/v4-maintenance/pkg/executable_seq"
	"github.com/sieveLau/mosdns/v4-maintenance/pkg/pool"
	"github.com/sieveLau/mosdns/v4-maintenance/pkg/query_context"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
)

const (
	PluginType = "cache"
)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })

	coremain.RegNewPersetPluginFunc("_default_cache", func(bp *coremain.BP) (coremain.Plugin, error) {
		return newCachePlugin(bp, &Args{})
	})
}

const (
	defaultLazyUpdateTimeout = time.Second * 5
	defaultEmptyAnswerTTL    = time.Second * 300
	recommendedLazyTTL		 = 30 // RFC 8767 Section 4
)

var _ coremain.ExecutablePlugin = (*cachePlugin)(nil)

type Args struct {
	Size              int    `yaml:"size"`
	Redis             string `yaml:"redis"`
	RedisTimeout      int    `yaml:"redis_timeout"`
	LazyCacheTTL      int    `yaml:"lazy_cache_ttl"`
	LazyCacheReplyTTL int    `yaml:"lazy_cache_reply_ttl"`
	CacheEverything   bool   `yaml:"cache_everything"`
	CompressResp      bool   `yaml:"compress_resp"`
	WhenHit           string `yaml:"when_hit"`
}

type cachePlugin struct {
	*coremain.BP
	args *Args

	whenHit      executable_seq.Executable
	backend      cache.Backend
	lazyUpdateSF singleflight.Group

	queryTotal   prometheus.Counter
	hitTotal     prometheus.Counter
	lazyHitTotal prometheus.Counter
	size         prometheus.GaugeFunc
}

func Init(bp *coremain.BP, args interface{}) (p coremain.Plugin, err error) {
	return newCachePlugin(bp, args.(*Args))
}

func newCachePlugin(bp *coremain.BP, args *Args) (*cachePlugin, error) {
	var c cache.Backend
	if len(args.Redis) != 0 {
		opt, err := redis.ParseURL(args.Redis)
		if err != nil {
			return nil, fmt.Errorf("invalid redis url, %w", err)
		}
		opt.MaxRetries = -1
		r := redis.NewClient(opt)
		rcOpts := redis_cache.RedisCacheOpts{
			Client:        r,
			ClientCloser:  r,
			ClientTimeout: time.Duration(args.RedisTimeout) * time.Millisecond,
			Logger:        bp.L(),
		}
		rc, err := redis_cache.NewRedisCache(rcOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to init redis cache, %w", err)
		}
		c = rc
	} else {
		c = mem_cache.NewMemCache(args.Size, 0)
	}

	if args.LazyCacheReplyTTL <= 0 {
		args.LazyCacheReplyTTL = recommendedLazyTTL
	}

	var whenHit executable_seq.Executable
	if tag := args.WhenHit; len(tag) > 0 {
		m := bp.M().GetExecutables()
		whenHit = m[tag]
		if whenHit == nil {
			return nil, fmt.Errorf("cannot find exectable %s", tag)
		}
	}

	p := &cachePlugin{
		BP:      bp,
		args:    args,
		whenHit: whenHit,
		backend: c,

		queryTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "query_total",
			Help: "The total number of processed queries",
		}),
		hitTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "hit_total",
			Help: "The total number of queries that hit the cache",
		}),
		lazyHitTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "lazy_hit_total",
			Help: "The total number of queries that hit the expired cache",
		}),
		size: prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "cache_size",
			Help: "Current cache size in records",
		}, func() float64 {
			return float64(c.Len())
		}),
	}
	bp.GetMetricsReg().MustRegister(p.queryTotal, p.hitTotal, p.lazyHitTotal, p.size)
	return p, nil
}

func (c *cachePlugin) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	c.queryTotal.Inc()
	q := qCtx.Q()

	msgKey, err := c.getMsgKey(q)
	if err != nil {
		c.L().Error("get msg key", qCtx.InfoField(), zap.Error(err))
	}
	if len(msgKey) == 0 { // skip cache
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	cachedResp, lazyHit, err := c.lookupCache(msgKey)
	if err != nil {
		c.L().Error("lookup cache", qCtx.InfoField(), zap.Error(err))
	}
	if lazyHit {
		c.lazyHitTotal.Inc()
		c.doLazyUpdate(msgKey, qCtx, next)
	}
	if cachedResp != nil { // cache hit
		c.hitTotal.Inc()
		cachedResp.Id = q.Id // change msg id
		c.L().Debug("cache hit", qCtx.InfoField())
		qCtx.SetResponse(cachedResp)
		if c.whenHit != nil {
			return c.whenHit.Exec(ctx, qCtx, nil)
		}
		return nil
	}

	// cache miss, run the entry and try to store its response.
	c.L().Debug("cache miss", qCtx.InfoField())
	err = executable_seq.ExecChainNode(ctx, qCtx, next)
	r := qCtx.R()
	if r != nil {
		if err := c.tryStoreMsg(msgKey, r); err != nil {
			c.L().Error("cache store", qCtx.InfoField(), zap.Error(err))
		}
	}
	return err
}

// getMsgKey returns a string key for the query msg, or an empty
// string if query should not be cached.
func (c *cachePlugin) getMsgKey(msg *dns.Msg) (string, error) {
	appendWithPipe := func(sb *bytes.Buffer, str string) {
		sb.WriteString("|")
		sb.WriteString(str)
	}

	// if cache everything or more than 1 question, use the old method
	if c.args.CacheEverything || len(msg.Question) > 1 {
		msgKey, err := dnsutils.GetMsgKey(msg, 0)
		if err != nil {
			return "", fmt.Errorf("failed to unpack query msg, %w", err)
		}
		return msgKey, nil
	}

	// if not everything, use the new method, considering ecs
    // Hash the question section
    q := msg.Question[0]
	var keyBuffer bytes.Buffer

    keyBuffer.WriteString(strings.ToLower(q.Name))
	appendWithPipe(&keyBuffer, strconv.FormatUint(uint64(q.Qtype),10))
	appendWithPipe(&keyBuffer, strconv.FormatUint(uint64(q.Qclass),10))

	// combine e.Address and e.SourceNetmask into a string
	// Just in case the e.Address is a full IP, not masked
	ecsString := func(e *dns.EDNS0_SUBNET) string {
		// e.Family is 1 for IPv4, 2 for IPv6
		// maskbits is 32 for IPv4, 128 for IPv6
		// algebra: 24*(2-x)+128*(x-1)
		maskbit := int(96*(e.Family)-64)
		mask := net.CIDRMask(int(e.SourceNetmask),maskbit)
		maskedIP := e.Address.Mask(mask)
		// Return the formatted result as "IP/mask"
		return fmt.Sprintf("%s/%d", maskedIP.String(), e.SourceNetmask)
	}

    // Check for EDNS options
    if opt := msg.IsEdns0(); opt != nil {
		//appendWithPipe(&keybuffer, strconv.FormatBool(opt.Do()))
		if ecs := dnsutils.GetECS(opt); ecs != nil {
			appendWithPipe(&keyBuffer, ecsString(ecs))
		}
    }
	return keyBuffer.String(), nil
}

// lookupCache returns the cached response. The ttl of returned msg will be changed properly.
// Remember, caller must change the msg id.
func (c *cachePlugin) lookupCache(msgKey string) (r *dns.Msg, lazyHit bool, err error) {
	// lookup in cache
	v, storedTime, _ := c.backend.Get(msgKey)

	// cache hit
	if v != nil {
		if c.args.CompressResp {
			decodeLen, err := snappy.DecodedLen(v)
			if err != nil {
				return nil, false, fmt.Errorf("snappy decode err: %w", err)
			}
			if decodeLen > dns.MaxMsgSize {
				return nil, false, fmt.Errorf("invalid snappy data, not a dns msg, data len: %d", decodeLen)
			}
			decompressBuf := pool.GetBuf(decodeLen)
			defer decompressBuf.Release()
			v, err = snappy.Decode(decompressBuf.Bytes(), v)
			if err != nil {
				return nil, false, fmt.Errorf("snappy decode err: %w", err)
			}
		}
		r = new(dns.Msg)
		if err := r.Unpack(v); err != nil {
			return nil, false, fmt.Errorf("failed to unpack cached data, %w", err)
		}

		var msgTTL time.Duration
		if len(r.Answer) == 0 {
			msgTTL = defaultEmptyAnswerTTL
		} else {
			msgTTL = time.Duration(dnsutils.GetMinimalTTL(r)) * time.Second
		}

		// not expired
		if storedTime.Add(msgTTL).After(time.Now()) {
			dnsutils.SubtractTTL(r, uint32(time.Since(storedTime).Seconds()))
			return r, false, nil
		}

		// expired but lazy update enabled
		if c.args.LazyCacheTTL > 0 {
			// set the default ttl
			dnsutils.SetTTL(r, uint32(c.args.LazyCacheReplyTTL))
			return r, true, nil
		}
	}

	// cache miss
	return nil, false, nil
}

// doLazyUpdate starts a new goroutine to execute next node and update the cache in the background.
// It has an inner singleflight.Group to de-duplicate same msgKey.
func (c *cachePlugin) doLazyUpdate(msgKey string, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) {
	lazyQCtx := qCtx.Copy()
	lazyUpdateFunc := func() (interface{}, error) {
		c.L().Debug("start lazy cache update", lazyQCtx.InfoField())
		defer c.lazyUpdateSF.Forget(msgKey)
		lazyCtx, cancel := context.WithTimeout(context.Background(), defaultLazyUpdateTimeout)
		defer cancel()

		err := executable_seq.ExecChainNode(lazyCtx, lazyQCtx, next)
		if err != nil {
			c.L().Warn("failed to update lazy cache", lazyQCtx.InfoField(), zap.Error(err))
		}

		r := lazyQCtx.R()
		if r != nil {
			if err := c.tryStoreMsg(msgKey, r); err != nil {
				c.L().Error("cache store", qCtx.InfoField(), zap.Error(err))
			}
		}
		c.L().Debug("lazy cache updated", lazyQCtx.InfoField())
		return nil, nil
	}
	c.lazyUpdateSF.DoChan(msgKey, lazyUpdateFunc) // DoChan won't block this goroutine
}

// tryStoreMsg tries to store r to cache. If r should be cached.
func (c *cachePlugin) tryStoreMsg(key string, r *dns.Msg) error {
	if !(r.Rcode == dns.RcodeSuccess || r.Rcode == dns.RcodeNameError) || (r.Truncated) {
		return nil
	}

	v, err := r.Pack()
	if err != nil {
		return fmt.Errorf("failed to pack response msg, %w", err)
	}

	now := time.Now()
    timeNumber := uint32(0)
	var expirationTime time.Time
	if c.args.LazyCacheTTL > 0 {
		timeNumber = uint32(c.args.LazyCacheTTL)
	} else {
		// switch, instead of if, is for other possible negative cache in the future
		switch r.Rcode {
			case dns.RcodeNameError:
				for _, rr := range r.Ns {
					if soa, ok := rr.(*dns.SOA); ok {
						// Return the SOA's Minimum TTL (Negative caching TTL recommendation from RFC 2308)
						timeNumber = soa.Minttl
					}
					// if response contains no SOA, it should be seen as invalid, so not caching it is appropriate
				}
			default:
				timeNumber = dnsutils.GetMinimalTTL(r)
		}		
	}
	if timeNumber == 0 {
		return nil
	}
	expirationTime = now.Add(time.Duration(timeNumber) * time.Second)

	if c.args.CompressResp {
		compressBuf := pool.GetBuf(snappy.MaxEncodedLen(len(v)))
		v = snappy.Encode(compressBuf.Bytes(), v)
		defer compressBuf.Release()
	}
	c.backend.Store(key, v, now, expirationTime)
	return nil
}

func (c *cachePlugin) Shutdown() error {
	return c.backend.Close()
}
