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

package doh

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/miekg/dns"
)

const (
	defaultDoHTimeout = time.Second * 5
)

// Upstream is a DNS-over-HTTPS (RFC 8484) upstream.
type Upstream struct {
	// EndPoint is the DoH server URL.
	EndPoint string
	// Client is a http.Client that sends http requests.
	Client *http.Client
}

func NewUpstream(endPoint string, client *http.Client) *Upstream {
	return &Upstream{EndPoint: endPoint, Client: client}
}

var (
	bufPool4k = pool.NewBytesBufPool(4096)
)

func (u *Upstream) ExchangeContext(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	wire, buf, err := pool.PackBuffer(q)
	if err != nil {
		return nil, fmt.Errorf("failed to pack query msg, %w", err)
	}
	defer pool.ReleaseBuf(buf)

	// In order to maximize HTTP cache friendliness, DoH clients using media
	// formats that include the ID field from the DNS message header, such
	// as "application/dns-message", SHOULD use a DNS ID of 0 in every DNS
	// request.
	// https://tools.ietf.org/html/rfc8484#section-4.1
	wire[0] = 0
	wire[1] = 0

	urlLen := len(u.EndPoint) + 5 + base64.RawURLEncoding.EncodedLen(len(wire))
	urlBuf := make([]byte, urlLen)

	p := 0
	p += copy(urlBuf[p:], u.EndPoint)
	// A simple way to check whether the endpoint already has a parameter.
	if strings.LastIndexByte(u.EndPoint, '?') >= 0 {
		p += copy(urlBuf[p:], "&dns=")
	} else {
		p += copy(urlBuf[p:], "?dns=")
	}

	// Padding characters for base64url MUST NOT be included.
	// See: https://tools.ietf.org/html/rfc8484#section-6.
	base64.RawURLEncoding.Encode(urlBuf[p:], wire)

	type result struct {
		r   *dns.Msg
		err error
	}

	resChan := make(chan *result, 1)
	go func() {
		// We overwrite the ctx with a fixed timout context here.
		// Because the http package may close the underlay connection
		// if the context is done before the query is completed. This
		// reduces the connection reuse efficiency.
		ctx, cancel := context.WithTimeout(context.Background(), defaultDoHTimeout)
		defer cancel()
		r, err := u.exchange(ctx, utils.BytesToStringUnsafe(urlBuf))
		resChan <- &result{r: r, err: err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-resChan:
		r := res.r
		err := res.err
		if r != nil {
			r.Id = q.Id
		}
		return r, err
	}
}

func (u *Upstream) exchange(ctx context.Context, url string) (*dns.Msg, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("internal err: NewRequestWithContext: %w", err)
	}

	req.Header["Accept"] = []string{"application/dns-message"}
	req.Header["User-Agent"] = nil // Don't let go http send a default user agent header.
	resp, err := u.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	// check status code
	if resp.StatusCode != http.StatusOK {
		body1k, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		if body1k != nil {
			return nil, fmt.Errorf("bad http status codes %d with body [%s]", resp.StatusCode, body1k)
		}
		return nil, fmt.Errorf("bad http status codes %d", resp.StatusCode)
	}

	bb := bufPool4k.Get()
	defer bufPool4k.Release(bb)
	_, err = bb.ReadFrom(io.LimitReader(resp.Body, dns.MaxMsgSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read http body: %w", err)
	}

	r := new(dns.Msg)
	if err := r.Unpack(bb.Bytes()); err != nil {
		return nil, fmt.Errorf("failed to unpack http body: %w", err)
	}
	return r, nil
}
