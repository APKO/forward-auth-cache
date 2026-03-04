package forwardauthcache

import (
	"bytes"
	"fmt"
	"io"
	"maps"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jellydator/ttlcache/v3"
)

func init() {
	caddy.RegisterModule(ForwardAuthCache{})
	httpcaddyfile.RegisterHandlerDirective("forward-auth-cache", parseCaddyfile)
}

type ForwardAuthCache struct {
	AuthURL          string            `json:"auth_url,omitempty"`
	TTL              caddy.Duration    `json:"ttl,omitempty"`
	CookieName       string            `json:"cookie_name,omitempty"`
	CopyHeaders      []string          `json:"copy_headers,omitempty"`
	PassHeaders      map[string]string `json:"pass_headers,omitempty"`
	CacheKeyTemplate string            `json:"cache_key,omitempty"`
	Timeout          caddy.Duration    `json:"timeout,omitempty"`
	RequestMethod    string            `json:"method,omitempty"`

	cache  *ttlcache.Cache[string, cacheEntry]
	client *http.Client
}

type cacheEntry struct {
	Status  int
	Headers http.Header
	Body    []byte
}

func (ForwardAuthCache) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.forward-auth-cache",
		New: func() caddy.Module { return new(ForwardAuthCache) },
	}
}

func (a *ForwardAuthCache) Validate() error {
	if a.AuthURL == "" {
		return fmt.Errorf("forward-auth-cache: 'auth_url' is required")
	}
	if a.TTL == 0 {
		a.TTL = caddy.Duration(1 * time.Minute)
	}
	if a.CookieName == "" {
		return fmt.Errorf("forward-auth-cache: 'cookie' is required")
	}
	if len(a.CopyHeaders) == 0 {
		return fmt.Errorf("forward-auth-cache: 'copy_headers' is required (at least one)")
	}
	if a.CacheKeyTemplate == "" {
		return fmt.Errorf("forward-auth-cache: 'cache_key' is required")
	}
	if a.Timeout == 0 {
		a.Timeout = caddy.Duration(3 * time.Second)
	}
	if a.RequestMethod == "" {
		a.RequestMethod = "GET"
	}
	return nil
}

func (a *ForwardAuthCache) Provision(ctx caddy.Context) error {
	a.PassHeaders = make(map[string]string)

	a.cache = ttlcache.New(
		ttlcache.WithTTL[string, cacheEntry](time.Duration(a.TTL)),
		ttlcache.WithCapacity[string, cacheEntry](100_000),
	)

	// Запускаємо автоматичне очищення протермінованих елементів
	go a.cache.Start()

	a.client = &http.Client{
		Timeout: time.Duration(a.Timeout),
		Transport: &http.Transport{
			MaxIdleConns:        200,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  true,
		},
	}

	return nil
}

func (a *ForwardAuthCache) Cleanup() error {
	if a.cache != nil {
		a.cache.Stop() // зупиняємо cleaner, щоб graceful shutdown
	}
	return nil
}

func (a *ForwardAuthCache) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok {
		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("forward-auth-cache: replacer not found"))
	}

	token := ""
	if c, _ := r.Cookie(a.CookieName); c != nil {
		token = c.Value
	}

	key := repl.ReplaceAll(a.CacheKeyTemplate, "")

	if item := a.cache.Get(key); item != nil {
		entry := item.Value()

		if entry.Status != http.StatusOK && entry.Status != http.StatusNoContent {
			maps.Copy(w.Header(), entry.Headers)
			w.WriteHeader(entry.Status)
			if len(entry.Body) > 0 {
				w.Write(entry.Body)
			}
			return nil
		}

		for _, h := range a.CopyHeaders {
			if v := entry.Headers.Get(h); v != "" {
				r.Header.Set(h, v)
			}
		}
		return next.ServeHTTP(w, r)
	}

	// miss → запит до auth
	req, _ := http.NewRequestWithContext(r.Context(), a.RequestMethod, a.AuthURL, nil)
	req.Header.Set("Cookie", fmt.Sprintf("%s=%s", a.CookieName, token))

	for name, val := range a.PassHeaders {
		req.Header.Set(name, repl.ReplaceAll(val, ""))
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return caddyhttp.Error(http.StatusBadGateway, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	entry := cacheEntry{
		Status:  resp.StatusCode,
		Headers: resp.Header.Clone(),
		Body:    bytes.Clone(body),
	}

	a.cache.Set(key, entry, ttlcache.DefaultTTL)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		maps.Copy(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		w.Write(body)
		return nil
	}

	for _, h := range a.CopyHeaders {
		if v := resp.Header.Get(h); v != "" {
			r.Header.Set(h, v)
		}
	}

	return next.ServeHTTP(w, r)
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	a := new(ForwardAuthCache)
	a.PassHeaders = make(map[string]string)

	for h.Next() {
		for h.NextBlock(0) {
			switch h.Val() {
			case "auth_url":
				a.AuthURL = h.RemainingArgs()[0]
			case "ttl":
				d, _ := caddy.ParseDuration(h.RemainingArgs()[0])
				a.TTL = caddy.Duration(d)
			case "cookie":
				a.CookieName = h.RemainingArgs()[0]
			case "copy_headers":
				for h.NextArg() {
					a.CopyHeaders = append(a.CopyHeaders, h.Val())
				}
			case "pass_header":
				if h.NextArg() {
					name := h.Val()
					if h.NextArg() {
						a.PassHeaders[name] = h.Val()
					}
				}
			case "cache_key":
				a.CacheKeyTemplate = h.RemainingArgs()[0]
			case "timeout":
				d, _ := caddy.ParseDuration(h.RemainingArgs()[0])
				a.Timeout = caddy.Duration(d)
			case "method":
				a.RequestMethod = h.RemainingArgs()[0]
			}
		}
	}
	return a, nil
}
