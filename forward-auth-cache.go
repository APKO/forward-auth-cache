package forwardauthcache

import (
	"crypto/tls"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jellydator/ttlcache/v3"
	"golang.org/x/net/http2"
)

func init() {
	caddy.RegisterModule(ForwardAuthCache{})
	httpcaddyfile.RegisterHandlerDirective("forward-auth-cache", parseCaddyfile)
}

type ForwardAuthCache struct {
	AuthURL          string            `json:"auth_url,omitempty"`
	TTL              time.Duration     `json:"ttl,omitempty"`
	CookieName       string            `json:"cookie_name,omitempty"`
	CopyHeaders      []string          `json:"copy_headers,omitempty"`
	PassHeaders      map[string]string `json:"pass_headers,omitempty"`
	CacheKeyTemplate string            `json:"cache_key,omitempty"`
	Timeout          time.Duration     `json:"timeout,omitempty"`
	RequestMethod    string            `json:"method,omitempty"`

	cache        *ttlcache.Cache[string, cacheEntry]
	client       *http.Client
	cookiePrefix string // оптимізація — префікс "CookieName="
}

type cacheEntry struct {
	Status  int
	Headers http.Header
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
		a.TTL = time.Duration(1 * time.Minute)
	}
	if a.CookieName == "" {
		return fmt.Errorf("forward-auth-cache: 'cookie' is required")
	}
	if len(a.CopyHeaders) == 0 {
		return fmt.Errorf("forward-auth-cache: 'copy_headers' is required (at least one)")
	}
	if a.CacheKeyTemplate == "" {
		a.CacheKeyTemplate = "auth:{cookie.__Secure_auth_token}:ip:{remote_host}"
	}
	if a.Timeout == 0 {
		a.Timeout = time.Duration(3 * time.Second)
	}
	if a.RequestMethod == "" {
		a.RequestMethod = http.MethodGet
	}
	return nil
}

func (a *ForwardAuthCache) Provision(ctx caddy.Context) error {
	a.PassHeaders = make(map[string]string, 10)

	a.cache = ttlcache.New(
		ttlcache.WithTTL[string, cacheEntry](a.TTL),
		ttlcache.WithCapacity[string, cacheEntry](131072), // ~128k слотів
	)

	go a.cache.Start()

	transport := &http2.Transport{
		AllowHTTP:       true,
		ReadIdleTimeout: 30 * time.Second,
		PingTimeout:     15 * time.Second,
		DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			return net.DialTimeout(network, addr, time.Duration(a.Timeout))
		},
	}

	a.client = &http.Client{
		Transport: transport,
		Timeout:   time.Duration(a.Timeout),
	}

	a.cookiePrefix = a.CookieName + "="

	return nil
}

func (a *ForwardAuthCache) Cleanup() error {
	if a.cache != nil {
		a.cache.Stop()
	}
	return nil
}

func (a *ForwardAuthCache) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	token := ""
	if c, _ := r.Cookie(a.CookieName); c != nil {
		token = c.Value
	}
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}
	var key string
	if a.CacheKeyTemplate == "auth:{cookie.__Secure_auth_token}:ip:{remote_host}" {
		key = "auth:" + token + ":ip:" + clientIP
	} else {
		key = repl.ReplaceAll(a.CacheKeyTemplate, "")
	}

	if item := a.cache.Get(key); item != nil {
		entry := item.Value()

		if entry.Status != http.StatusOK && entry.Status != http.StatusNoContent {
			h := w.Header()
			maps.Copy(h, entry.Headers)
			w.WriteHeader(entry.Status)
			// Тут тіла немає, бо ми його не кешуємо
			return nil
		}

		for _, hname := range a.CopyHeaders {
			if v := entry.Headers.Get(hname); v != "" {
				r.Header.Set(hname, v)
			}
		}
		return next.ServeHTTP(w, r)
	}

	u, _ := url.Parse(a.AuthURL)
	reqURL := a.AuthURL
	reqHost := u.Host
	if u.Scheme == "h2c" {
		reqURL = "http://" + u.Host + u.RequestURI()
	}

	req, err := http.NewRequestWithContext(r.Context(), a.RequestMethod, reqURL, nil)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	req.Header.Set("Cookie", a.cookiePrefix+token)
	req.Host = reqHost

	for name, val := range a.PassHeaders {
		req.Header.Set(name, repl.ReplaceAll(val, ""))
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return caddyhttp.Error(http.StatusBadGateway, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return caddyhttp.Error(http.StatusBadGateway, err)
	}

	entry := cacheEntry{
		Status:  resp.StatusCode,
		Headers: resp.Header.Clone(),
	}

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		a.cache.Set(key, entry, ttlcache.DefaultTTL)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		maps.Copy(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		if len(body) > 0 {
			w.Write(body)
		}
		return nil
	}

	for _, hname := range a.CopyHeaders {
		if v := resp.Header.Get(hname); v != "" {
			r.Header.Set(hname, v)
		}
	}

	return next.ServeHTTP(w, r)
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	a := new(ForwardAuthCache)
	a.PassHeaders = make(map[string]string, 8)

	for h.Next() {
		for h.NextBlock(0) {
			switch h.Val() {
			case "auth_url":
				a.AuthURL = h.RemainingArgs()[0]
			case "ttl":
				d, err := caddy.ParseDuration(h.RemainingArgs()[0])
				if err != nil {
					return nil, err
				}
				a.TTL = time.Duration(d)
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
				d, err := caddy.ParseDuration(h.RemainingArgs()[0])
				if err != nil {
					return nil, err
				}
				a.Timeout = time.Duration(d)
			case "method":
				a.RequestMethod = h.RemainingArgs()[0]
			}
		}
	}
	return a, nil
}
