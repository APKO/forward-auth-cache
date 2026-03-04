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
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jellydator/ttlcache/v3"
	"go.uber.org/zap"
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
	cookiePrefix string
	logger       *zap.Logger
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
	if a.CookieName == "" {
		return fmt.Errorf("forward-auth-cache: 'cookie' is required")
	}
	if len(a.CopyHeaders) == 0 {
		return fmt.Errorf("forward-auth-cache: 'copy_headers' is required (at least one)")
	}

	// Дефолтні значення для опціональних полів
	if a.TTL == 0 {
		a.TTL = 1 * time.Minute
	}
	if a.CacheKeyTemplate == "" {
		a.CacheKeyTemplate = "auth:{cookie.__Secure_auth_token}:ip:{remote_host}"
	}
	if a.Timeout == 0 {
		a.Timeout = 3 * time.Second
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
		ttlcache.WithCapacity[string, cacheEntry](131072),
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

	a.logger = ctx.Logger(a)

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

	a.logger.Debug("forward-auth-cache request",
		zap.String("path", r.URL.Path),
		zap.String("method", r.Method),
		zap.String("cache_key", key),
		zap.Bool("has_token", token != ""),
	)

	// Кеш хіт
	if item := a.cache.Get(key); item != nil {
		entry := item.Value()

		a.logger.Debug("cache hit",
			zap.String("key", key),
			zap.Int("status", entry.Status),
		)

		if entry.Status == http.StatusOK || entry.Status == http.StatusNoContent {
			for _, hname := range a.CopyHeaders {
				if v := entry.Headers.Get(hname); v != "" {
					r.Header.Set(hname, v)
					a.logger.Debug("set header from cache",
						zap.String("header", hname),
						zap.String("value", v),
					)
				}
			}
			return next.ServeHTTP(w, r)
		}

		// помилка з кешу (без тіла)
		h := w.Header()
		maps.Copy(h, entry.Headers)
		w.WriteHeader(entry.Status)

		a.logger.Debug("cache hit → error response",
			zap.Int("status", entry.Status),
		)
		return nil
	}

	// Кеш промах
	a.logger.Debug("cache miss", zap.String("key", key))

	u, err := url.Parse(a.AuthURL)
	if err != nil {
		a.logger.Error("invalid auth_url", zap.Error(err))
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	reqURL := a.AuthURL
	reqHost := u.Host
	if u.Scheme == "h2c" {
		reqURL = "http://" + u.Host + u.RequestURI()
	}

	req, err := http.NewRequestWithContext(r.Context(), a.RequestMethod, reqURL, nil)
	if err != nil {
		a.logger.Error("failed to create auth request", zap.Error(err))
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	req.Header.Set("Cookie", a.cookiePrefix+token)
	req.Host = reqHost

	for name, val := range a.PassHeaders {
		req.Header.Set(name, repl.ReplaceAll(val, ""))
	}

	a.logger.Debug("sending auth request",
		zap.String("url", reqURL),
		zap.String("method", req.Method),
	)

	resp, err := a.client.Do(req)
	if err != nil {
		a.logger.Error("auth request failed", zap.Error(err))
		return caddyhttp.Error(http.StatusBadGateway, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		a.logger.Error("failed to read auth body", zap.Error(err))
		return caddyhttp.Error(http.StatusBadGateway, err)
	}

	// Кешуємо ТІЛЬКИ 200 та 204
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		entry := cacheEntry{
			Status:  resp.StatusCode,
			Headers: resp.Header.Clone(),
		}
		a.cache.Set(key, entry, ttlcache.DefaultTTL)

		a.logger.Debug("cached successful response",
			zap.String("key", key),
			zap.Int("status", resp.StatusCode),
		)
	} else {
		a.logger.Debug("upstream error - not cached",
			zap.Int("status", resp.StatusCode),
			zap.Int("body_size", len(body)),
		)
	}

	// Якщо НЕ 200 і НЕ 204 — повертаємо повну відповідь клієнту
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		maps.Copy(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		if len(body) > 0 {
			w.Write(body)
		}
		a.logger.Debug("returned error from upstream",
			zap.Int("status", resp.StatusCode),
			zap.Int("body_size", len(body)),
		)
		return nil
	}

	// Успішна авторизація
	for _, hname := range a.CopyHeaders {
		if v := resp.Header.Get(hname); v != "" {
			r.Header.Set(hname, v)
			a.logger.Debug("set header to downstream request",
				zap.String("header", hname),
				zap.String("value", v),
			)
		}
	}

	return next.ServeHTTP(w, r)
}

func (a *ForwardAuthCache) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	a.PassHeaders = make(map[string]string, 8)

	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "auth_url":
				if !d.Args(&a.AuthURL) {
					return d.ArgErr()
				}

			case "ttl":
				if !d.Args() {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return err
				}
				a.TTL = time.Duration(dur)

			case "cookie":
				if !d.Args(&a.CookieName) {
					return d.ArgErr()
				}

			case "copy_headers":
				a.CopyHeaders = d.RemainingArgs()
				if len(a.CopyHeaders) == 0 {
					return d.Err("copy_headers requires at least one header name")
				}

			case "pass_header":
				var name, value string
				if !d.Args(&name) {
					return d.ArgErr()
				}
				if !d.Args(&value) {
					return d.ArgErr()
				}
				a.PassHeaders[name] = value

			case "cache_key":
				if !d.Args(&a.CacheKeyTemplate) {
					return d.ArgErr()
				}

			case "timeout":
				if !d.Args() {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return err
				}
				a.Timeout = time.Duration(dur)

			case "method":
				if !d.Args(&a.RequestMethod) {
					return d.ArgErr()
				}

			default:
				return d.Errf("unrecognized directive: %s", d.Val())
			}
		}
	}

	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var a ForwardAuthCache
	return &a, a.UnmarshalCaddyfile(h.Dispenser)
}

var (
	_ caddy.Provisioner           = (*ForwardAuthCache)(nil)
	_ caddy.Validator             = (*ForwardAuthCache)(nil)
	_ caddy.CleanerUpper          = (*ForwardAuthCache)(nil)
	_ caddyhttp.MiddlewareHandler = (*ForwardAuthCache)(nil)
	_ caddyfile.Unmarshaler       = (*ForwardAuthCache)(nil)
)
