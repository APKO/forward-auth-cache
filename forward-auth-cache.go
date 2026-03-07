package forwardauthcache

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jellydator/ttlcache/v3"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/net/http2"
	"golang.org/x/sync/singleflight"
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
	Debug            bool              `json:"debug,omitempty"`
	UserIDHeader     string            `json:"user_id_header,omitempty"`

	cache  *ttlcache.Cache[string, cacheEntry]
	group  *singleflight.Group
	client *http.Client
	logger *zap.Logger
}

type cacheEntry struct {
	Status  int
	Headers map[string]string
	UserID  string
}

func (u cacheEntry) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddInt("status", u.Status)
	enc.AddString("user_id", u.UserID)
	if len(u.Headers) > 0 {
		_ = enc.AddObject("headers", zapcore.ObjectMarshalerFunc(func(hEnc zapcore.ObjectEncoder) error {
			for key, val := range u.Headers {
				hEnc.AddString(key, val)
			}
			return nil
		}))
	}
	return nil
}

type resultModel struct {
	Status  int
	Headers http.Header
	Body    []byte
	Success bool
	UserID  string
}

func (u resultModel) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddInt("status", u.Status)
	enc.AddBool("success", u.Success)
	enc.AddString("user_id", u.UserID)
	if u.Headers != nil {
		_ = enc.AddObject("headers", zapcore.ObjectMarshalerFunc(func(hEnc zapcore.ObjectEncoder) error {
			for key, values := range u.Headers {
				if len(values) > 0 {
					hEnc.AddString(key, values[0])
				}
			}
			return nil
		}))
	}
	return nil
}

func (ForwardAuthCache) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.forward-auth-cache",
		New: func() caddy.Module { return new(ForwardAuthCache) },
	}
}

func (a *ForwardAuthCache) Provision(ctx caddy.Context) error {
	a.logger = ctx.Logger(a)
	a.group = new(singleflight.Group)

	if a.TTL <= 0 {
		a.TTL = 1 * time.Minute
	}
	if a.Timeout <= 0 {
		a.Timeout = 5 * time.Second
	}
	if a.RequestMethod == "" {
		a.RequestMethod = http.MethodGet
	}
	if a.CookieName == "" {
		a.CookieName = "__Secure_auth_token"
	}
	if a.CacheKeyTemplate == "" {
		a.CacheKeyTemplate = "auth:{http.request.cookie." + a.CookieName + "}:ip:{client_ip}"
	}

	a.cache = ttlcache.New(
		ttlcache.WithTTL[string, cacheEntry](a.TTL),
		ttlcache.WithCapacity[string, cacheEntry](131072),
	)
	go a.cache.Start()

	if strings.HasPrefix(a.AuthURL, "h2c://") {
		a.client = &http.Client{
			Transport: &http2.Transport{
				AllowHTTP: true,
				DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
					return net.DialTimeout(network, addr, a.Timeout)
				},
			},
			Timeout: a.Timeout,
		}
	} else {
		a.client = &http.Client{
			Timeout: a.Timeout,
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   a.Timeout,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				ForceAttemptHTTP2: true,
				MaxIdleConns:      1000,
				IdleConnTimeout:   90 * time.Second,
			},
		}
	}
	a.logger.Info("Created Auth Service Success", zap.String("url", a.AuthURL))
	return nil
}

func (a *ForwardAuthCache) Validate() error {
	if a.AuthURL == "" {
		return fmt.Errorf("auth_url is required")
	}
	if len(a.CopyHeaders) == 0 {
		return fmt.Errorf("copy_headers must not be empty")
	}
	return nil
}

func (a *ForwardAuthCache) Cleanup() error {
	if a.cache != nil {
		a.cache.Stop()
	}
	return nil
}

var (
	cacheAuthHeader = http.CanonicalHeaderKey("X-Cache-Auth")
	realIPHeader    = http.CanonicalHeaderKey("X-Real-IP")
)

func (a *ForwardAuthCache) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	start := time.Now()
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	clientIP := getClientIP(r)
	repl.Set("client_ip", clientIP)
	key := repl.ReplaceAll(a.CacheKeyTemplate, "")

	if a.Debug {
		a.logger.Info("auth check started", zap.String("key", key), zap.String("path", r.URL.Path))
	}
	if item := a.cache.Get(key); item != nil {
		entry := item.Value()
		if a.Debug {
			a.logger.Info("cache hit", zap.String("key", key), zap.Object("entry", entry), zap.Duration("latency", time.Since(start)))
		}
		for hname, hval := range entry.Headers {
			r.Header.Set(hname, hval)
		}
		if a.UserIDHeader != "" {
			repl.Set("http.auth.user.id", entry.UserID)
		}
		r.Header.Set(cacheAuthHeader, "HIT")
		return next.ServeHTTP(w, r)
	}

	resInterface, err, shared := a.group.Do(key, func() (any, error) {
		return a.doAuthRequest(r, repl)
	})

	if err != nil {
		a.logger.Error("auth request failed", zap.Error(err), zap.String("key", key))
		return caddyhttp.Error(http.StatusBadGateway, err)
	}

	result := resInterface.(resultModel)

	if a.Debug {
		a.logger.Info("auth service responded",
			zap.Object("result", result),
			zap.Bool("shared", shared),
			zap.Duration("latency", time.Since(start)),
		)
	}

	if result.Success {
		headersToCache := make(map[string]string)
		for _, hname := range a.CopyHeaders {
			if val := result.Headers.Get(hname); val != "" {
				headersToCache[hname] = val
				r.Header.Set(hname, val)
			}
		}

		if a.UserIDHeader != "" {
			repl.Set("http.auth.user.id", result.UserID)
		}

		a.cache.Set(key, cacheEntry{
			Status:  result.Status,
			Headers: headersToCache,
			UserID:  result.UserID,
		}, ttlcache.DefaultTTL)
		r.Header.Set(cacheAuthHeader, "SET")
		return next.ServeHTTP(w, r)
	}

	if a.Debug {
		a.logger.Warn("access denied by auth service", zap.String("key", key), zap.Object("result", result))
	}

	maps.Copy(w.Header(), result.Headers)
	if len(result.Body) > 0 {
		w.WriteHeader(result.Status)
		_, _ = w.Write(result.Body)
		return nil
	}

	return caddyhttp.Error(result.Status, fmt.Errorf("access denied"))
}

func (a *ForwardAuthCache) doAuthRequest(r *http.Request, repl *caddy.Replacer) (resultModel, error) {
	reqURL := strings.Replace(a.AuthURL, "h2c://", "http://", 1)

	ctx, cancel := context.WithTimeout(context.Background(), a.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, a.RequestMethod, reqURL, nil)
	if err != nil {
		return resultModel{}, err
	}

	for _, c := range r.Cookies() {
		req.AddCookie(c)
	}

	for _, hname := range a.CopyHeaders {
		if val := r.Header.Get(hname); val != "" {
			req.Header.Set(hname, val)
		}
	}

	for name, val := range a.PassHeaders {
		if headerVal := repl.ReplaceAll(val, ""); headerVal != "" {
			req.Header.Set(name, headerVal)
		}
	}
	req.Header.Set(realIPHeader, getClientIP(r))

	resp, err := a.client.Do(req)
	if err != nil {
		return resultModel{}, err
	}
	defer resp.Body.Close()

	isSuccess := resp.StatusCode >= 200 && resp.StatusCode < 300
	var body []byte
	var userID string
	if isSuccess {
		if a.UserIDHeader != "" {
			userID = resp.Header.Get(a.UserIDHeader)
			if userID == "" {
				a.logger.Warn("user_id header is empty", zap.String("header", a.UserIDHeader))
			}
		}
		_, _ = io.Copy(io.Discard, resp.Body)
	} else {
		body, _ = io.ReadAll(io.LimitReader(resp.Body, 16384))
	}

	return resultModel{
		Status:  resp.StatusCode,
		Headers: resp.Header.Clone(), // Clone гарантує безпеку даних
		Body:    body,
		Success: isSuccess,
		UserID:  userID,
	}, nil
}

func getClientIP(r *http.Request) string {
	for _, h := range []string{"True-Client-IP", realIPHeader} {
		if ip := r.Header.Get(h); ip != "" {
			return strings.TrimSpace(ip)
		}
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func (a *ForwardAuthCache) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	a.PassHeaders = make(map[string]string)
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "auth_url":
				if !d.Args(&a.AuthURL) {
					return d.ArgErr()
				}
			case "ttl":
				var durStr string
				if !d.Args(&durStr) {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(durStr)
				if err != nil {
					return d.Errf("invalid ttl: %v", err)
				}
				a.TTL = dur
			case "cookie":
				if !d.Args(&a.CookieName) {
					return d.ArgErr()
				}
			case "copy_headers":
				a.CopyHeaders = d.RemainingArgs()
			case "pass_header":
				var k, v string
				if !d.Args(&k, &v) {
					return d.ArgErr()
				}
				a.PassHeaders[k] = v
			case "cache_key":
				if !d.Args(&a.CacheKeyTemplate) {
					return d.ArgErr()
				}
			case "timeout":
				var durStr string
				if !d.Args(&durStr) {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(durStr)
				if err != nil {
					return d.Errf("invalid timeout: %v", err)
				}
				a.Timeout = dur
			case "method":
				if !d.Args(&a.RequestMethod) {
					return d.ArgErr()
				}
			case "debug":
				a.Debug = true
			case "user_id_header":
				if !d.Args(&a.UserIDHeader) {
					return d.ArgErr()
				}
			default:
				return d.Errf("unknown directive: %s", d.Val())
			}
		}
	}
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var a ForwardAuthCache
	err := a.UnmarshalCaddyfile(h.Dispenser)
	return &a, err
}

var (
	_ caddy.Provisioner           = (*ForwardAuthCache)(nil)
	_ caddy.Validator             = (*ForwardAuthCache)(nil)
	_ caddy.CleanerUpper          = (*ForwardAuthCache)(nil)
	_ caddyhttp.MiddlewareHandler = (*ForwardAuthCache)(nil)
	_ caddyfile.Unmarshaler       = (*ForwardAuthCache)(nil)
)
