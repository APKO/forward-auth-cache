package forwardauthcache

import (
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

	cache  *ttlcache.Cache[string, cacheEntry]
	client *http.Client
	logger *zap.Logger
	sf     *singleflight.Group
}

type cacheEntry struct {
	Status  int
	Headers http.Header
}

type resultModel struct {
	Status  int
	Headers http.Header
	Body    []byte
	Success bool
}

func (ForwardAuthCache) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.forward-auth-cache",
		New: func() caddy.Module { return new(ForwardAuthCache) },
	}
}

// Provision налаштовує модуль перед використанням.
func (a *ForwardAuthCache) Provision(ctx caddy.Context) error {
	a.logger = ctx.Logger(a)
	a.sf = new(singleflight.Group)

	// Дефолтні значення
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
		a.CacheKeyTemplate = "auth:{cookie." + a.CookieName + "}:ip:{client_ip}"
	}

	// Ініціалізація кешу
	a.cache = ttlcache.New(
		ttlcache.WithTTL[string, cacheEntry](a.TTL),
		ttlcache.WithCapacity[string, cacheEntry](131072),
	)
	go a.cache.Start()

	// Налаштування HTTP клієнта
	if strings.HasPrefix(a.AuthURL, "h2c://") {
		// Спеціальний транспорт для HTTP/2 Cleartext
		h2tr := &http2.Transport{
			AllowHTTP: true,
			DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
				return net.DialTimeout(network, addr, a.Timeout)
			},
		}
		a.client = &http.Client{Transport: h2tr, Timeout: a.Timeout}
	} else {
		// Стандартний транспорт (підтримує HTTP/1.1 та стандартний H2)
		a.client = &http.Client{
			Timeout: a.Timeout,
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   a.Timeout,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		}
	}

	return nil
}

// Validate перевіряє коректність конфігурації.
func (a *ForwardAuthCache) Validate() error {
	if a.AuthURL == "" {
		return fmt.Errorf("forward-auth-cache: 'auth_url' є обов'язковим")
	}
	if len(a.CopyHeaders) == 0 {
		return fmt.Errorf("forward-auth-cache: 'copy_headers' має містити хоча б один заголовок")
	}
	return nil
}

// Cleanup зупиняє фонові процеси.
func (a *ForwardAuthCache) Cleanup() error {
	if a.cache != nil {
		a.cache.Stop()
	}
	return nil
}

func (a *ForwardAuthCache) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	clientIP := getClientIP(r)
	repl.Set("client_ip", clientIP)

	key := repl.ReplaceAll(a.CacheKeyTemplate, "")

	// 1. Перевірка кешу
	if item := a.cache.Get(key); item != nil {
		entry := item.Value()
		for _, hname := range a.CopyHeaders {
			if v := entry.Headers.Get(hname); v != "" {
				r.Header.Set(hname, v)
			}
		}
		return next.ServeHTTP(w, r)
	}

	// 2. Виконання запиту до сервісу авторизації (із захистом від дублювання)
	v, err, _ := a.sf.Do(key, func() (any, error) {
		reqURL := strings.Replace(a.AuthURL, "h2c://", "http://", 1)

		req, err := http.NewRequestWithContext(r.Context(), a.RequestMethod, reqURL, nil)
		if err != nil {
			return nil, err
		}

		// Копіюємо куки для автентифікації
		for _, c := range r.Cookies() {
			req.AddCookie(c)
		}

		// Передаємо кастомні заголовки (наприклад, X-Original-URI)
		for name, val := range a.PassHeaders {
			req.Header.Set(name, repl.ReplaceAll(val, ""))
		}

		resp, err := a.client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		isSuccess := resp.StatusCode >= 200 && resp.StatusCode < 300

		// Читаємо тіло лише у разі помилки (макс 16KB для захисту пам'яті)
		var body []byte
		if !isSuccess {
			body, _ = io.ReadAll(io.LimitReader(resp.Body, 16384))
		}

		result := resultModel{
			Status:  resp.StatusCode,
			Headers: resp.Header.Clone(),
			Body:    body,
			Success: isSuccess,
		}

		if isSuccess {
			a.cache.Set(key, cacheEntry{
				Status:  resp.StatusCode,
				Headers: result.Headers,
			}, ttlcache.DefaultTTL)
		}

		return result, nil
	})

	if err != nil {
		a.logger.Error("auth request failed", zap.Error(err), zap.String("key", key))
		return caddyhttp.Error(http.StatusBadGateway, err)
	}

	result := v.(resultModel)

	if !result.Success {
		// Повертаємо помилку авторизації клієнту
		maps.Copy(w.Header(), result.Headers)
		w.WriteHeader(result.Status)
		w.Write(result.Body)
		return nil
	}

	// Успіх: додаємо заголовки в оригінальний запит
	for _, hname := range a.CopyHeaders {
		if v := result.Headers.Get(hname); v != "" {
			r.Header.Set(hname, v)
		}
	}

	return next.ServeHTTP(w, r)
}

func getClientIP(r *http.Request) string {
	for _, h := range []string{"True-Client-IP", "X-Real-IP"} {
		if ip := r.Header.Get(h); ip != "" {
			return strings.TrimSpace(ip)
		}
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if host == "" {
		return r.RemoteAddr
	}
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
			default:
				return d.Errf("unknown directive: %s", d.Val())
			}
		}
	}
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var a ForwardAuthCache
	return &a, a.UnmarshalCaddyfile(h.Dispenser)
}

// Перевірка інтерфейсів
var (
	_ caddy.Provisioner           = (*ForwardAuthCache)(nil)
	_ caddy.Validator             = (*ForwardAuthCache)(nil)
	_ caddy.CleanerUpper          = (*ForwardAuthCache)(nil)
	_ caddyhttp.MiddlewareHandler = (*ForwardAuthCache)(nil)
	_ caddyfile.Unmarshaler       = (*ForwardAuthCache)(nil)
)
