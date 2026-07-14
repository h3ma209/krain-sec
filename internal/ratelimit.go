package internal

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"krain-sec/internal/store"

	"github.com/golang/glog"
)

type rateBucket struct {
	count   int
	resetAt time.Time
}

type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*rateBucket
}

var httpLimiter = &rateLimiter{buckets: make(map[string]*rateBucket)}

func init() {
	go func() {
		t := time.NewTicker(2 * time.Minute)
		for range t.C {
			httpLimiter.cleanup()
		}
	}()
}

func (l *rateLimiter) cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for k, b := range l.buckets {
		if now.After(b.resetAt) {
			delete(l.buckets, k)
		}
	}
}

// allow returns whether the request is permitted and retry-after seconds.
func (l *rateLimiter) allow(key string, limit int, window time.Duration) (ok bool, remaining int, retryAfter int) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, exists := l.buckets[key]
	if !exists || now.After(b.resetAt) {
		l.buckets[key] = &rateBucket{count: 1, resetAt: now.Add(window)}
		return true, limit - 1, 0
	}
	if b.count >= limit {
		ra := int(b.resetAt.Sub(now).Seconds())
		if ra < 1 {
			ra = 1
		}
		return false, 0, ra
	}
	b.count++
	return true, limit - b.count, 0
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return def
	}
	return n
}

func limitsFor(method, path string) (limit int, window time.Duration) {
	window = time.Minute
	switch {
	case path == "/login" && method == http.MethodPost:
		return envInt("RATE_LIMIT_LOGIN_RPM", 8), window
	case strings.HasPrefix(path, "/backup/") ||
		strings.HasPrefix(path, "/reports/") ||
		strings.HasPrefix(path, "/archive/") ||
		strings.HasPrefix(path, "/exports/") ||
		strings.HasPrefix(path, "/logs/"):
		return envInt("RATE_LIMIT_TRAP_RPM", 20), window
	case strings.HasPrefix(path, "/api/telemetry/") || strings.HasPrefix(path, "/t/"):
		return envInt("RATE_LIMIT_TELEMETRY_RPM", 60), window
	default:
		return envInt("RATE_LIMIT_RPM", 40), window
	}
}

func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)
		limit, window := limitsFor(r.Method, r.URL.Path)
		key := ip + "|" + limitBucket(r.Method, r.URL.Path)

		ok, remaining, retryAfter := httpLimiter.allow(key, limit, window)
		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit))
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
		w.Header().Set("X-RateLimit-Policy", fmt.Sprintf("%d;w=%d", limit, int(window.Seconds())))

		if !ok {
			glog.Warningf("RATE_LIMIT ip=%s method=%s path=%s retry_after=%d",
				ip, r.Method, r.URL.Path, retryAfter)
			store.RecordHTTPRequest(r.Method, r.URL.Path, ip, r.UserAgent(), http.StatusTooManyRequests)
			writeRateLimitResponse(w, r, limit, retryAfter)
			return
		}

		next(w, r)
	}
}

func limitBucket(method, path string) string {
	switch {
	case path == "/login" && method == http.MethodPost:
		return "login"
	case strings.HasPrefix(path, "/backup/") ||
		strings.HasPrefix(path, "/reports/") ||
		strings.HasPrefix(path, "/archive/") ||
		strings.HasPrefix(path, "/exports/") ||
		strings.HasPrefix(path, "/logs/"):
		return "trap"
	case strings.HasPrefix(path, "/api/telemetry/") || strings.HasPrefix(path, "/t/"):
		return "telemetry"
	default:
		return "default"
	}
}

func writeRateLimitResponse(w http.ResponseWriter, r *http.Request, limit, retryAfter int) {
	w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	w.Header().Set("X-RateLimit-Remaining", "0")

	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "text/html") && !strings.Contains(accept, "application/json") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Aetheris Security — Too Many Requests</title>
  <style>
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0b1220;color:#e2e8f0;
      display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
    .box{max-width:420px;padding:2rem;border:1px solid #243044;border-radius:10px;background:#111827}
    h1{font-size:1.25rem;margin:0 0 .5rem;color:#f8fafc}
    p{color:#94a3b8;font-size:.9rem;line-height:1.5;margin:.5rem 0}
    code{color:#93c5fd}
  </style>
</head>
<body>
  <div class="box">
    <h1>429 — Rate limit exceeded</h1>
    <p>Your client exceeded the allowed request rate for this tenant
      (<code>CORP-PROD-TENANT-01</code>).</p>
    <p>Limit: <code>%d</code> requests / minute.
      Retry after <code>%d</code> seconds.</p>
    <p>If you believe this is an error, contact
      <code>soc-ops@aetheris.security</code>.</p>
  </div>
</body>
</html>`, limit, retryAfter)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusTooManyRequests)
	fmt.Fprintf(w, `{
  "error": "rate_limit_exceeded",
  "message": "Too many requests from this client. Contact soc-ops@aetheris.security if this persists.",
  "tenant": "CORP-PROD-TENANT-01",
  "limit_per_minute": %d,
  "retry_after_seconds": %d
}
`, limit, retryAfter)
}
