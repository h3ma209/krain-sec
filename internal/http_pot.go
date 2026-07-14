package internal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"krain-sec/internal/honeytoken"
	"krain-sec/internal/store"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/golang/glog"
)

type HTTPClient struct {
	ip string
	id int
}

var JWT_SECRET_KEY = []byte("honeypot")

type contextKey string

const authTokenKey contextKey = "auth_token"

type UserLoginRequest struct {
	Username string `json="username"`
	Password string `json="password"`
}

var HTTPClientList []HTTPClient

func StartHTTPServer(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", withMiddleware(landingPage, logIPMiddleware))
	mux.HandleFunc("/robots.txt", withMiddleware(robotsTxtPage, logIPMiddleware))
	mux.HandleFunc("/sitemap.xml", withMiddleware(sitemapXMLPage, logIPMiddleware))
	mux.HandleFunc("/login", withMiddleware(POSTLoginPage, logIPMiddleware))
	mux.HandleFunc("/dashboard", withMiddleware(dashboardPage, logIPMiddleware, validateJWTTokenMiddleware))
	mux.HandleFunc("/api/telemetry/exfil", withMiddleware(telemetryExfil, logIPMiddleware, validateJWTTokenMiddleware))
	mux.HandleFunc("/t/", withMiddleware(honeytokenBeacon, logIPMiddleware))
	mux.HandleFunc("/downloads/", withMiddleware(honeytokenDownload, logIPMiddleware, validateJWTTokenMiddleware))
	mux.HandleFunc("/logs/", withMiddleware(honeytoken.GzipBomb, logIPMiddleware))
	mux.HandleFunc("/backup/", withMiddleware(honeytoken.InfiniteDirListing, logIPMiddleware))
	mux.HandleFunc("/reports/", withMiddleware(honeytoken.InfiniteDirListing, logIPMiddleware))
	mux.HandleFunc("/archive/", withMiddleware(honeytoken.InfiniteDirListing, logIPMiddleware))
	mux.HandleFunc("/exports/", withMiddleware(honeytoken.InfiniteDirListing, logIPMiddleware))
	s := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 45 * time.Second, // room for 1–9s request lag + response
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		<-ctx.Done()
		glog.Info("shutting down http server")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := s.Shutdown(shutdownCtx); err != nil {
			glog.Info("http shuttdonw err: ", err)
		}
	}()
	glog.Info("http server on 8080")
	return s.ListenAndServe()
}

func extractIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func landingPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	// w.Write([]byte("Hello, World"))

	// ip, ok := r.Context().Value("IP").(string)
	// if !ok {
	// 	ip = extractIP(r)
	// }
	// fmt.Fprintf(w, "hello world\n IP: %s", ip)

	content := readFile("html/index.html")

	w.Write([]byte(content))
}

func robotsTxtPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	// Disallow entries are intentional lures — scanners that honor robots still
	// probe these paths; curious humans click them.
	w.Write([]byte(`# CORP-PROD-SRV05.internal — Krain Security Operations Console
# Do not crawl authenticated or internal surfaces.

User-agent: *
Allow: /
Disallow: /admin/
Disallow: /dashboard
Disallow: /dashboard/
Disallow: /login
Disallow: /api/
Disallow: /api/telemetry/
Disallow: /internal/
Disallow: /reports/
Disallow: /downloads/
Disallow: /downloads/breakglass.txt
Disallow: /downloads/aws-keys.csv
Disallow: /downloads/runbook.txt
Disallow: /t/
Disallow: /logs/
Disallow: /backup/
Disallow: /archive/
Disallow: /exports/
Disallow: /config/
Disallow: /.env
Disallow: /.git/
Disallow: /server-status
Disallow: /phpmyadmin/
Disallow: /wp-admin/

User-agent: Googlebot
Disallow: /dashboard
Disallow: /api/
Disallow: /downloads/
Disallow: /t/
Disallow: /logs/
Disallow: /backup/
Disallow: /archive/
Disallow: /exports/
Disallow: /reports/

Sitemap: /sitemap.xml
`))
}

func sitemapXMLPage(w http.ResponseWriter, r *http.Request) {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}
	host := r.Host
	if host == "" {
		host = HostFQDN
	}
	base := scheme + "://" + host
	lastmod := time.Now().UTC().Format("2006-01-02")

	// Mix of public marketing-ish paths and "accidentally" listed internal
	// surfaces — scanners follow these; several map to honeytoken / tarpit routes.
	body := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://www.sitemaps.org/schemas/sitemap/0.9
        http://www.sitemaps.org/schemas/sitemap/0.9/sitemap.xsd">
  <url>
    <loc>%s/</loc>
    <lastmod>%s</lastmod>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>%s/login</loc>
    <lastmod>%s</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.9</priority>
  </url>
  <url>
    <loc>%s/dashboard</loc>
    <lastmod>%s</lastmod>
    <changefreq>daily</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>%s/reports/executive-summary</loc>
    <lastmod>2026-07-08</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.6</priority>
  </url>
  <url>
    <loc>%s/reports/threat-intel</loc>
    <lastmod>2026-07-08</lastmod>
    <changefreq>daily</changefreq>
    <priority>0.6</priority>
  </url>
  <url>
    <loc>%s/downloads/runbook.txt</loc>
    <lastmod>2026-07-08</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.4</priority>
  </url>
  <url>
    <loc>%s/downloads/breakglass.txt</loc>
    <lastmod>2026-07-01</lastmod>
    <changefreq>yearly</changefreq>
    <priority>0.3</priority>
  </url>
  <url>
    <loc>%s/downloads/aws-keys.csv</loc>
    <lastmod>2026-07-01</lastmod>
    <changefreq>yearly</changefreq>
    <priority>0.2</priority>
  </url>
  <url>
    <loc>%s/api/health</loc>
    <lastmod>%s</lastmod>
    <changefreq>hourly</changefreq>
    <priority>0.5</priority>
  </url>
  <url>
    <loc>%s/api/v1/status</loc>
    <lastmod>%s</lastmod>
    <changefreq>hourly</changefreq>
    <priority>0.5</priority>
  </url>
  <url>
    <loc>%s/internal/ops</loc>
    <lastmod>2026-06-15</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.3</priority>
  </url>
  <url>
    <loc>%s/admin/</loc>
    <lastmod>2026-05-20</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.2</priority>
  </url>
  <url>
    <loc>%s/logs/</loc>
    <lastmod>%s</lastmod>
    <changefreq>daily</changefreq>
    <priority>0.1</priority>
  </url>
  <url>
    <loc>%s/backup/console-export-2026-07.tar.gz</loc>
    <lastmod>2026-07-08</lastmod>
    <changefreq>never</changefreq>
    <priority>0.1</priority>
  </url>
  <url>
    <loc>%s/docs/trust-center</loc>
    <lastmod>2026-06-01</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.7</priority>
  </url>
  <url>
    <loc>%s/docs/api-reference</loc>
    <lastmod>2026-06-01</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.6</priority>
  </url>
  <url>
    <loc>%s/status</loc>
    <lastmod>%s</lastmod>
    <changefreq>hourly</changefreq>
    <priority>0.7</priority>
  </url>
</urlset>
`, base, lastmod,
		base, lastmod,
		base, lastmod,
		base,
		base,
		base,
		base,
		base,
		base, lastmod,
		base, lastmod,
		base,
		base,
		base, lastmod,
		base,
		base,
		base,
		base, lastmod,
	)

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(body))
}

type Middleware func(http.HandlerFunc) http.HandlerFunc

func withMiddleware(handler http.HandlerFunc, middlewares ...Middleware) http.HandlerFunc {
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	return handler
}

func logIPMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)

		HTTPClientList = append(HTTPClientList, HTTPClient{
			ip: ip,
			id: len(HTTPClientList) + 1,
		})

		// Fake backend lag — slows scanners / credential stuffing
		delay := time.Duration(1+rand.IntN(9)) * time.Second
		time.Sleep(delay)

		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		ctx := context.WithValue(r.Context(), "IP", ip)
		next(rw, r.WithContext(ctx))
		store.RecordHTTPRequest(r.Method, r.URL.Path, ip, r.UserAgent(), rw.status)
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func validateJWTTokenMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("auth_token")
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		ctx := context.WithValue(r.Context(), authTokenKey, cookie.Value)
		if err := validateJWTToken(ctx); err != nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		next(w, r.WithContext(ctx))
	}
}
func setIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, "IP", ip)
}

func readFile(dir string) string {
	content, err := os.ReadFile(dir)
	if err != nil {
		glog.Error("Error ", err)
	}
	return string(content)
}

func generateJWTToken() string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "admin",                          // Subject (User ID)
		"exp": time.Now().Add(time.Hour).Unix(), // Expiration time (Unix timestamp)
	})

	tokenString, _ := token.SignedString(JWT_SECRET_KEY)
	fmt.Printf("Token: %s\n\n", tokenString)
	return tokenString
}

func validateJWTToken(ctx context.Context) error {
	tokenString, ok := ctx.Value(authTokenKey).(string)
	if !ok || tokenString == "" {
		return errors.New("missing auth token")
	}

	parsedToken, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return JWT_SECRET_KEY, nil
	})
	if err != nil {
		return err
	}
	if !parsedToken.Valid {
		return errors.New("invalid token")
	}
	return nil
}

func POSTLoginPage(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)
	// request lag applied in logIPMiddleware (1–9s)

	// err := json.NewDecoder(r.Body).Decode(&userLoginReq)
	// if err != nil {
	// 	w.Header().Set("Content-Type", "text/json; charset=utf-8")
	// 	w.WriteHeader(http.StatusUnauthorized)
	// 	w.Write([]byte("Failed to login"))
	// 	return
	// }

	username := r.FormValue("username")
	password := r.FormValue("password")
	srcIP, _ := r.Context().Value("IP").(string)
	if err := checkUsernameAndPassword(w, r, username, password); err != nil {
		store.RecordAuthAttempt("http", srcIP, username, password, false)
		w.Header().Set("Content-Type", "text/json; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Failed to login"))
		return
	}
	store.RecordAuthAttempt("http", srcIP, username, password, true)

	token := generateJWTToken()
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func checkUsernameAndPassword(w http.ResponseWriter, r *http.Request, username, password string) (err error) {

	if r.Method == http.MethodPost {
		if username == "admin" && password == "1234567890" {
			glog.Warning("Login Successeed from IP: ", r.Context().Value("IP"))
			glog.Warning("Adding following IP to watch list")

		} else {
			err = errors.New("Wrong Username Password")
			return err
		}
	} else {
		err = errors.New("Route doesnt exist")
		return err
	}
	return err
}

func dashboardPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(readFile("html/dashboard.html")))
}

func telemetryExfil(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	srcIP, _ := r.Context().Value("IP").(string)
	glog.Warningf("WEBRTC_LEAK src=%s payload=%v", srcIP, payload)

	addr, _ := payload["address"].(string)
	raw, _ := json.Marshal(payload)
	store.RecordWebRTCLeak(srcIP, addr, string(raw))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"ok":true}`))
}
