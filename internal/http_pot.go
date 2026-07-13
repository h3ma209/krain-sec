package internal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	mux.HandleFunc("/login", withMiddleware(POSTLoginPage, logIPMiddleware))
	mux.HandleFunc("/dashboard", withMiddleware(dashboardPage, logIPMiddleware, validateJWTTokenMiddleware))
	mux.HandleFunc("/api/telemetry/exfil", withMiddleware(telemetryExfil, logIPMiddleware, validateJWTTokenMiddleware))
	mux.HandleFunc("/t/", withMiddleware(honeytokenBeacon, logIPMiddleware))
	mux.HandleFunc("/downloads/", withMiddleware(honeytokenDownload, logIPMiddleware, validateJWTTokenMiddleware))
	s := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  10 * time.Second,
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
	w.Write([]byte(`User-agent: *
Disallow: /admin/
Disallow: /dashboard/
Disallow: /api/
Disallow: /internal/
Disallow: /reports/

Sitemap: /sitemap.xml
`))
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

		fmt.Sprint("[HTTP] - %s %s\n", ip, r.URL.Path)
		ctx := context.WithValue(r.Context(), "IP", ip)
		next(w, r.WithContext(ctx))
	}
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
	time.Sleep(3 * time.Second)

	// err := json.NewDecoder(r.Body).Decode(&userLoginReq)
	// if err != nil {
	// 	w.Header().Set("Content-Type", "text/json; charset=utf-8")
	// 	w.WriteHeader(http.StatusUnauthorized)
	// 	w.Write([]byte("Failed to login"))
	// 	return
	// }

	username := r.FormValue("username")
	password := r.FormValue("password")
	if err := checkUsernameAndPassword(w, r, username, password); err != nil {
		w.Header().Set("Content-Type", "text/json; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Failed to login"))
		return
	}

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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"ok":true}`))
}

