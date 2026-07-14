package internal

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"strings"
	"time"

	"krain-sec/internal/store"

	"github.com/golang/glog"
)

// StartGrafanaDecoy serves a convincing Grafana-like UI on :3000.
// Health looks OK; login always fails. No real dashboards or data.
func StartGrafanaDecoy(ctx context.Context) error {
	api := http.NewServeMux()
	api.HandleFunc("/api/health", grafanaHealth)
	api.HandleFunc("/api/login", grafanaAPILogin)
	api.HandleFunc("/api/dashboards/home", grafanaNotAuth)
	api.HandleFunc("/api/search", grafanaNotAuth)
	api.HandleFunc("/api/org", grafanaNotAuth)
	api.HandleFunc("/api/user", grafanaNotAuth)
	api.HandleFunc("/api/datasources", grafanaNotAuth)
	api.HandleFunc("/api/frontend/settings", grafanaFrontendSettings)

	root := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			api.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/login" {
			grafanaLogin(w, r)
			return
		}
		grafanaIndex(w, r)
	})

	s := &http.Server{
		Addr:         ":3000",
		Handler:      grafanaLag(root),
		ReadTimeout:  20 * time.Second,
		WriteTimeout: 45 * time.Second,
		IdleTimeout:  60 * time.Second,
		BaseContext:  func(net.Listener) context.Context { return ctx },
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Shutdown(shutdownCtx)
	}()

	glog.Info("grafana decoy listening on :3000")
	if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("grafana decoy: %w", err)
	}
	return nil
}

func grafanaLag(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if ip == "" {
			ip = r.RemoteAddr
		}
		glog.Infof("grafana decoy %s %s from %s", r.Method, r.URL.Path, ip)
		store.RecordDecoy("grafana", ip, r.Method+" "+r.URL.Path)
		time.Sleep(time.Duration(400+rand.IntN(1600)) * time.Millisecond)
		next.ServeHTTP(w, r)
	})
}

func grafanaHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"commit":"598e0338d5","database":"ok","version":"11.5.2"}`))
}

func grafanaFrontendSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"defaultDatasource":"","datasources":{},"panels":{},"appUrl":"/","appSubUrl":"","auth":{"disableLoginForm":false,"oauthAutoLogin":false},"buildInfo":{"version":"11.5.2","edition":"Open Source"}}`))
}

func grafanaNotAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(`{"message":"Unauthorized","statusCode":401}`))
}

func grafanaAPILogin(w http.ResponseWriter, r *http.Request) {
	time.Sleep(time.Duration(1200+rand.IntN(2800)) * time.Millisecond)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(`{"message":"Invalid username or password","messageId":"password-auth.failed","statusCode":401}`))
}

func grafanaLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		grafanaAPILogin(w, r)
		return
	}
	grafanaIndex(w, r)
}

func grafanaIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(grafanaLoginHTML))
}

const grafanaLoginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Grafana</title>
  <style>
    :root { --bg:#111217; --panel:#181b1f; --border:#2c3235; --text:#d8d9da; --muted:#7b8087; --accent:#ff780a; --input:#0b0c0e; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { min-height: 100vh; display:flex; align-items:center; justify-content:center;
      font-family: Inter, Roboto, "Helvetica Neue", Arial, sans-serif; background: var(--bg); color: var(--text); }
    .wrap { width: 100%; max-width: 380px; padding: 1.5rem; }
    .brand { display:flex; align-items:center; gap:.75rem; margin-bottom: 1.75rem; justify-content:center; }
    .logo { width: 36px; height: 36px; border-radius: 4px; background: linear-gradient(135deg,#f90,#f60); }
    .brand h1 { font-size: 1.35rem; font-weight: 600; letter-spacing: -0.02em; }
    .card { background: var(--panel); border: 1px solid var(--border); border-radius: 4px; padding: 1.5rem; }
    label { display:block; font-size: .75rem; color: var(--muted); margin-bottom: .35rem; }
    input { width:100%; padding: .65rem .75rem; margin-bottom: 1rem; color: var(--text);
      background: var(--input); border: 1px solid var(--border); border-radius: 3px; outline: none; font-size: .9rem; }
    input:focus { border-color: var(--accent); }
    button { width:100%; padding: .7rem; border: none; border-radius: 3px; font-weight: 600; font-size: .9rem;
      color: #111; background: var(--accent); cursor: pointer; }
    button:hover { filter: brightness(1.05); }
    .err { display:none; margin-bottom: 1rem; padding: .6rem .75rem; font-size: .8rem;
      color: #ff7383; background: #2d1215; border: 1px solid #5c1a22; border-radius: 3px; }
    .err.show { display:block; }
    .foot { margin-top: 1.25rem; text-align:center; font-size: .7rem; color: var(--muted); }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="brand">
      <div class="logo"></div>
      <h1>Grafana</h1>
    </div>
    <div class="card">
      <div id="err" class="err">Invalid username or password</div>
      <form id="f" method="post" action="/api/login">
        <label for="user">Email or username</label>
        <input id="user" name="user" autocomplete="username" required />
        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required />
        <button type="submit">Log in</button>
      </form>
    </div>
    <p class="foot">Grafana v11.5.2 &copy; Grafana Labs</p>
  </div>
  <script>
    document.getElementById("f").addEventListener("submit", async function (e) {
      e.preventDefault();
      var btn = e.target.querySelector("button");
      btn.disabled = true; btn.textContent = "Logging in…";
      try {
        var res = await fetch("/api/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            user: document.getElementById("user").value,
            password: document.getElementById("password").value
          })
        });
        if (!res.ok) document.getElementById("err").classList.add("show");
      } catch (err) {
        document.getElementById("err").classList.add("show");
      }
      btn.disabled = false; btn.textContent = "Log in";
    });
  </script>
</body>
</html>
`
