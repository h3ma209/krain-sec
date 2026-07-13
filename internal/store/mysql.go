package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/golang/glog"
)

var (
	db   *sql.DB
	mu   sync.RWMutex
	once sync.Once
)

// InitFromEnv opens MySQL using MYSQL_* env vars.
// No-op when MYSQL_HOST and MYSQL_DSN are unset (local dev without Compose).
func InitFromEnv() error {
	var initErr error
	once.Do(func() {
		dsn := os.Getenv("MYSQL_DSN")
		if dsn == "" {
			host := os.Getenv("MYSQL_HOST")
			if host == "" {
				glog.Info("mysql store: MYSQL_HOST not set — telemetry stays in logs only")
				return
			}
			port := envOr("MYSQL_PORT", "3306")
			user := envOr("MYSQL_USER", "krain")
			pass := envOr("MYSQL_PASSWORD", "CorpApp!ChangeMe")
			name := envOr("MYSQL_DATABASE", "krain")
			dsn = fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&charset=utf8mb4&loc=UTC",
				user, pass, host, port, name)
		}

		conn, err := sql.Open("mysql", dsn)
		if err != nil {
			initErr = err
			return
		}
		conn.SetMaxOpenConns(10)
		conn.SetMaxIdleConns(5)
		conn.SetConnMaxLifetime(5 * time.Minute)

		deadline := time.Now().Add(60 * time.Second)
		for {
			if err := conn.Ping(); err == nil {
				break
			} else if time.Now().After(deadline) {
				_ = conn.Close()
				initErr = fmt.Errorf("mysql ping: %w", err)
				return
			}
			time.Sleep(2 * time.Second)
		}

		mu.Lock()
		db = conn
		mu.Unlock()

		if err := ensureSchema(conn); err != nil {
			_ = conn.Close()
			mu.Lock()
			db = nil
			mu.Unlock()
			initErr = err
			return
		}
		glog.Info("mysql store: connected")
	})
	return initErr
}

func ensureSchema(conn *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS auth_attempts (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  service VARCHAR(32) NOT NULL,
  src_ip VARCHAR(64) NOT NULL,
  username VARCHAR(255) NOT NULL,
  password VARCHAR(255) NULL,
  success TINYINT(1) NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_auth_created (created_at),
  INDEX idx_auth_src (src_ip),
  INDEX idx_auth_service (service)
) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS http_requests (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  method VARCHAR(16) NOT NULL,
  path VARCHAR(512) NOT NULL,
  src_ip VARCHAR(64) NOT NULL,
  user_agent VARCHAR(512) NULL,
  status_code INT NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_http_created (created_at),
  INDEX idx_http_src (src_ip),
  INDEX idx_http_path (path(191))
) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS ssh_commands (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  src_ip VARCHAR(64) NOT NULL,
  username VARCHAR(255) NOT NULL,
  command TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_ssh_created (created_at),
  INDEX idx_ssh_src (src_ip)
) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS honeytoken_hits (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  token_id VARCHAR(64) NOT NULL,
  kind VARCHAR(32) NOT NULL,
  src_ip VARCHAR(64) NOT NULL,
  detail VARCHAR(512) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_ht_created (created_at),
  INDEX idx_ht_token (token_id)
) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS webrtc_leaks (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  src_ip VARCHAR(64) NOT NULL,
  address VARCHAR(128) NULL,
  payload TEXT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_webrtc_created (created_at),
  INDEX idx_webrtc_src (src_ip)
) ENGINE=InnoDB`,
	}
	for _, s := range stmts {
		if _, err := conn.Exec(s); err != nil {
			return fmt.Errorf("ensure schema: %w", err)
		}
	}
	return nil
}

func Close() {
	mu.Lock()
	defer mu.Unlock()
	if db != nil {
		_ = db.Close()
		db = nil
	}
}

func ready() *sql.DB {
	mu.RLock()
	defer mu.RUnlock()
	return db
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func goInsert(query string, args ...any) {
	conn := ready()
	if conn == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := conn.ExecContext(ctx, query, args...); err != nil {
			glog.Warningf("mysql insert failed: %v", err)
		}
	}()
}

func RecordAuthAttempt(service, srcIP, username, password string, success bool) {
	ok := 0
	if success {
		ok = 1
	}
	goInsert(
		`INSERT INTO auth_attempts (service, src_ip, username, password, success) VALUES (?, ?, ?, ?, ?)`,
		service, srcIP, username, password, ok,
	)
}

func RecordSSHCommand(srcIP, username, command string) {
	goInsert(
		`INSERT INTO ssh_commands (src_ip, username, command) VALUES (?, ?, ?)`,
		srcIP, username, command,
	)
}

func RecordHoneytokenHit(tokenID, kind, srcIP, detail string) {
	goInsert(
		`INSERT INTO honeytoken_hits (token_id, kind, src_ip, detail) VALUES (?, ?, ?, ?)`,
		tokenID, kind, srcIP, detail,
	)
}

func RecordHTTPRequest(method, path, srcIP, userAgent string, status int) {
	goInsert(
		`INSERT INTO http_requests (method, path, src_ip, user_agent, status_code) VALUES (?, ?, ?, ?, ?)`,
		method, path, srcIP, truncate(userAgent, 512), status,
	)
}

func RecordWebRTCLeak(srcIP, address, payload string) {
	goInsert(
		`INSERT INTO webrtc_leaks (src_ip, address, payload) VALUES (?, ?, ?)`,
		srcIP, address, truncate(payload, 2048),
	)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
