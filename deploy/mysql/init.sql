-- Honeypot telemetry schema for CORP-PROD stack
CREATE DATABASE IF NOT EXISTS krain CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE krain;

CREATE TABLE IF NOT EXISTS auth_attempts (
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
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS http_requests (
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
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS ssh_commands (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  src_ip VARCHAR(64) NOT NULL,
  username VARCHAR(255) NOT NULL,
  command TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_ssh_created (created_at),
  INDEX idx_ssh_src (src_ip)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS honeytoken_hits (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  token_id VARCHAR(64) NOT NULL,
  kind VARCHAR(32) NOT NULL,
  src_ip VARCHAR(64) NOT NULL,
  detail VARCHAR(512) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_ht_created (created_at),
  INDEX idx_ht_token (token_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS webrtc_leaks (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  src_ip VARCHAR(64) NOT NULL,
  address VARCHAR(128) NULL,
  payload TEXT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_webrtc_created (created_at),
  INDEX idx_webrtc_src (src_ip)
) ENGINE=InnoDB;

CREATE USER IF NOT EXISTS 'grafana'@'%' IDENTIFIED BY 'GrafanaRead!ChangeMe';
GRANT SELECT ON krain.* TO 'grafana'@'%';
FLUSH PRIVILEGES;
