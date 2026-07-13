-- Honeypot telemetry / decoy schema for CORP-PROD stack
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
  INDEX idx_auth_src (src_ip)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS ssh_commands (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  src_ip VARCHAR(64) NOT NULL,
  username VARCHAR(255) NOT NULL,
  command TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_ssh_created (created_at)
) ENGINE=InnoDB;

CREATE USER IF NOT EXISTS 'grafana'@'%' IDENTIFIED BY 'GrafanaRead!ChangeMe';
GRANT SELECT ON krain.* TO 'grafana'@'%';
FLUSH PRIVILEGES;
