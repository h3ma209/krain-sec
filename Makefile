SHELL := /bin/bash

.PHONY: krain prod prod-up prod-down prod-restart prod-logs prod-ps prod-build attack-logs

# Local development (hot reload)
krain:
	mkdir -p logs
	source cmd/krain-sec/.env 2>/dev/null; reflex -r '\.go' -s -- sh -c 'go run cmd/krain-sec/main.go'

# ---------------------------------------------------------------------------
# Production: single honeypot container (HTTP/SSH + MySQL/Grafana decoys)
# ---------------------------------------------------------------------------

prod: prod-up

prod-up:
	@command -v docker >/dev/null || { echo "error: docker not found"; exit 1; }
	@docker compose version >/dev/null 2>&1 || { echo "error: docker compose not found"; exit 1; }
	@if [ ! -f .env ]; then \
		echo "==> creating .env from .env.example"; \
		cp .env.example .env; \
		echo "==> edit .env (HONEYTOKEN_BASE_URL) before exposing"; \
	fi
	@mkdir -p logs && chmod 777 logs
	@echo "==> building and starting honeypot"
	docker compose --env-file .env up -d --build
	@echo ""
	@echo "Honeypot is up:"
	@echo "  HTTP console     http://127.0.0.1:8080"
	@echo "  SSH decoy        ssh admin@127.0.0.1"
	@echo "  MySQL decoy      127.0.0.1:3306  (handshake only — auth always fails)"
	@echo "  Grafana decoy    http://127.0.0.1:3000  (looks real — login never works)"
	@echo "  Local logs       ./logs/  (events-YYYY-MM-DD.jsonl …, purge >7d)"
	@echo ""
	@echo "Useful:  make prod-ps | make prod-logs | make prod-down | make attack-logs"

prod-build:
	@if [ ! -f .env ]; then cp .env.example .env; fi
	docker compose --env-file .env build

prod-down:
	docker compose --env-file .env down

prod-restart: prod-down prod-up

prod-logs:
	docker compose --env-file .env logs -f --tail=200

prod-ps:
	docker compose --env-file .env ps

# Tail attack event files on the host (JSONL)
attack-logs:
	@mkdir -p logs
	@day=$$(date -u +%Y-%m-%d); \
	f="logs/events-$${day}.jsonl"; \
	touch "$$f"; \
	echo "==> $$f (Ctrl-C to stop)"; \
	tail -f "$$f"
