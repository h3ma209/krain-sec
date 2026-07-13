SHELL := /bin/bash

.PHONY: krain prod prod-up prod-down prod-restart prod-logs prod-ps prod-build

# Local development (hot reload)
krain:
	source cmd/krain-sec/.env && reflex -r '\.go' -s -- sh -c 'go run cmd/krain-sec/main.go'

# ---------------------------------------------------------------------------
# Production stack: honeypot + MySQL + Grafana
# ---------------------------------------------------------------------------

prod: prod-up

prod-up:
	@command -v docker >/dev/null || { echo "error: docker not found"; exit 1; }
	@docker compose version >/dev/null 2>&1 || { echo "error: docker compose not found"; exit 1; }
	@if [ ! -f .env ]; then \
		echo "==> creating .env from .env.example"; \
		cp .env.example .env; \
		echo "==> edit .env before exposing this host (passwords, HONEYTOKEN_BASE_URL)"; \
	fi
	@echo "==> building and starting production stack"
	docker compose --env-file .env up -d --build
	@echo ""
	@echo "Production stack is up:"
	@echo "  HTTP honeypot   http://127.0.0.1:8080"
	@echo "  SSH honeypot    ssh -p 2222 admin@127.0.0.1"
	@echo "  Grafana         http://127.0.0.1:3000"
	@echo "  MySQL           127.0.0.1:3306"
	@echo ""
	@echo "Useful:  make prod-ps | make prod-logs | make prod-down"

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
