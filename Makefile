SHELL := /bin/bash

.PHONY: help dev prod down restart logs ps build attack-logs test

# Default: show commands
help:
	@echo "krain-sec — decoy next to your real website"
	@echo ""
	@echo "  make prod         Build & start honeypot (Docker)"
	@echo "  make down         Stop honeypot"
	@echo "  make restart      Stop then start"
	@echo "  make logs         Follow container logs"
	@echo "  make ps           Container status"
	@echo "  make build        Build image only"
	@echo "  make attack-logs  Tail today's attack events (./logs)"
	@echo "  make test         Run unit tests under ./test"
	@echo "  make dev          Local Go hot-reload (needs reflex)"
	@echo ""
	@echo "Before public use: move real SSH off :22, set HONEYTOKEN_BASE_URL in .env"

# ---------------------------------------------------------------------------
# Deploy (same VPS as your real site)
# ---------------------------------------------------------------------------

prod: _need-docker _env _logs
	@echo "==> starting honeypot"
	docker compose --env-file .env up -d --build
	@echo ""
	@echo "Up. Real site keeps :80/:443. Bait ports:"
	@echo "  Console   http://127.0.0.1:8080"
	@echo "  SSH       ssh admin@127.0.0.1          (port 22 — bait)"
	@echo "  MySQL     127.0.0.1:3306               (decoy)"
	@echo "  Grafana   http://127.0.0.1:3000        (decoy)"
	@echo "  Logs      ./logs/   →  make attack-logs"
	@echo ""
	@echo "Set HONEYTOKEN_BASE_URL to your public bait URL in .env"

down:
	docker compose --env-file .env down

restart: down prod

logs:
	docker compose --env-file .env logs -f --tail=200

ps:
	docker compose --env-file .env ps

build: _env
	docker compose --env-file .env build

attack-logs:
	@mkdir -p logs
	@day=$$(date -u +%Y-%m-%d); \
	echo "==> logs for $${day} UTC"; \
	ls -lh logs/*-$${day}.jsonl 2>/dev/null || echo "(no files yet)"; \
	echo ""; \
	echo "==> following events-$${day}.jsonl (Ctrl-C to stop)"; \
	touch "logs/events-$${day}.jsonl"; \
	tail -f "logs/events-$${day}.jsonl"

# ---------------------------------------------------------------------------
# Local development
# ---------------------------------------------------------------------------

test:
	go test ./test/...

dev:
	mkdir -p logs
	source cmd/krain-sec/.env 2>/dev/null; reflex -r '\.go' -s -- sh -c 'go run ./cmd/krain-sec'

# aliases kept for older docs/muscle memory
krain: dev
prod-up: prod
prod-down: down
prod-restart: restart
prod-logs: logs
prod-ps: ps
prod-build: build

.PHONY: krain prod-up prod-down prod-restart prod-logs prod-ps prod-build

# ---------------------------------------------------------------------------
# internals
# ---------------------------------------------------------------------------

_need-docker:
	@command -v docker >/dev/null || { echo "error: docker not found"; exit 1; }
	@docker compose version >/dev/null 2>&1 || { echo "error: docker compose not found"; exit 1; }

_env:
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "==> created .env from .env.example — edit HONEYTOKEN_BASE_URL before exposing"; \
	fi

_logs:
	@mkdir -p logs && chmod 777 logs
