<p align="center">
  <img src="./icon.png" alt="krain-sec" width="180" />
</p>

<h1 align="center">krain-sec</h1>

<p align="center">
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go&logoColor=white" alt="Go" /></a>
  <a href="./docker-compose.yml"><img src="https://img.shields.io/badge/Docker-Compose-2496ED?style=flat&logo=docker&logoColor=white" alt="Docker" /></a>
  <a href="#status"><img src="https://img.shields.io/badge/status-lab%20%2F%20research-orange" alt="Status" /></a>
  <a href="#license"><img src="https://img.shields.io/badge/license-TBD-lightgrey" alt="License" /></a>
</p>

**High-fidelity deception honeypot** that impersonates an internal corporate security operations console (`CORP-PROD-SRV05.internal` — Krain Threat Detection & Response).

HTTP login + SOC dashboard, SSH admin shell with decoy artifacts, honeytokens, WebRTC leak probe, and crawler lures (`robots.txt` / `sitemap.xml`).

> [!WARNING]
> Deploy only on systems and networks you **own** or are **explicitly authorized** to monitor. For defensive research, SOC training, and controlled deception — not unauthorized collection or entrapment.

---

## Table of contents

- [Features](#features)
- [Who this is for](#who-this-is-for)
- [Who it attracts](#who-it-attracts)
- [Quick start](#quick-start)
- [Default decoy credentials](#default-decoy-credentials)
- [Docker Compose](#docker-compose)
- [Configuration](#configuration)
- [Try the bait](#try-the-bait)
- [Project layout](#project-layout)
- [Safety](#safety)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Features

| Area | Capabilities |
|------|----------------|
| **HTTP** (`:8080`) | Corporate sign-in (WebRTC probe **before** login), JWT dashboard, telemetry API |
| **SSH** (`:22`) | OpenSSH-like banner, fake interactive shell, bash/PS history |
| **Honeytokens** | Break-glass creds, fake AWS keys, SSH key, runbook + `/t/{id}.gif` beacon |
| **Lures** | Juicy `robots.txt` + believable `sitemap.xml` |
| **Tarpit** | `/logs/` gzip bomb for greedy fetchers |
| **Logs** | Local `./logs/*.jsonl` + glog files (Compose bind-mount) |
| **Decoys** | Fake MySQL `:3306` + Grafana `:3000` (look open; never useful) |

---

## Who this is for

| Audience | Why |
|----------|-----|
| Blue teams / SOC | Decoy asset that lights up when scanners or humans poke it |
| Detection engineers | Labeled HTTP/SSH/canary traffic for rules and pipelines |
| Researchers / students | Study deception & attribution without touching real IdP |
| Homelab / purple team | Safe attacker playground on an isolated VLAN |

**Not** a real SSO portal, SIEM, or production auth stack.

---

## Who it attracts

- Internet scanners following `robots.txt` / sitemaps  
- Credential stuffing against the fake console  
- Curious humans downloading “break-glass” / runbook packs  
- Low–mid skill operators diving SSH history and canary files  

Optimized for **noisy, high-volume, and curious** adversaries — not a full APT jail (yet).

---

## Quick start

**Requirements:** [Go 1.25+](https://go.dev/dl/), optional [Docker](https://docs.docker.com/) / [reflex](https://github.com/cespare/reflex)

```bash
git clone https://github.com/h3ma209/krain-sec.git
cd krain-sec
go mod download
go run ./cmd/krain-sec
```

Dev reload:

```bash
make krain   # needs reflex; sources cmd/krain-sec/.env if present
```

| Endpoint | URL |
|----------|-----|
| Login / dashboard | http://127.0.0.1:8080 |
| SSH | `ssh admin@127.0.0.1` |
| MySQL decoy | `127.0.0.1:3306` (handshake + Access denied) |
| Grafana decoy | http://127.0.0.1:3000 (login always fails) |

---

## Default decoy credentials

These are **intentional bait**. Never reuse on real systems.

| Surface | Username | Password |
|---------|----------|----------|
| HTTP | `admin` | `1234567890` |
| SSH | `admin` | `secret123` |

---

## Docker Compose

Single container — HTTP, SSH, MySQL decoy, Grafana decoy:

```bash
cp .env.example .env   # first time — set HONEYTOKEN_BASE_URL
make prod              # build, start, print URLs
```

| Make target | Action |
|-------------|--------|
| `make prod` / `make prod-up` | Build image, create `.env` if missing, start |
| `make prod-ps` | Container status |
| `make prod-logs` | Follow logs |
| `make prod-down` | Stop |
| `make prod-restart` | Down then up |

| Port | What attackers see |
|------|--------------------|
| `8080` | Corporate SOC console |
| `22` | Fake SSH shell |
| `3306` | MySQL 8.4 handshake → always Access denied |
| `3000` | Grafana login + `/api/health` OK → login never works |

No real MySQL/Grafana stack. Decoy ports exist so scanners report “open services.”

### Local attack logs

Host directory `./logs` is mounted at `/app/logs` in the container.

| File | Contents |
|------|----------|
| `events-YYYY-MM-DD.jsonl` | All events for that UTC day |
| `auth-*.jsonl` | Login attempts (HTTP + SSH) |
| `http-*.jsonl` | HTTP requests |
| `ssh-*.jsonl` | Fake-shell commands |
| `honeytoken-*.jsonl` | Canary / beacon hits |
| `webrtc-*.jsonl` | WebRTC exfil payloads |
| `decoy-*.jsonl` | MySQL / Grafana decoy probes |
| `krain-sec.*` | glog process logs |

Files with mtime older than **7 days** are deleted on startup and every hour (`LOG_RETENTION_DAYS`).

```bash
make attack-logs          # tail today's events-*.jsonl
tail -f logs/auth-$(date -u +%Y-%m-%d).jsonl
```

```bash
docker compose down
```

---

## Configuration

| Variable | Purpose | Default |
|----------|---------|---------|
| `LOG_DIR` | Directory for JSONL + glog (Compose uses `/app/logs`) | `logs` |
| `LOG_RETENTION_DAYS` | Delete log files older than N days (mtime) | `7` |
| `HONEYTOKEN_BASE_URL` | Public base for canary beacon links inside planted files | `http://127.0.0.1:8080` |
| `RATE_LIMIT_*` | Per-IP HTTP rate limits | see [`.env.example`](./.env.example) |

---

## Try the bait

```bash
curl -s http://127.0.0.1:8080/robots.txt
curl -s http://127.0.0.1:8080/sitemap.xml | head
curl -sI http://127.0.0.1:8080/t/ht-brk-a7f3c91e.gif   # → HONEYTOKEN_HIT in logs

ssh admin@127.0.0.1
# ls Documents
# cat Documents/VPN_Breakglass_Credentials.txt
```

Log signals to watch: `ssh auth attempt`, `WEBRTC_LEAK`, `HONEYTOKEN_HIT`.

---

## Project layout

```text
krain-sec/
├── cmd/krain-sec/              # Entrypoint
├── internal/
│   ├── http_pot.go             # HTTP pot, robots, sitemap, telemetry
│   ├── ssh_pot.go              # SSH pot
│   ├── mysql_decoy.go          # Fake MySQL :3306
│   ├── grafana_decoy.go        # Fake Grafana :3000
│   ├── identity.go             # CORP-PROD-* naming
│   ├── decoy/                  # Fake shell + history + virtual FS
│   └── honeytoken/             # Canaries + gzip tarpit
├── html/                       # Login + dashboard UI
├── docker-compose.yml
├── Dockerfile
└── honeypot_architecture_plan.md
```

---

## Safety

Before any internet or lab exposure:

1. Dedicated host / VLAN — no shared secrets with real IdP, VPN, or cloud  
2. Strict egress — pot must not reach production networks  
3. Out-of-band logging only  
4. Treat every hit as hostile  

---

## Roadmap

See [`honeypot_architecture_plan.md`](./honeypot_architecture_plan.md) for DNS canaries, Office document beacons, Endlessh on port 22, and SIEM shipping.

### Status

Lab / research. Core surfaces shipped: HTTP + SSH pots, Tier-1 honeytokens, WebRTC probe, robots/sitemap lures.

---

## Contributing

PRs welcome that improve **deception fidelity** and **isolation**. Please do **not** add bridges into real corporate identity or data planes.

1. Fork → feature branch → PR  
2. Keep decoy credentials non-functional on real systems  
3. Prefer logging / canaries over “helpful” production features  

---

## License

License not published yet. If you fork for private lab use, keep the ethics warning above. A proper `LICENSE` file will be added when the project is declared open-source.

---

<p align="center">
  <sub>Built for blue teams who like their bait medium-rare.</sub>
</p>
