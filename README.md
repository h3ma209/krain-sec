<p align="center">
  <img src="./icon.png" alt="krain-sec" width="180" />
</p>

<h1 align="center">krain-sec</h1>

<p align="center">
  <strong>Decoy honeypot for your VPS — distract attackers from the real website</strong>
</p>

<p align="center">
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go&logoColor=white" alt="Go" /></a>
  <a href="./docker-compose.yml"><img src="https://img.shields.io/badge/Docker-Compose-2496ED?style=flat&logo=docker&logoColor=white" alt="Docker" /></a>
  <a href="#goal"><img src="https://img.shields.io/badge/for-small%20teams%20%2F%20VPS-0ea5e9" alt="Audience" /></a>
  <a href="#goal"><img src="https://img.shields.io/badge/image-~23MB%20Alpine-22c55e" alt="Lightweight" /></a>
</p>

---

## Goal

**Keep scanners/crawlers/bots busy on fake doors so your real site stays less interesting.**

Your real website should look uninteresting to scanners. krain-sec parks a louder, juicier fake beside it — fake SSH, fake MySQL, fake Grafana, and a fake SOC console — giving commodity scanners and curious intruders believable dead ends to investigate.

krain-sec runs **beside** your website on the same server. It pretends to be an actual part of the server

- Fake web login + dashboard + operator PDF manuals  
- Fake SSH on **port 22** (you move real admin SSH elsewhere)  
- Fake MySQL (`3306`) and Grafana (`3000`) that look open but never help  
- Planted “secrets,” tarpits, and local attack logs under `./logs`

Made for **small teams and solo operators** — no SOC required. One small container, `make prod`, watch the logs.

**Lightweight on purpose:** static Go binary on **Alpine** (~**23MB** image), capped at **256MB RAM / 0.5 CPU**, no real database or Grafana stack — safe to park next to a cheap VPS website without eating the box.

> [!WARNING]
> Deploy only on servers **you own**. Bait passwords are fake — never reuse them for real access. This distracts attackers; it does **not** replace patching, backups, TLS, or locking down your real app.

---

## How it works on a real server

```text
                         Internet
                             |
             +---------------v----------------+
             |            your VPS             |
             |                                 |
             |  :80 / :443  →  real website    |  customers
             |  :8080       →  Aetheris UI     |  bait HTTP
             |  :22         →  fake SSH        |  bait (real SSH → e.g. :2222)
             |  :3306       →  MySQL decoy     |
             |  :3000       →  Grafana decoy   |
             |  ./logs      →  attack events   |
             +--------------------------------+
```

| Step | What you do |
|------|-------------|
| 1 | Move **real** SSH off port 22 (e.g. `:2222`, ideally allowlist your IP) |
| 2 | Clone repo, set `HONEYTOKEN_BASE_URL` in `.env` to your public bait URL |
| 3 | `make prod` — honeypot starts; site on 80/443 unchanged |
| 4 | Optional: proxy `console.yourdomain.com` → `127.0.0.1:8080` |
| 5 | When curious: `make attack-logs` |

The container uses an **internal** Docker network (no outbound to your DB/LAN), a read-only filesystem, and hard caps (**256MB RAM / 0.5 CPU**) so the decoy cannot pivot or starve the real site.

---

## Features

| Feature | What it does |
|---------|----------------|
| **SOC console** `:8080` | Fake Aetheris login and JWT dashboard that look like a real ops console |
| **Operator manuals** `/docs/` | Multi-page bait PDFs on the login page, with canary plant-IDs and verify links |
| **Crawler lures** | `robots.txt` and `sitemap.xml` that advertise “forbidden” paths scanners love to hit |
| **WebRTC probe** | On login-page load, attempts a STUN/ICE leak and posts results to telemetry |
| **Canary beacons** `/t/*.gif` | Tiny tracking pixel that logs when someone opens a planted link or PDF |
| **Auth downloads** `/downloads/` | Fake break-glass, AWS keys, SSH key, and runbook (after decoy login) |
| **SSH decoy** `:22` | Fake interactive shell with history and “emergency” files in a virtual home |
| **MySQL decoy** `:3306` | Speaks a real-looking MySQL handshake, then always returns Access denied |
| **Grafana decoy** `:3000` | Grafana-like UI and healthy `/api/health`; login never succeeds |
| **Infinite dirs** | Endless Apache-style indexes on `/backup/` `/reports/` `/archive/` `/exports/` |
| **Gzip bomb** `/logs/` | Serves an enormous compressed payload to stall greedy download tools |
| **Request lag** | Adds 1–9 seconds of delay on most HTTP paths so automation slows down |
| **Rate limits** | Per-IP limits (login, traps, telemetry, default) that return 429 when exceeded |
| **Honeytokens** | Planted credentials and keys in HTTP docs and the SSH home directory |
| **Local logs** | Writes daily JSONL under `./logs` (auth, HTTP, SSH, tokens, WebRTC, decoys) |
| **Log retention** | Deletes log files older than 7 days so disk use stays bounded |
| **Corp identity** | Consistent `CORP-PROD-*` host names across banners, MOTD, and documents |
| **Sidecar deploy** | Runs next to your real site; customers stay on 80/443, bait gets the rest |
| **Isolation** | Internal Docker network, read-only filesystem, and dropped capabilities |
| **Resource caps** | Hard limit of 256MB RAM / 0.5 CPU so the decoy cannot starve the real site |
| **Soft-fail decoys** | If SSH, MySQL, or Grafana cannot bind, the HTTP bait keeps running |
| **Tiny image** | ~23MB Alpine image with a static Go binary — no real DB or Grafana stack |

**Not included:** real MySQL, real Grafana, or SIEM — by design. Small image, small bill, small blast radius.




---

## Quick start

**Need:** [Docker](https://docs.docker.com/) + Docker Compose.

```bash
git clone https://github.com/h3ma209/krain-sec.git
cd krain-sec
cp .env.example .env          # edit HONEYTOKEN_BASE_URL when you go public
make prod                     # build + start
make attack-logs              # optional: watch probes
```

| Bait | How to hit it |
|------|----------------|
| Console | http://127.0.0.1:8080 |
| SSH | `ssh admin@127.0.0.1` |
| MySQL | `127.0.0.1:3306` |
| Grafana | http://127.0.0.1:3000 |

```bash
make help    # all commands
make down    # stop
```

### Decoy credentials (bait only)

| Surface | User | Password |
|---------|------|----------|
| HTTP | `admin` | `1234567890` |
| SSH | `admin` | `secret123` |

### Local Go (optional)

```bash
go run ./cmd/krain-sec
# or: make dev    # hot reload (reflex)
```

---

## Make commands

| Command | Purpose |
|---------|---------|
| `make prod` | Build & start honeypot beside your site |
| `make down` | Stop |
| `make restart` | Restart |
| `make logs` | Container stdout |
| `make ps` | Status |
| `make build` | Image only |
| `make attack-logs` | Tail today’s `events-*.jsonl` |
| `make dev` | Local Go + reflex |
| `make help` | This list |

---

## Logs

Host folder `./logs` is mounted into the container.

| File | Contents |
|------|----------|
| `app-YYYY-MM-DD.jsonl` | Operational JSON logs (also stdout) |
| `events-YYYY-MM-DD.jsonl` | All attack events (UTC day) |
| `auth-*.jsonl` | HTTP + SSH login attempts |
| `http-*.jsonl` | HTTP requests |
| `ssh-*.jsonl` | Commands in the fake shell |
| `honeytoken-*.jsonl` | Canary / PDF / beacon hits |
| `webrtc-*.jsonl` | Browser WebRTC probes on the login page |
| `decoy-*.jsonl` | MySQL / Grafana probes |

Retention: files older than **7 days** removed (`LOG_RETENTION_DAYS`).

Operational logs are JSON (`ts`, `level`, `msg`, attrs). Attack telemetry stays in the event JSONL channels above. Passwords land in `auth-*.jsonl` only — not stdout.

---

## Configuration

Copy [`.env.example`](./.env.example) → `.env`.

| Variable | Purpose | Default |
|----------|---------|---------|
| `HONEYTOKEN_BASE_URL` | Public URL baked into PDFs / planted files | `http://127.0.0.1:8080` |
| `LOG_DIR` | Log directory (Compose forces `/app/logs`) | `logs` |
| `LOG_RETENTION_DAYS` | Delete old log files by mtime | `7` |
| `LOG_LEVEL` | Operational slog level (`debug`/`info`/`warn`/`error`) | `info` |
| `JWT_SECRET` | Dashboard cookie signing key (random if unset) | (random) |
| `MAX_HTTP_INFLIGHT` | Cap concurrent HTTP handlers (else 503) | `64` |
| `MAX_MYSQL_DECOY` | Cap concurrent MySQL decoy sessions | `16` |
| `MAX_SSH_SESSIONS` | Cap concurrent SSH decoy shells | `32` |
| `RATE_LIMIT_*` | Per-IP HTTP rate limits | see `.env.example` |

---

## Smoke-test the bait

```bash
curl -s http://127.0.0.1:8080/robots.txt
curl -sI http://127.0.0.1:8080/docs/SOC_Console_Operator_Manual.pdf
ssh admin@127.0.0.1   # then: ls Documents
```

---

## Layout

```text
krain-sec/
├── cmd/krain-sec/         Entrypoint
├── internal/              HTTP/SSH pots, decoys, honeytokens, file logs
├── html/                  Login + dashboard (Aetheris brand)
├── docker-compose.yml     Sidecar deploy (internal net, caps, read-only)
├── Dockerfile             Alpine runtime
├── Makefile               prod / logs / attack-logs / dev
└── .env.example
```

---

## Safety checklist

1. Real SSH **not** on port 22 before you publish bait SSH.  
2. No shared secrets or DB volumes between honeypot and real site.  
3. Leave Compose isolation on (internal network, caps, read-only).  
4. Still harden the real website.  
5. Anything in `./logs` is hostile — don’t trust it.

---

## Contributing

PRs for better decoys and safer defaults welcome. Do not connect this to real IdP, cloud accounts, or production data.

---

## License

AGPL-3.0 license

---

<p align="center">
  <sub>Bait for the bots and crawlers and scanners. Keep the real site boring.</sub>
</p>
