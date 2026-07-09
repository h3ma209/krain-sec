# krain-sec

Security tooling project using standard Go layout.

## Directory layout

```
krain-sec/
├── cmd/            # Application entry points
│   └── krain-sec/  # Main binary
├── internal/       # Private application packages
├── configs/        # Configuration files
├── scripts/        # Build and utility scripts
└── docs/           # Documentation
```

Each directory has a `README.md` explaining what goes there.

## Getting started

1. Put business logic in packages under `internal/` (e.g. `internal/honeypot/`, `internal/geolocation/`).
2. Wire everything together in `cmd/krain-sec/main.go`.
3. Add config files to `configs/`.
