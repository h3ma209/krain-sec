# cmd

Application entry points. One subdirectory per binary.

| Directory | Purpose |
|-----------|---------|
| [krain-sec/](./krain-sec/) | Main application binary |

Keep `main` packages thin — parse flags, load config, call into `internal/`.
