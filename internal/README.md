# internal

Private application code. Not importable by external modules.

Add one Go package per feature or concern, directly under this directory:

```
internal/
├── honeypot/       # Honeypot logic
├── geolocation/    # IP geolocation
├── network/        # Network scanning
└── cli/            # CLI handlers and output
```

No nested layer folders — keep packages flat and named by what they do.
