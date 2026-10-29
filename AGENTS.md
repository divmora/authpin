# AI Agent Guidelines & Repository Standards for AuthPin

Welcome to **AuthPin**, the standalone, universal, encrypted-at-rest OTP generation and verification microservice.

---

## 🏗️ Project Architecture Layout

```
authpin/
├── cmd/
│   └── authpin/                  # CLI & HTTP daemon entrypoint
├── docs/
│   └── openapi.yaml              # OpenAPI 3.1 specification
├── internal/
│   ├── api/                      # REST handlers, router, and middleware
│   ├── config/                   # YAML & Environment variable configuration loader
│   ├── crypto/                   # AES-256-GCM, HMAC-SHA256, Argon2id, and Attestation JWT
│   ├── dispatcher/               # Email (SMTP), SMS (Twilio), and Mock dispatchers
│   ├── metrics/                  # Prometheus instrumentation & metrics
│   ├── model/                    # Domain structs and request/response payloads
│   ├── service/                  # Core OTP generation & verification business logic
│   └── storage/                  # Pluggable repository adapters
│       ├── dynamodb/             # AWS DynamoDB (native TTL)
│       ├── memory/               # In-memory storage engine
│       ├── mysql/                # MySQL (InnoDB)
│       └── postgres/             # PostgreSQL (pgxpool)
├── Dockerfile                    # Multi-stage production container
├── docker-compose.yml            # Docker compose with PostgreSQL
├── Makefile                      # Standard build & test automation targets
├── LICENSE                       # BSL 1.1 license
├── README.md                     # User-facing overview, API examples, and badges
├── ROADMAP.md                    # Living product roadmap
├── CONTRIBUTING.md               # Contribution and dev guidelines
└── SECURITY.md                   # Vulnerability disclosure policy
```

---

## 🛡️ Safety & Core Guarantees

1. **Zero Plaintext OTPs**: OTP codes MUST NEVER be stored in plaintext. Always use `vault.HashOTP(code)` with constant-time equality check (`subtle.ConstantTimeCompare`).
2. **Blind Token Pattern**: Downstream callers calling `/generate` MUST NEVER receive the raw OTP code in the API response. Codes are delivered directly to the user (via Email or SMS).
3. **Field-Level Encryption**: All sensitive PII (emails, phone numbers) and metadata MUST be encrypted using `AES-256-GCM` before persistence.
4. **Error Handling**: Always wrap internal errors using `fmt.Errorf("...: %w", err)`. Never return raw database errors or stack traces to HTTP callers.

---

## 📝 Commit Conventions

All commits must strictly adhere to the **Conventional Commits** specification:
- `feat:` New capabilities or features (e.g. `feat: add AWS DynamoDB adapter`)
- `fix:` Bug fixes (e.g. `fix: prevent race condition in attempt counter`)
- `docs:` Documentation additions or updates
- `chore:` Dependency bumps, repo maintenance, or tooling changes
- `test:` Unit and integration test additions or updates
- `refactor:` Code refactoring without behavioral alterations
- `feat!:` Breaking API changes

---

## 🗺️ Living Product Roadmap Lifecycle

- **Adding Backlog Items**: Whenever a new optimization, edge case, or capability is identified for future work, document it in `ROADMAP.md`.
- **Deduplication**: Do not duplicate active, assigned GitHub Issues into `ROADMAP.md`.
- **Pruning Completed Work**: When a roadmap task is implemented, tested, and committed, update `ROADMAP.md` accordingly.

---

## 🧪 Verification Commands

Before committing any changes, run the full verification suite:
```bash
make fmt       # Format code
make test      # Run all unit and integration tests
make build     # Verify binary compilation
```
