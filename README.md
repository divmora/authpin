# AuthPin 🔐

[![Latest Release](https://img.shields.io/github/v/release/divmora/authpin?logo=github)](https://github.com/divmora/authpin/releases)
[![License: BSL 1.1](https://img.shields.io/badge/License-BSL_1.1-blue.svg)](https://github.com/divmora/.github/blob/main/LICENSING.md)
[![CI/CD](https://github.com/divmora/authpin/actions/workflows/ci.yml/badge.svg)](https://github.com/divmora/authpin/actions)
[![Go Version](https://img.shields.io/github/go-mod/go-version/divmora/authpin)](go.mod)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/divmora/authpin)
[![Security Policy](https://img.shields.io/badge/Security-Policy-green.svg)](SECURITY.md)

> A standalone, universal, and database-agnostic OTP generation, delivery, and verification service that anyone can use.

AuthPin is built to be consumed by **any application, website, mobile client, or backend service**. It handles the entire OTP lifecycle: cryptographically generating codes, dispatching them directly to users via Email or SMS, storing records encrypted at rest, and validating inputs securely through a blind token verification protocol.

---

## 🌟 Key Features

- **Universal & Standalone API**: Anyone can use AuthPin out-of-the-box. Supports both:
  - **Self-Hosted / Single-Tenant Mode**: Simple internal deployment for your team or company.
  - **Multi-Tenant / Shared Platform Mode**: Uses scoped API keys (`X-API-Key`) so different apps, teams, or customers have isolated limits, custom templates, and independent delivery credentials.
- **Blind Verification Protocol**: The calling application never sees the plain OTP code. AuthPin sends the code directly to the user (via Email or SMS) and returns an opaque tracking hash (`verification_token`). Downstream systems verify by passing both the tracking hash and the user's OTP.
- **Signed Cryptographic Verification Proof**: Upon successful verification, AuthPin can issue a signed JWT assertion (`verification_proof`). Downstream services can verify authentication cryptographically without needing a direct database connection.
- **Pluggable Database Engines**:
  - **PostgreSQL** (Active default)
  - **AWS DynamoDB** (Native TTL support for automatic zero-cost eviction)
  - **MySQL** (InnoDB)
- **Zero-Knowledge Encryption at Rest**:
  - OTPs are stored only as salted cryptographic hashes (`Argon2id` or `HMAC-SHA256`).
  - Sensitive recipient data (email addresses, phone numbers) and metadata are encrypted using `AES-256-GCM`.
- **Dynamic TTL**: Expiration time can be configured dynamically per API call, per channel, or per purpose (e.g. 60s for 2FA, 900s for email sign-up).
- **Direct Multi-Channel Dispatchers**:
  - **Email**: SMTP relay, AWS SES, Resend.
  - **SMS**: AWS SNS, Twilio.
- **Anti-Abuse & Rate Limiting**:
  - Built-in protection against SMS toll fraud and email spamming.
  - Limits per recipient, per client IP, and per API key.
  - Brute-force lockout after maximum verification attempts (default: 3).

---

## 🏗️ Architecture

```
                  +----------------------------------+
                  |     Any Downstream Client        |
                  |  (Web, Mobile, Microservice)     |
                  +----------------------------------+
                        |                      |
            1. POST /otp/generate     3. POST /otp/verify
            (target, channel, ttl)     (token, otp)
                        |                      |
                        v                      v
             +------------------------------------+
             |              AuthPin               |
             |   - Scoped API Key / Multi-Tenant  |
             |   - OTP Engine (crypto/rand)       |
             |   - Crypto Vault (AES-256-GCM)     |
             |   - Pluggable Storage Drivers      |
             |   - Direct Email & SMS Dispatchers |
             +------------------------------------+
                 /          |                  \
                /           |                   \
    +-----------------+  +-----------------+  +-----------------+
    |   PostgreSQL    |  |  AWS DynamoDB   |  |     MySQL       |
    +-----------------+  +-----------------+  +-----------------+
            |                                          |
    +-----------------+                     +--------------------+
    | Dispatchers     |                     | Signed Proof (JWT) |
    | - Email (SMTP)  |                     | { sub, verified }  |
    | - SMS (Twilio)  |                     +--------------------+
    +-----------------+
```

---

## 📋 API Overview

### 1. Generate OTP (Single or Multi-Channel)
```http
POST /api/v1/otp/generate
Content-Type: application/json
X-API-Key: authpin_live_9a8b7c6d5e4f3a2b1c0d

{
  "channels": [
    { "channel": "email", "target": "alice@example.com" },
    { "channel": "sms", "target": "+14155552671" }
  ],
  "purpose": "login",
  "otp_length": 6,
  "otp_type": "numeric",
  "ttl_seconds": 300
}
```

**Response:**
```json
{
  "success": true,
  "verification_token": "vtok_7d3f8a1c9e2b4f508192a3b4c5d6e7f8",
  "channel": "email",
  "recipient_masked": "a***e@example.com",
  "deliveries": [
    { "channel": "email", "recipient_masked": "a***e@example.com", "success": true },
    { "channel": "sms", "recipient_masked": "+1****71", "success": true }
  ],
  "expires_at": "2026-10-29T15:40:00Z",
  "ttl_seconds": 300,
  "otp_length": 6,
  "otp_type": "numeric"
}
```

### 2. Verify OTP
```http
POST /api/v1/otp/verify
Content-Type: application/json
X-API-Key: authpin_live_9a8b7c6d5e4f3a2b1c0d

{
  "verification_token": "vtok_7d3f8a1c9e2b4f508192a3b4c5d6e7f8",
  "otp": "830291",
  "purpose": "login"
}
```

**Response:**
```json
{
  "success": true,
  "status": "VERIFIED",
  "verified_at": "2026-10-29T15:36:12Z",
  "assertion_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### 3. Resend OTP
```http
POST /api/v1/otp/resend
Content-Type: application/json

{
  "verification_token": "vtok_7d3f8a1c9e2b4f508192a3b4c5d6e7f8"
}
```

### 4. Revoke OTP
```http
POST /api/v1/otp/revoke
Content-Type: application/json

{
  "verification_token": "vtok_7d3f8a1c9e2b4f508192a3b4c5d6e7f8",
  "reason": "user cancelled"
}
```

### 5. Health & Monitoring Probes
- `GET /health` or `GET /livez`: Liveness check (`200 OK`)
- `GET /readyz`: Readiness probe testing active database connectivity (`200 OK` or `503 Unavailable`)
- `GET /metrics`: Standard Prometheus metrics export format

---

## 📂 Project Structure

```
divmora/github-repos/authpin/
├── README.md              # Project overview & quickstart
├── ROADMAP.md             # Detailed engineering roadmap & milestones
├── config.example.yaml    # Sample configuration
├── cmd/
│   └── authpin/           # Application entrypoint
├── internal/
│   ├── api/               # HTTP REST handlers, routing & middleware (API key auth)
│   ├── config/            # Configuration management
│   ├── crypto/            # AES-256-GCM, Argon2id hashing & JWT attestation
│   ├── dispatcher/        # Email (SMTP/SES) & SMS (Twilio/SNS)
│   ├── service/           # Core OTP lifecycle business logic
│   └── storage/           # Pluggable storage adapters
│       ├── postgres/      # PostgreSQL adapter (pgx)
│       ├── dynamodb/      # DynamoDB adapter (AWS SDK v2)
│       └── mysql/         # MySQL adapter (InnoDB)
```

---

## ⚙️ Configuration & Environment Variables

| Variable | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `PORT` | `int` | `8080` | Port for the HTTP daemon to listen on |
| `HOST` | `string` | `0.0.0.0` | Host interface binding |
| `AUTHPIN_MODE` | `string` | `standalone` | Operating mode: `standalone` (zero auth) or `multi_tenant` (`X-API-Key`) |
| `DATABASE_DRIVER` | `string` | `postgres` | Storage driver: `postgres`, `mysql`, `dynamodb`, or `memory` |
| `POSTGRES_DSN` | `string` | `""` | PostgreSQL connection string (`DATABASE_URL` also accepted) |
| `MYSQL_DSN` | `string` | `""` | MySQL DSN (`user:pass@tcp(host:port)/dbname?parseTime=true`) |
| `DYNAMODB_REGION` | `string` | `us-east-1` | AWS Region for DynamoDB (`AWS_REGION` also accepted) |
| `DYNAMODB_TABLE` | `string` | `authpin_sessions` | AWS DynamoDB table name |
| `DYNAMODB_ENDPOINT`| `string` | `""` | Custom endpoint for DynamoDB (e.g. LocalStack) |
| `MASTER_KEY` | `string` | `(dev-key)` | 32-byte (64 hex characters) key for AES-256-GCM encryption |

---

## 🤝 Community & Contributing

- **[CONTRIBUTING.md](CONTRIBUTING.md)**: Development prerequisites, make targets, and commit conventions.
- **[SECURITY.md](SECURITY.md)**: Responsible disclosure process and reporting vulnerabilities to `security@divmora.com`.
- **[Code of Conduct](https://github.com/divmora/.github/blob/main/CODE_OF_CONDUCT.md)**: Community standards and expectations.

---

## 📜 License & Commercial Use

AuthPin is licensed under the **Business Source License 1.1 (BSL 1.1)**:
- **Free Use**: You may use AuthPin free of charge for non-production purposes, including local development, testing, staging, QA, CI/CD automated validation, educational purposes, and proof-of-concept evaluation.
- **Commercial Production Use**: Deploying or executing AuthPin in a commercial production environment or offering it as a hosted/managed service requires an active commercial subscription (EULA) from **DIVMORA Technologies**.
- **Change Date**: Converts to **Apache License, Version 2.0** three (3) years after the release date of each specific version.

For commercial inquiries, licensing, and enterprise support:
- 🌐 **Website**: [https://divmora.com](https://divmora.com)
- ✉️ **Licensing**: [licensing@divmora.com](mailto:licensing@divmora.com)
- 🔒 **Security**: [security@divmora.com](mailto:security@divmora.com)

---

## 🚀 Roadmap

See [ROADMAP.md](ROADMAP.md) for detailed delivery phases and engineering deliverables.
