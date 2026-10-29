# Project Roadmap: AuthPin (Standalone & Multi-Tenant OTP Service)

> **Repository:** `divmora/github-repos/authpin` (also accessible via `divmora/github-repo/authpin`)  
> **Type:** Standalone, Universal Plug-and-Play Microservice / SaaS-ready API  
> **Initial Target Engine:** PostgreSQL  
> **Extensible Engines:** AWS DynamoDB, MySQL  

---

## 1. Executive Summary & Vision

**AuthPin** is a standalone, developer-first OTP generation, delivery, and verification service designed so that **any application, team, or external client can consume it directly**.

Whether deployed as an internal central auth service across microservices or as a multi-tenant platform for multiple apps:
1. **Blind Verification Model**: The service handles raw OTP generation and multi-channel delivery directly to the end user. The caller receives an opaque verification tracking hash (`verification_token`). Downstream systems verify by providing this tracking hash alongside the user's input.
2. **Cryptographic Attestation Proof (JWT)**: Upon successful verification, AuthPin issues an Ed25519/RS256-signed JWT assertion (`verification_proof`). Any downstream backend can cryptographically verify the user's successful authentication offline without querying AuthPin again.
3. **Pluggable Database Layer**: A unified storage interface allowing deployment over **PostgreSQL** (first), **AWS DynamoDB** (native TTL), or **MySQL** (InnoDB) with zero application code changes.
4. **Multi-Tenant & Self-Hosted Ready**:
   - Supports **API Key / Project isolation** so any team or app gets dedicated rate limits, custom sender identities, and templates.
   - **Bring-Your-Own-Provider (BYOP)**: Projects can use platform dispatch pools or inject their own SMTP/SES/Twilio credentials.
5. **Zero-Knowledge Encryption at Rest**: Sensitive PII (emails, phone numbers) and metadata are encrypted using AES-256-GCM. OTPs are stored strictly as salted one-way hashes (`Argon2id` / `HMAC-SHA256`).
6. **Dynamic Expiry & Granular Policies**: Custom TTL per request (e.g., 60s for high-risk auth, 900s for email validation), rate limiting, and maximum attempt lockouts.
7. **Direct Multi-Channel Dispatch**: Native email (SMTP, AWS SES, Resend) and SMS (Twilio, AWS SNS) capabilities built right in.

---

## 2. Core Architecture & End-to-End Workflow

```
+-----------------------------------------------------------------------------------------------+
|                                    Any Downstream Client                                      |
|                       (Web App, Mobile App, Microservice, Backend API)                       |
+-----------------------------------------------------------------------------------------------+
              |                                                               |
     1. POST /v1/otp/generate                                        3. POST /v1/otp/verify
     Header: X-API-Key: sec_live_...                                 Header: X-API-Key: sec_live_...
     { target, channel, purpose, ttl }                               { verification_token, otp }
              |                                                               |
              v                                                               v
+-----------------------------------------------------------------------------------------------+
|                                            AuthPin                                            |
|                                                                                               |
|  [Tenant & Rate Limiting] --> [Crypto Vault: AES-256-GCM] --> [Pluggable Storage Layer]       |
|  - Validates API Key           - Hashes OTP (Argon2id)        - PostgreSQL (pgxpool)          |
|  - Enforces quota & anti-fraud - Encrypts target PII          - DynamoDB (native TTL)         |
|  - Resolves email/SMS templates- Issues tracking hash         - MySQL (InnoDB)                |
+-----------------------------------------------------------------------------------------------+
              |                                                               |
              | 2. Direct Delivery                                            | 4. Verification Proof
              v                                                               v
      [Email / SMS Relay]                                       Signed Attestation JWT
      - SMTP / AWS SES / Resend                                 { "sub": "alice@ex.com",
      - Twilio / AWS SNS                                          "status": "verified",
                                                                  "sig": "ed25519_..." }
```

---

## 3. Engineering Roadmap

### Phase 1: Universal API Contracts & Clean Architecture
- [x] Define OpenAPI 3.1 specification (`docs/openapi.yaml`) accessible to any developer.
- [x] Implement Tenant & Project Context Layer:
  - API Key authentication (`X-API-Key`) with configurable standalone vs multi-tenant modes.
  - Project configuration: Dynamic TTL, custom OTP length (4 to 32), character sets (`numeric`, `alphanumeric`).
  - Standalone mode bypass for internal zero-friction microservice deployments.
- [x] Define the `StorageEngine` interface contract in Go:
  - `SaveSession(ctx, session)`
  - `GetSessionByTokenHash(ctx, tokenHash)`
  - `IncrementAttempts(ctx, tokenHash)`
  - `MarkVerified(ctx, tokenHash, verifiedAt)`
  - `Invalidate(ctx, tokenHash, status)`
  - `CleanupExpired(ctx, before, limit)`
  - `Ping(ctx)`
- [x] Define the `Dispatcher` interface for delivery channels (`EmailDispatcher`, `SMSDispatcher`, `MockDispatcher`).
- [x] Implement simultaneous multi-channel parallel dispatcher (delivering to Email + SMS simultaneously).
- [x] Define Crypto Vault subsystem:
  - Field-Level Encryption (FLE) using AES-256-GCM for PII and metadata.
  - Constant-time OTP hash matching with HMAC-SHA256 / Argon2id.
  - Signed JWT attestation proof generator.

### Phase 2: PostgreSQL Storage Engine & Core Pipeline
- [x] Implement PostgreSQL driver using `pgxpool`.
- [x] Design auto-migrating schema with partial indexes for active unexpired sessions.
- [x] Implement Generation pipeline:
  - Cryptographically secure CSPRNG generator (`crypto/rand`).
  - Dynamic TTL validation (30s to 3600s).
  - Opaque tracking token generation (`vtok_<random_32_bytes>`).
- [x] Implement Verification pipeline:
  - Strict state checks (`PENDING` -> `VERIFIED` / `EXHAUSTED` / `EXPIRED` / `REVOKED`).
  - Constant-time verification preventing timing side-channel attacks.
  - Early length & format validation.
  - Atomic attempt counter and lockout after max attempts.
  - Signed JWT attestation issuance (`assertion_token`).
- [x] Implement background expired token cleanup worker.

### Phase 3: Direct Multi-Channel Dispatchers & Endpoints
- [x] **Email Dispatcher**:
  - Direct SMTP relay with TLS/STARTTLS authentication.
  - Responsive HTML & text email templates.
- [x] **SMS Dispatcher**:
  - Twilio REST API integration.
- [x] **Simultaneous Multi-Channel Support**:
  - Parallel dispatch goroutines sending identical OTP to multiple destinations concurrently.
- [x] **Lifecycle Endpoints**:
  - `POST /api/v1/otp/resend`: Redispatch fresh code for active session without creating new tracking tokens.
  - `POST /api/v1/otp/revoke`: Immediately cancel and invalidate pending sessions.

### Phase 4: AWS DynamoDB & MySQL Storage Adapters
- [x] **AWS DynamoDB Adapter** (`internal/storage/dynamodb`):
  - Partition Key: `token_hash`.
  - Native DynamoDB `ttl` attribute (Unix epoch) for automatic, zero-cost cloud record eviction.
  - Atomic condition expressions (`attribute_exists`, `#status = :pending`).
- [x] **MySQL Adapter** (`internal/storage/mysql`):
  - InnoDB transaction-safe implementation with connection pooling (`go-sql-driver/mysql`).
  - Auto-migration table schema and indexes.
- [x] In-memory storage adapter (`internal/storage/memory`) for zero-dependency local development and testing.

### Phase 5: Observability & Operational Probes
- [x] `GET /readyz` readiness probe verifying database connectivity (`storage.Ping`).
- [x] `GET /livez` and `/health` liveness checks.
- [x] `GET /metrics` Prometheus metrics exporter via official `promhttp`:
  - Request latencies histogram
  - Counter metrics for generated OTPs partitioned by channel and type
  - Counter metrics for verification outcomes (verified, incorrect, expired, exhausted, replay_rejected)
  - Database connectivity gauge (`authpin_storage_up`)

### Phase 6: Packaging & Integration
- [x] Multi-stage minimal production Dockerfile (`alpine:3.20`).
- [x] Docker Compose setup (`docker-compose.yml`) with PostgreSQL.
- [x] Clean architecture and 100% unit & integration test coverage across all packages.

---

## 4. Universal API Specification

### 4.1 Generate Request
`POST /api/v1/otp/generate`
```http
POST /api/v1/otp/generate
Content-Type: application/json
X-API-Key: authpin_live_9a8b7c6d5e4f3a2b1c0d

{
  "target": "alice@example.com",
  "channel": "email",
  "purpose": "login_2fa",
  "digits": 6,
  "ttl_seconds": 300,
  "template_id": "default_login",
  "metadata": {
    "client_ip": "203.0.113.195",
    "user_agent": "Mozilla/5.0..."
  }
}
```

### 4.2 Generate Response
```json
{
  "success": true,
  "verification_token": "vtok_f47ac10b58cc4372a5670e02b2c3d479",
  "channel": "email",
  "recipient_masked": "a***e@example.com",
  "expires_at": "2026-10-29T15:38:07Z",
  "ttl_seconds": 300
}
```
*(Notice: The raw OTP is sent directly to the user's inbox/phone and is never exposed in the API response.)*

### 4.3 Verify Request
`POST /api/v1/otp/verify`
```http
POST /api/v1/otp/verify
Content-Type: application/json
X-API-Key: authpin_live_9a8b7c6d5e4f3a2b1c0d

{
  "verification_token": "vtok_f47ac10b58cc4372a5670e02b2c3d479",
  "otp": "482910",
  "purpose": "login_2fa"
}
```

### 4.4 Verify Response
```json
{
  "success": true,
  "status": "verified",
  "verified_at": "2026-10-29T15:34:12Z",
  "assertion_token": "eyJhbGciOiJFRDI1NTE5IiwidHlwIjoiSldUIn0..."
}
```

---

## 5. Storage Schema & Encryption Model

| Field | Storage Type | Security Level | Purpose |
| :--- | :--- | :--- | :--- |
| `project_id` | `VARCHAR(36)` | Plaintext | Tenant/project partition key for multi-tenant isolation |
| `token_hash` | `VARCHAR(64)` | SHA-256 Hash | Primary lookup key matching the client's `verification_token` |
| `otp_hash` | `VARCHAR(128)` | Argon2id / HMAC-SHA256 | Cryptographic one-way hash of the OTP |
| `recipient_encrypted`| `BYTEA` / `BLOB` | AES-256-GCM | Encrypted email or phone number |
| `recipient_lookup_hash`| `VARCHAR(64)` | HMAC-SHA256 | Blind index for rate-limiting by recipient |
| `purpose` | `VARCHAR(32)` | Plaintext | Context isolation (e.g., `login`, `pwd_reset`) |
| `attempts` | `INT` | Plaintext | Counter for failed verification attempts |
| `max_attempts` | `INT` | Plaintext | Max allowed attempts before lockout (default: 3) |
| `status` | `VARCHAR(16)` | Plaintext | `PENDING`, `VERIFIED`, `EXHAUSTED`, `EXPIRED` |
| `metadata_encrypted` | `BYTEA` / `BLOB` | AES-256-GCM | Encrypted contextual metadata |
| `created_at` | `TIMESTAMP` | Plaintext | Creation timestamp |
| `expires_at` | `TIMESTAMP` / `BIGINT` | Plaintext / Epoch TTL | Dynamic expiration cutoff |
| `verified_at` | `TIMESTAMP` | Plaintext | Verification timestamp |

---

## 6. Success Metrics & Non-Functional Requirements
- **Universal Accessibility**: Anyone can integrate via standard REST endpoints or lightweight client libraries within 5 minutes.
- **Latency**: Sub-25ms P99 verification latency (excluding database network round-trip).
- **Security**: Zero plaintext OTPs in persistence, in-memory scrub where supported, constant-time comparisons.
- **Portability**: 100% database interface decoupling, swappable via a single config flag `DATABASE_DRIVER=postgres|dynamodb|mysql`.
- **Zero-Downtime Resilience**: Graceful degradation if delivery channels suffer transient network errors.
