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

### Phase 1: Universal API Contracts & Multi-Tenancy Architecture (Week 1)
- [ ] Define OpenAPI 3.1 & Swagger interactive docs (`/docs`) accessible to any developer.
- [ ] Implement Tenant & Project Context Layer:
  - API Key authentication (`X-API-Key`) with hashed keys stored in DB.
  - Project configuration: Default TTL, OTP digit length (4, 6, 8, alphanumeric), max attempts, sender name.
  - Optional standalone mode: Single-tenant bypass for self-hosters wanting zero API key friction.
- [ ] Define the `StorageEngine` interface contract in Go:
  - `SaveSession(ctx, session)`
  - `GetSessionByTokenHash(ctx, tokenHash)`
  - `IncrementAttempts(ctx, tokenHash)`
  - `MarkConsumed(ctx, tokenHash)`
  - `Invalidate(ctx, tokenHash)`
  - `CleanupExpired(ctx, batchSize)`
- [ ] Define the `Dispatcher` interface for delivery channels (`EmailDispatcher`, `SMSDispatcher`).
- [ ] Define Crypto Vault subsystem:
  - Field-Level Encryption (FLE) using AES-256-GCM for PII.
  - Constant-time OTP hash matching with Argon2id / HMAC-SHA256.

### Phase 2: PostgreSQL Engine & Core Pipeline (Week 2)
- [ ] Implement PostgreSQL driver using `pgxpool`.
- [ ] Design migration schema with partial indexes for active unexpired sessions.
- [ ] Implement Generation pipeline:
  - Cryptographically secure random generator (`crypto/rand`).
  - Dynamic TTL validation (enforcing min 30s, max 1800s, configurable default).
  - Opaque tracking token generation (`vtok_<random_32_bytes>`).
- [ ] Implement Verification pipeline:
  - Strict state checks (`PENDING` -> `VERIFIED` / `EXHAUSTED` / `EXPIRED`).
  - Constant-time verification preventing timing side-channel attacks.
  - Atomic attempt counter and lockout after max attempts.
  - Signed JWT attestation issuance (`verification_proof`).
- [ ] Implement background expired token cleanup worker for PostgreSQL.

### Phase 3: Direct Multi-Channel Dispatchers & Templates (Week 3)
- [ ] **Email Dispatcher**:
  - Direct SMTP relay (TLS / STARTTLS authentication).
  - AWS SES API v2 provider.
  - Resend / SendGrid pluggable adapter.
  - Template engine with HTML & plain text fallback with customizable branding per project.
- [ ] **SMS Dispatcher**:
  - AWS SNS integration.
  - Twilio REST API integration.
  - Recipient phone number validation and E.164 normalization.
- [ ] Provider fallback & retry queue for transient delivery failures.

### Phase 4: AWS DynamoDB & MySQL Adapters (Week 4)
- [ ] **AWS DynamoDB Adapter**:
  - Partition Key: `token_hash`.
  - Secondary Index: `recipient_hash` for rate-limiting and active session lookups.
  - Native DynamoDB TTL attribute for zero-overhead, automated record pruning.
  - Conditional expressions for atomic verification and attempt increments.
- [ ] **MySQL Adapter**:
  - InnoDB transaction-safe implementation with pessimistic or optimistic locking.
  - MySQL migration scripts and connection pool configuration.
- [ ] Storage engine test suite: unified test suite run against testcontainers for Postgres, MySQL, and LocalStack DynamoDB.

### Phase 5: Anti-Abuse, Rate Limiting & Observability (Week 5)
- [ ] SMS Toll Fraud & Email Flooding Protection:
  - Rate limiting per recipient identifier (e.g. max 3 requests per 10 minutes).
  - Rate limiting per client IP (sliding window token bucket).
  - Tenant rate limits and monthly usage caps.
- [ ] PII Masking: Automatic redaction of emails and phone numbers in all log outputs.
- [ ] OpenTelemetry instrumentation: Distributed tracing across generation, database persistence, and message dispatch.
- [ ] Prometheus metrics: OTP generation latency, verification success/failure rates, delivery channel latencies, and attempt distributions.

### Phase 6: Universal Developer Experience, Packaging & SDKs (Week 6)
- [ ] Interactive Swagger UI (`/docs`) and Redoc API documentation.
- [ ] Multi-stage scratch/alpine Dockerfile & Helm charts.
- [ ] Docker Compose environment with Postgres, MySQL, LocalStack DynamoDB, and MailHog/SMTP test server.
- [ ] Official lightweight client libraries:
  - Go SDK (`github.com/divmora/authpin-go`)
  - TypeScript / Node SDK (`@divmora/authpin`)
  - Python SDK (`authpin`)
- [ ] Webhook notifications: emit `otp.generated`, `otp.verified`, `otp.failed` events to downstream webhooks.

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
