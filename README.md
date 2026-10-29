# AuthPin 🔐

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

### 1. Generate OTP
```http
POST /api/v1/otp/generate
Content-Type: application/json
X-API-Key: authpin_live_9a8b7c6d5e4f3a2b1c0d

{
  "target": "alice@example.com",
  "channel": "email",
  "purpose": "login",
  "ttl_seconds": 300,
  "digits": 6
}
```

**Response:**
```json
{
  "success": true,
  "verification_token": "vtok_7d3f8a1c9e2b4f508192a3b4c5d6e7f8",
  "channel": "email",
  "recipient_masked": "a***e@example.com",
  "expires_at": "2026-10-29T15:40:00Z",
  "ttl_seconds": 300
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
  "status": "verified",
  "verified_at": "2026-10-29T15:36:12Z",
  "assertion_token": "eyJhbGciOiJFRDI1NTE5IiwidHlwIjoiSldUIn0..."
}
```

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

## 🚀 Roadmap

See [ROADMAP.md](file:///home/ngoyal16/Desktop/divmora/github-repos/authpin/ROADMAP.md) for detailed delivery phases and engineering deliverables.
