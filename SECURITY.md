# Security Policy

## Supported Versions

KeyVault actively maintains the `main` branch. Security patches and dependency updates are applied directly to `main`.

| Version / Branch | Supported |
| :--- | :--- |
| `main` (`1.5.x`) | Yes |

---

## Reporting a Vulnerability

If you discover a security vulnerability in KeyVault, please report it responsibly rather than opening a public GitHub issue with exploit details.

- **Contact:** Open a private security advisory on GitHub (**Security** tab -> **Advisories** -> **Report a vulnerability**) or contact the maintainer directly via [kritagyay2006@gmail.com](mailto:kritagyay2006@gmail.com).
- **What to include:**
  - A clear description of the vulnerability and its potential impact.
  - Step-by-step reproduction instructions, affected endpoints, or a minimal proof of concept.
  - Any suggested mitigation or patch if available.
- **Response Expectations:** Reports are acknowledged promptly, triaged for severity, and resolved with coordinated disclosure once a fix is merged.

---

## Security Architecture & Controls

KeyVault enforces defense-in-depth across authentication, credential storage, request filtering, and data export:

1. **One-Way Credential Storage:**
   - Raw API keys (`kv_live_...`) are generated via `java.security.SecureRandom` (256-bit entropy) and returned **only once** at creation, regeneration, rotation, or duplication.
   - Only one-way SHA-256 hex digests and masked previews (`kv_live_••••••••abcd`) are persisted in PostgreSQL.
   - User passwords are salted and hashed with **BCrypt**, with a 72-character upper bound enforced at request validation to prevent silent truncation or oversized-payload CPU exhaustion.

2. **JWT & Authentication Hardening:**
   - JWTs are signed using HMAC-SHA256 (`JJWT`). Configured `JWT_SECRET` values shorter than 32 bytes (256 bits) fail fast at startup.
   - User email addresses are trimmed and lowercased consistently across registration, login, profile lookups, and password changes to prevent duplicate-account case ambiguities.
   - Password changes verify the current password and reject reuse of the identical password.

3. **API Key Access Controls & Abuse Mitigation:**
   - **Granular Scopes:** Protected routes enforce `KEY_READ` / `KEY_WRITE` authorities.
   - **IP & CIDR Whitelisting:** `IpUtils` restricts authentication to explicit IPv4/IPv6 literals or CIDR ranges (`0..32` / `0..128` prefix bounds) without performing blocking DNS lookups on untrusted `X-Forwarded-For` inputs.
   - **Sliding-Window Rate Limiting:** Per-key synchronized sliding windows enforce configurable per-minute limits and return HTTP `429 Too Many Requests` with standard `Retry-After` and `X-RateLimit-*` headers.
   - **Pause / Revoke / Expiry:** Revoked, paused, or expired keys are rejected with `401 Unauthorized`.

4. **Tenant Isolation & Safe Error Handling:**
   - Cross-user key lookups, mutations, exports, and audit/usage queries return `404 Not Found` to prevent resource ID enumeration.
   - `GlobalExceptionHandler` normalizes validation, malformed JSON, type mismatch, and method-not-supported errors into uniform `ErrorResponse` payloads without exposing Java class names or stack traces.

5. **Export & Browser Protections:**
   - **CSV Formula Injection Mitigation (CWE-1236):** `CsvUtils` prefixes leading spreadsheet formula triggers (`=`, `+`, `-`, `@`, tab, carriage return) with `'` across all catalog, usage, and audit CSV exports.
   - **HTTP Security Headers:** `SecurityConfig` enforces `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, and `Permissions-Policy: geolocation=(), microphone=(), camera=()`.
   - **Unprivileged Runtime Container:** The production Docker image runs as a non-root `keyvault` user on a JRE-only Alpine base image.
