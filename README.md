# KeyVault — API Key Management & Access Control Platform

[![CI](https://github.com/kritagya025/KeyVault/actions/workflows/ci.yml/badge.svg)](https://github.com/kritagya025/KeyVault/actions/workflows/ci.yml)
[![Java 17](https://img.shields.io/badge/Java-17-orange)](https://adoptium.net/)
[![Spring Boot 3.4.2](https://img.shields.io/badge/Spring%20Boot-3.4.2-brightgreen)](https://spring.io/projects/spring-boot)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue)](LICENSE)

KeyVault is a lightweight, secure Spring Boot 3 backend service built for API Key Management, Dual Authentication (JWT & `X-API-Key`), One-Way Hashed Key Persistence, Granular Access Control (`READ`, `WRITE`), and Real-Time API Usage Tracking.

---

## Project Overview

KeyVault addresses key lifecycle management and access control in backend architectures without storing plaintext credentials.

- **User Authentication**: JWT-based access for developers/users managing their keys.
- **One-Way Hashing**: Raw API keys (`kv_live_...`) are returned only once upon generation/regeneration. Only SHA-256 hashes are persisted in PostgreSQL.
- **Granular Permissions**: API keys can be scoped with `READ` or `WRITE` permissions.
- **Lifecycle Management**: View, revoke, and regenerate keys with dynamic status calculation (`ACTIVE`, `REVOKED`, `EXPIRED`).
- **Usage Tracking**: Intercepts requests to record endpoint calls, HTTP methods, response status codes, and success metrics per key without logging sensitive data.

---

## Architecture

```text
Client Application (Consumer)         Developer / Dashboard User
       │ (X-API-Key)                         │ (Authorization: Bearer <JWT>)
       ▼                                     ▼
┌──────────────────────────────────────────────────────────────────────┐
│                        Spring Security Filter Chain                   │
│  ┌───────────────────────────┐     ┌──────────────────────────────┐  │
│  │ ApiKeyAuthenticationFilter│     │    JwtAuthenticationFilter   │  │
│  └─────────────┬─────────────┘     └──────────────┬───────────────┘  │
└────────────────┼──────────────────────────────────┼──────────────────┘
                 │                                  │
                 ▼                                  ▼
┌──────────────────────────────────┐┌──────────────────────────────────┐
│      ProtectedController         ││    ApiKeyController / User       │
│   (@PreAuthorize("KEY_READ"))    ││   (Key Lifecycle / Usage Stats)  │
└────────────────┬─────────────────┘└────────────────┬─────────────────┘
                 │                                   │
                 ▼                                   ▼
┌──────────────────────────────────┐┌──────────────────────────────────┐
│          ApiUsageFilter          ││   ApiKeyService / UserService    │
│    (Records endpoint metrics)    ││    (SHA-256 Hashing / Logic)     │
└────────────────┬─────────────────┘└────────────────┬─────────────────┘
                 │                                   │
                 └─────────────────┬─────────────────┘
                                   ▼
                   ┌──────────────────────────────┐
                   │    PostgreSQL Database       │
                   │ (users, api_keys, api_usage) │
                   └──────────────────────────────┘
```

---

## Dual Authentication & Authorization

| Authentication Type | Header | Target Audience | Primary Use Case |
| :--- | :--- | :--- | :--- |
| **JWT Bearer Token** | `Authorization: Bearer <token>` | Developers / Platform Users | Registering, logging in, generating, viewing, revoking, and analyzing API keys. |
| **API Key Header** | `X-API-Key: <raw-key>` | External Services / API Consumers | Accessing protected consumer endpoints with enforced `READ`/`WRITE` permissions. |

### Security HTTP Status Code Distinction
- **`401 Unauthorized`**: Authentication failure (missing, invalid, revoked, or expired API Key / JWT).
- **`403 Forbidden`**: Authenticated principal lacks required authority (e.g., calling write endpoint with a `READ`-only key).

---

## API Key Lifecycle

```text
       Generate Key (POST /api/keys)
                    │
                    ▼
          Returns Raw Key Once (kv_live_...)
          SHA-256 Hash stored in DB
                    │
                    ▼
           ┌────────────────┐
           │     ACTIVE     │
           └───────┬────────┘
                   │
         ┌─────────┴─────────┐
         ▼                   ▼
Revoke Key (PATCH)   Key Expires (expiresAt < now)
         │                   │
         ▼                   ▼
 ┌──────────────┐    ┌──────────────┐
 │   REVOKED    │    │   EXPIRED    │
 └──────────────┘    └───────┬──────┘
                             │
                             ▼
                 Regenerate Key (POST /api/keys/{id}/regenerate)
                 (New raw key issued, new hash stored)
```

### Regeneration Semantics
- Regeneration replaces the stored hash, so the previous raw key stops authenticating immediately.
- Regenerating an `ACTIVE` key leaves its expiry untouched.
- Regenerating an `EXPIRED` key re-anchors its original validity window from the moment of regeneration, returning the key to `ACTIVE`. A key created with a 30-day window therefore gets another 30 days, and the newly issued raw key is usable right away rather than being born expired.
- Regenerating a `REVOKED` key is rejected with `400 Bad Request`. Revocation is terminal.

---

## API Usage Tracking Flow

Requests using a valid API key are intercepted and logged:

```text
X-API-Key Request -> Authenticate Key -> Check Permissions -> Controller -> ApiUsageFilter Logs (Endpoint, Status Code, Success Flag, Timestamp)
```

- **Zero Secret Exposure**: `api_usage` records reference only `api_key_id`. Raw API keys and hashes are never stored in usage logs.
- **Privacy Enforcement**: Unauthenticated/invalid API key requests (`401 Unauthorized`) are not tracked.

---

## Technology Stack

- **Java**: 17
- **Framework**: Spring Boot 3.4.2 (Spring Web, Spring Data JPA, Spring Security, Validation)
- **Documentation**: Springdoc OpenAPI 2.8.4 (Swagger UI)
- **Database**: PostgreSQL (runtime), H2 in PostgreSQL compatibility mode (tests)
- **Testing**: JUnit 5, Mockito, MockMvc, Spring Boot Test
- **Frontend**: Bundled dashboard in vanilla HTML/CSS/ES modules (no build step)
- **Build & Deploy**: Maven Wrapper, multi-stage Docker build, Docker Compose, GitHub Actions
- **Utilities**: Lombok, JJWT 0.12.6, BCrypt, SHA-256

---

## Configuration

Every setting is read from an environment variable with a development-friendly default. No credentials or signing secrets are committed to this repository.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `DB_URL` | `jdbc:postgresql://localhost:5432/keyvault_db` | JDBC connection string. |
| `DB_USERNAME` | `postgres` | Database user. |
| `DB_PASSWORD` | `postgres` | Database password. |
| `JWT_SECRET` | *(empty)* | HMAC signing secret, minimum 32 bytes. See the note below. |
| `JWT_EXPIRATION` | `86400000` | Access token lifetime in milliseconds (24 hours). |
| `SERVER_PORT` | `8080` | HTTP port. |
| `JPA_DDL_AUTO` | `update` | Hibernate schema management strategy. |
| `LOG_LEVEL` | `INFO` | Log level for the `com.keyvault` package. |

**About `JWT_SECRET`**: when it is unset, the application generates a random signing key at startup and logs a warning. Local development works out of the box, but every issued token is invalidated on restart. Set a real secret in any deployed environment:

```bash
export JWT_SECRET="$(openssl rand -hex 32)"
```

A secret shorter than 32 bytes is rejected at startup rather than silently weakening token signatures. Copy `.env.example` to `.env` to keep local overrides out of version control.

---

## Running Locally

### Option A: Docker Compose (recommended)

Brings up PostgreSQL and KeyVault together, with no local Java or database setup:

```bash
cp .env.example .env      # optional, for a persistent JWT secret
docker compose up --build
```

The API is then available at `http://localhost:8080`. Tear it down with `docker compose down` (add `-v` to drop the database volume).

### Option B: Maven Wrapper

#### 1. Configure PostgreSQL
Ensure PostgreSQL is running locally on port `5432` with database `keyvault_db`:
```sql
CREATE DATABASE keyvault_db;
```

#### 2. Set Environment Variables
```bash
export DB_URL="jdbc:postgresql://localhost:5432/keyvault_db"
export DB_USERNAME="postgres"
export DB_PASSWORD="your_password"
export JWT_SECRET="$(openssl rand -hex 32)"
```

#### 3. Build and Run Application
The wrapper pins the Maven version, so no local Maven install is required (use `mvnw.cmd` on Windows):
```bash
./mvnw clean package -DskipTests
java -jar target/keyvault-0.0.1-SNAPSHOT.jar
```

Or run it directly during development:
```bash
./mvnw spring-boot:run
```

### Web Dashboard

A dashboard is bundled into the jar and served at the application root:

`http://localhost:8080/`

It is plain HTML, CSS, and ES modules under `src/main/resources/static/` — no Node toolchain, no build step, and no separate deployment. Because it is served from the same origin as the API, no CORS configuration is involved; it authenticates with the same JWT any other client would use.

| Capability | Detail |
| :--- | :--- |
| **Register / sign in** | Stores the returned JWT in `localStorage` and restores the session on reload. A rejected token signs the user out automatically. |
| **Key table** | Name, derived status badge (`ACTIVE` / `REVOKED` / `EXPIRED`), permissions, creation and expiry timestamps. |
| **Create key** | Name, `READ` / `WRITE` selection, and an optional expiry. The raw key is revealed once in a dialog with a copy button and is never shown again. |
| **Regenerate / revoke** | Destructive actions use a two-step in-button confirm. Revoked keys lose both actions, matching the server rule that revocation is terminal. |
| **Usage** | Total, successful, and failed request counts for the selected key, plus its ten most recent requests. |
| **Endpoint tester** | Calls `/api/protected/*` with a raw key so `200` / `401` / `403` outcomes are visible directly in the UI. |

`SecurityConfig` permits `GET` on the dashboard's static paths (`/`, `/index.html`, `/css/**`, `/js/**`) so the login page can load; every `/api/**` route stays protected. `DashboardAccessIntegrationTest` guards both halves of that rule.

### Interactive API Documentation (Swagger UI)
Access the interactive OpenAPI interface at:
`http://localhost:8080/swagger-ui.html`

Use the **Authorize** button in Swagger UI to test endpoints:
- **`BearerAuth`**: Enter JWT token for user and key management endpoints.
- **`ApiKeyAuth`**: Enter raw `X-API-Key` for protected consumer endpoints.

---

## Complete API Endpoints Reference

### 1. Health Check
| Method | Endpoint | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/health` | Public | Service health check (`UP`). |

### 2. User Authentication
| Method | Endpoint | Auth | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/auth/register` | Public | Register new user account (`name`, `email`, `password`). |
| `POST` | `/api/auth/login` | Public | Authenticate user, returns JWT `accessToken`. |
| `GET` | `/api/users/me` | JWT | Retrieve current authenticated user profile. |

### 3. API Key Management & Usage
| Method | Endpoint | Auth | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/keys` | JWT | Generate new API key with permissions (e.g. `["READ", "WRITE"]`). Returns raw key once. |
| `GET` | `/api/keys` | JWT | List all API keys owned by current user. |
| `GET` | `/api/keys/{id}` | JWT | Get single API key metadata, permissions, and status. |
| `PATCH` | `/api/keys/{id}/revoke` | JWT | Revoke an API key immediately (`REVOKED`). |
| `POST` | `/api/keys/{id}/regenerate` | JWT | Regenerate an `ACTIVE` or `EXPIRED` key. Issues new raw key once. |
| `GET` | `/api/keys/{id}/usage` | JWT | Get aggregate request statistics (`totalRequests`, `successfulRequests`, `failedRequests`). |
| `GET` | `/api/keys/{id}/usage/recent` | JWT | Get top 10 recent request log records for an API key. |

### 4. Protected Consumer APIs
| Method | Endpoint | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/protected/hello` | API Key | Basic protected consumer endpoint. |
| `GET` | `/api/protected/read` | API Key | Consumer read endpoint (Requires `READ` permission). |
| `POST` | `/api/protected/write` | API Key | Consumer write endpoint (Requires `WRITE` permission). |

---

## Quick cURL Testing Examples

### 1. Register & Login
```bash
# Register
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Alex","email":"alex@example.com","password":"password123"}'

# Login
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alex@example.com","password":"password123"}'
```

### 2. Generate API Key
```bash
curl -X POST http://localhost:8080/api/keys \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"name":"Production Key","permissions":["READ","WRITE"]}'
```

### 3. Consume Protected Endpoint with API Key
```bash
curl -X GET http://localhost:8080/api/protected/read \
  -H "X-API-Key: kv_live_<RAW_KEY>"
```

---

## Testing

The suite runs against an in-memory H2 database in PostgreSQL compatibility mode, so it needs no local PostgreSQL instance and no Docker:

```bash
./mvnw test
```

50 tests across two layers:

| Layer | Coverage |
| :--- | :--- |
| **Unit** (`ApiKeyServiceTest`, `AuthServiceTest`, `ApiUsageServiceTest`, `ApiKeyGeneratorTest`, `JwtUtilsTest`) | Key hashing and SHA-256 digests, permission defaulting, expiry validation, revocation idempotency, regeneration windows, BCrypt password handling, JWT signing, expiry and secret validation. |
| **Integration** (`*IntegrationTest`) | Full request path through the Spring Security filter chain: registration and login, dual authentication, `READ`/`WRITE` permission enforcement, key lifecycle, ownership isolation, usage tracking, key regeneration, and dashboard asset access. |

The `test` profile lives in `src/test/resources/application-test.yml`. Every test class is annotated `@ActiveProfiles("test")`, so no production configuration is ever loaded during a test run.

### Continuous Integration

`.github/workflows/ci.yml` runs the full build on every push and pull request to `main`, then builds the container image. Because tests use H2, CI requires no database service container.

---

## Security Summary

1. **BCrypt Password Hashing**: User passwords are encrypted using BCrypt prior to persistence.
2. **SHA-256 Key Hashing**: Raw API keys are never stored. Only hex SHA-256 digests are stored in PostgreSQL.
3. **One-Time Key Emission**: Raw keys (`kv_live_...`) are returned only once upon creation/regeneration.
4. **Ownership Protection**: Cross-user access returns `404 Not Found` to prevent resource enumeration.
5. **No Secret Leaks**: Passwords, raw keys, and key hashes are omitted from JSON outputs and system logs.
6. **No Committed Credentials**: Database credentials and the JWT signing secret are supplied through environment variables. The repository ships defaults for local development only, and the application refuses a signing secret weaker than 256 bits.
7. **Unprivileged Container**: The Docker image runs as a non-root user and contains only a JRE and the application jar.

---

## License

Released under the [MIT License](LICENSE).
