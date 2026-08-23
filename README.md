# KeyVault — API Key Management & Access Control Platform

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
- **Database**: PostgreSQL
- **Testing**: JUnit 5, MockMvc, Spring Boot Test
- **Utilities**: Lombok, JJWT 0.12.6, BCrypt, SHA-256

---

## Running Locally

### 1. Configure PostgreSQL
Ensure PostgreSQL is running locally on port `5432` with database `keyvault_db`:
```sql
CREATE DATABASE keyvault_db;
```

### 2. Set Environment Variables (Optional)
```bash
export DB_URL="jdbc:postgresql://localhost:5432/keyvault_db"
export DB_USERNAME="postgres"
export DB_PASSWORD="your_password"
```

### 3. Build and Run Application
```bash
mvn clean package -DskipTests
java -jar target/keyvault-0.0.1-SNAPSHOT.jar
```

### 4. Interactive API Documentation (Swagger UI)
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

## Security Summary

1. **BCrypt Password Hashing**: User passwords are encrypted using BCrypt prior to persistence.
2. **SHA-256 Key Hashing**: Raw API keys are never stored. Only hex SHA-256 digests are stored in PostgreSQL.
3. **One-Time Key Emission**: Raw keys (`kv_live_...`) are returned only once upon creation/regeneration.
4. **Ownership Protection**: Cross-user access returns `404 Not Found` to prevent resource enumeration.
5. **No Secret Leaks**: Passwords, raw keys, and key hashes are omitted from JSON outputs and system logs.
