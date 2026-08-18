# KeyVault — API Key Management & Access Control Platform

KeyVault is a lightweight, secure Spring Boot 3 backend service built for API Key Management, Dual Authentication (JWT & `X-API-Key`), One-Way Hashed Key Persistence, Granular Access Control (`READ`, `WRITE`), and Real-Time API Usage Tracking.

---

## 📌 Project Overview

KeyVault solves the critical security problem of exposing raw secrets and managing API key lifecycles in modern distributed backend architectures. It provides:
1. **User Authentication**: Secure JWT-based management portal for developers/users.
2. **One-Way Hashing**: Raw API keys (`kv_live_...`) are returned **only once** upon generation/regeneration. Only SHA-256 hashes are persisted in PostgreSQL.
3. **Granular Permissions**: API keys can be scoped with `READ` or `WRITE` permissions.
4. **Lifecycle Management**: View, revoke, and regenerate keys with dynamic status calculation (`ACTIVE`, `REVOKED`, `EXPIRED`).
5. **Usage Tracking**: Intercepts requests to record endpoint calls, HTTP method, response status codes, and success metrics per key without storing secrets.

---

## 🏗️ Architecture

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

## 🔐 Dual Authentication & Authorization

| Authentication Type | Header | Target Audience | Primary Use Case |
| :--- | :--- | :--- | :--- |
| **JWT Bearer Token** | `Authorization: Bearer <token>` | Developers / Platform Users | Registering, logging in, generating, viewing, revoking, and analyzing API keys. |
| **API Key Header** | `X-API-Key: <raw-key>` | External Services / API Consumers | Accessing protected consumer endpoints with enforced `READ`/`WRITE` permissions. |

### Security HTTP Status Code Distinction
- **`401 Unauthorized`**: Returned when authentication fails (missing, invalid, revoked, or expired API Key / JWT).
- **`403 Forbidden`**: Returned when an authenticated API key lacks the required permission (e.g. calling write endpoint with a `READ`-only key).

---

## 🔄 API Key Lifecycle

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

## 📊 API Usage Tracking Flow

Every request using a valid API key is intercepted and logged:
```text
X-API-Key Request ➔ Authenticate Key ➔ Check Permissions ➔ Controller ➔ ApiUsageFilter Logs (Endpoint, Status Code, Success Flag, Timestamp)
```
- **Zero Secret Exposure**: `api_usage` records reference only `api_key_id`. Raw API keys and key hashes are **never stored** in usage logs.
- **Security Privacy**: Unknown/invalid API key requests (`401 Unauthorized`) are **never tracked**.

---

## 🛠️ Technology Stack

- **Java**: 17
- **Framework**: Spring Boot 3.4.2 (Spring Web, Spring Data JPA, Spring Security, Validation)
- **Documentation**: Springdoc OpenAPI 2.8.4 (Swagger UI)
- **Database**: PostgreSQL
- **Testing**: JUnit 5, MockMvc, Spring Boot Test
- **Utilities**: Lombok, JJWT 0.12.6, BCrypt, SHA-256

---

## 🚀 Running Locally

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
Open your browser and navigate to:
👉 **`http://localhost:8080/swagger-ui.html`**

Use the **Authorize** button in Swagger UI to test endpoints with:
- **`BearerAuth`**: Enter your JWT token for user/key management endpoints.
- **`ApiKeyAuth`**: Enter your raw `X-API-Key` for protected consumer endpoints.

---

## 📋 Complete API Endpoints Reference

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
| `POST` | `/api/keys` | JWT | Generate new API key with permissions e.g. `["READ", "WRITE"]`. Returns raw key **once**. |
| `GET` | `/api/keys` | JWT | List all API keys owned by current user. |
| `GET` | `/api/keys/{id}` | JWT | Get single API key metadata, permissions, and status. |
| `PATCH` | `/api/keys/{id}/revoke` | JWT | Revoke an API key immediately (`REVOKED`). |
| `POST` | `/api/keys/{id}/regenerate` | JWT | Regenerate an `ACTIVE` or `EXPIRED` key. Issues new raw key **once**. |
| `GET` | `/api/keys/{id}/usage` | JWT | Get aggregate request statistics (`totalRequests`, `successfulRequests`, `failedRequests`). |
| `GET` | `/api/keys/{id}/usage/recent` | JWT | Get top 10 recent request log records for an API key. |

### 4. Protected Consumer APIs
| Method | Endpoint | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/protected/hello` | API Key | Basic protected consumer endpoint. |
| `GET` | `/api/protected/read` | API Key | Consumer read endpoint (Requires `READ` permission). |
| `POST` | `/api/protected/write` | API Key | Consumer write endpoint (Requires `WRITE` permission). |

---

## 🔒 Security Summary

1. **BCrypt Password Hashing**: User passwords are encrypted using BCrypt before persistence.
2. **SHA-256 Key Hashing**: Raw API keys are never stored. Only hex SHA-256 digests are stored in PostgreSQL.
3. **One-Time Key Emission**: Raw keys (`kv_live_...`) are returned only once upon creation/regeneration.
4. **Ownership Protection**: Cross-user access returns `404 Not Found` to prevent resource enumeration.
5. **No Secret Leaks**: Passwords, raw keys, and key hashes are omitted from JSON outputs and system logs.
