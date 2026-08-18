# KeyVault — API Key Management & Access Control Platform

KeyVault is a lightweight Spring Boot 3 backend application designed for secure user management, authentication, full API key lifecycle management, API key authentication via SHA-256 hashed persistence, granular permissions (`READ`, `WRITE`), and API usage tracking.

---

## Features

- **Dual Authentication Architecture**:
  - **JWT Authentication (`Authorization: Bearer <JWT>`)**: Used by users/dashboard to register, log in, view profile, manage API keys, and query usage statistics.
  - **API Key Authentication (`X-API-Key: <api-key>`)**: Used by external clients/consumers to access protected APIs.
- **Granular API Key Permissions**:
  - `READ`: Allows read-only access to consumer API endpoints (e.g. `GET /api/protected/read`).
  - `WRITE`: Allows write operations on consumer API endpoints (e.g. `POST /api/protected/write`).
- **HTTP Security Status Distinction**:
  - `401 Unauthorized`: Returned when authentication fails (missing, invalid, revoked, or expired API Key / JWT).
  - `403 Forbidden`: Returned when an authenticated client/key lacks the required permission (e.g., calling write endpoint with a `READ`-only key).
- **Automatic API Usage Tracking**:
  - Automatically records endpoint, HTTP method, response status code, success flag, and timestamp for requests using valid API keys.
  - Captures both successful (`200 OK`) and failed operations (`403 Forbidden`, `400 Bad Request`, `500 Error`).
  - Unknown/invalid keys (`401 Unauthorized`) are **never recorded** in usage tables.
  - **Zero Secret Exposure**: Usage records reference only the `ApiKey` entity ID. Raw API keys and key hashes are **never stored** in the usage table.
- **One-Way Hash Persistence**: Raw API keys are returned **only once** upon creation/regeneration and are **never stored** in PostgreSQL. Only SHA-256 hashes (`keyHash`) are persisted.
- **Derived Status & Lifecycle Management**: View, revoke, and regenerate API keys with dynamically calculated status states:
  - `ACTIVE`: Key is valid, not revoked, and expiration date has not passed.
  - `REVOKED`: Key has been explicitly revoked (`revoked = true`). Cannot be regenerated or used for authentication.
  - `EXPIRED`: Key expiration date has passed (`expiresAt < now()`). Cannot be used for authentication; can be regenerated.
- **Access & Ownership Security**: Strict ownership enforcement ensuring users can only view, revoke, regenerate, or view usage stats for their own API keys (`404 Not Found` for unauthorized access).
- **PostgreSQL Database**: Relational schema mapping `User (1) <-> (*) ApiKey (1) <-> (*) ApiUsage`.

---

## Complete Request & Security Flow

```text
Client Request
      ↓
X-API-Key Header Check (ApiKeyAuthenticationFilter)
      ↓
Validate Hash & Expiration / Revocation Status
      ↓
Permission Authorization Check (@PreAuthorize)
      ↓
Protected Controller Execution
      ↓
Response Generated (200 OK / 403 Forbidden / 400 Bad Request)
      ↓
ApiUsageFilter Captures Status & Endpoint
      ↓
Persist ApiUsage Record to PostgreSQL (api_usage)
```

---

## Tech Stack

- **Java**: 17
- **Framework**: Spring Boot 3.4.2 (Spring Web, Spring Data JPA, Spring Security, Validation)
- **Database**: PostgreSQL
- **Utilities**: Lombok, JJWT 0.12.6, BCrypt, SHA-256

---

## Configuration & Setup

### Database Configuration
Set environment variables or use default local PostgreSQL credentials:

```bash
export DB_URL="jdbc:postgresql://localhost:5432/keyvault_db"
export DB_USERNAME="postgres"
export DB_PASSWORD="your_password"
```

### Build and Run
```bash
mvn clean package -DskipTests
java -jar target/keyvault-0.0.1-SNAPSHOT.jar
```

---

## API Endpoints

### 1. Health Check
- `GET /api/health` — Returns status `UP` (Public).

### 2. User Authentication (JWT)
- `POST /api/auth/register` — Register a new account (`name`, `email`, `password`).
- `POST /api/auth/login` — Log in with credentials (`email`, `password`), returns JWT `accessToken`.
- `GET /api/users/me` — Retrieve current authenticated user profile (`Authorization: Bearer <JWT>`).

### 3. API Key Management (JWT)
- `POST /api/keys` — Generate a new API key e.g. `permissions: ["READ", "WRITE"]` (`Authorization: Bearer <JWT>`). Returns raw API key **once**.
- `GET /api/keys` — List metadata and permissions for all API keys owned by the authenticated user.
- `GET /api/keys/{id}` — View single API key metadata (`status`, `permissions`, `createdAt`, `expiresAt`, `revoked`).
- `PATCH /api/keys/{id}/revoke` — Revoke an API key. Sets status to `REVOKED`.
- `POST /api/keys/{id}/regenerate` — Regenerate an `ACTIVE` or `EXPIRED` key. Replaces old hash with new SHA-256 hash and returns new raw API key **once**.

### 4. API Key Usage Statistics (JWT)
- `GET /api/keys/{id}/usage` — Retrieve aggregate usage metrics (`totalRequests`, `successfulRequests`, `failedRequests`). Requires JWT authentication & key ownership.
- `GET /api/keys/{id}/usage/recent` — Retrieve up to 10 most recent usage records for an API key (`endpoint`, `method`, `statusCode`, `successful`, `timestamp`). Requires JWT authentication & key ownership.

### 5. Protected Consumer API (API Key Authenticated)
- `GET /api/protected/hello` — Access protected API endpoint (`X-API-Key: <api-key>`).
- `GET /api/protected/read` — Read protected endpoint (Requires `READ` permission).
- `POST /api/protected/write` — Write protected endpoint (Requires `WRITE` permission).

---

## Sample Request & Response

### 1. Create API Key with Permissions (`POST /api/keys`)
**Header:** `Authorization: Bearer <JWT>`
**Request Body:**
```json
{
  "name": "Production Service Key",
  "permissions": ["READ"]
}
```

**Response (`201 Created`):**
```json
{
  "id": 1,
  "name": "Production Service Key",
  "apiKey": "kv_live_PVDhHrioIt4Wbps2k3M6QsR3cU6xufo_qDurok5J0vA",
  "expiresAt": null,
  "createdAt": "2026-08-18T16:31:16.850",
  "revoked": false,
  "permissions": ["READ"]
}
```

### 2. Fetch Usage Statistics (`GET /api/keys/1/usage`)
**Header:** `Authorization: Bearer <JWT>`

**Response (`200 OK`):**
```json
{
  "apiKeyId": 1,
  "totalRequests": 2,
  "successfulRequests": 1,
  "failedRequests": 1
}
```

### 3. Fetch Recent Usage Log (`GET /api/keys/1/usage/recent`)
**Header:** `Authorization: Bearer <JWT>`

**Response (`200 OK`):**
```json
[
  {
    "endpoint": "/api/protected/write",
    "method": "POST",
    "statusCode": 403,
    "successful": false,
    "timestamp": "2026-08-18T16:31:16.898"
  },
  {
    "endpoint": "/api/protected/read",
    "method": "GET",
    "statusCode": 200,
    "successful": true,
    "timestamp": "2026-08-18T16:31:16.877"
  }
]
```

---

## Security Architecture

1. **Raw Key One-Time Display**: Raw API keys (`kv_live_...`) are returned only once during creation or regeneration.
2. **SHA-256 Hashing**: Only the hex-encoded SHA-256 hash of the API key is stored in PostgreSQL.
3. **No Console / Log Leaks**: Raw API keys are never printed to system logs or application output.
4. **Usage Privacy**: Usage records reference only the `ApiKey` entity ID. Neither raw keys nor key hashes exist in the `api_usage` table.
5. **Ownership Protection**: Requests targeting API keys or usage stats owned by another user return `404 Not Found`.
