# KeyVault — API Key Management & Access Control Platform

KeyVault is a lightweight Spring Boot 3 backend application designed for secure user management, authentication, full API key lifecycle management, API key authentication via SHA-256 hashed persistence, and granular API key permissions (`READ`, `WRITE`).

---

## Features

- **Dual Authentication Architecture**:
  - **JWT Authentication (`Authorization: Bearer <JWT>`)**: Used by users/dashboard to register, log in, view profile, and manage API keys.
  - **API Key Authentication (`X-API-Key: <api-key>`)**: Used by external clients/consumers to access protected APIs.
- **Granular API Key Permissions**:
  - `READ`: Allows read-only access to consumer API endpoints (e.g. `GET /api/protected/read`).
  - `WRITE`: Allows write operations on consumer API endpoints (e.g. `POST /api/protected/write`).
- **HTTP Security Status Distinction**:
  - `401 Unauthorized`: Returned when authentication fails (missing, invalid, revoked, or expired API Key / JWT).
  - `403 Forbidden`: Returned when an authenticated client/key lacks the required permission (e.g., calling write endpoint with a `READ`-only key).
- **One-Way Hash Persistence**: Raw API keys are returned **only once** upon creation/regeneration and are **never stored** in PostgreSQL. Only SHA-256 hashes (`keyHash`) are persisted.
- **Derived Status & Lifecycle Management**: View, revoke, and regenerate API keys with dynamically calculated status states:
  - `ACTIVE`: Key is valid, not revoked, and expiration date has not passed.
  - `REVOKED`: Key has been explicitly revoked (`revoked = true`). Cannot be regenerated or used for authentication.
  - `EXPIRED`: Key expiration date has passed (`expiresAt < now()`). Cannot be used for authentication; can be regenerated.
- **Access & Ownership Security**: Strict ownership enforcement ensuring users can only view, revoke, or regenerate their own API keys (`404 Not Found` for unauthorized access).
- **PostgreSQL Database**: Relational schema mapping `User (1) <-> (*) ApiKey` with `@ElementCollection` mapping for `api_key_permissions`.

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
- `POST /api/keys` — Generate a new API key with permissions e.g. `["READ", "WRITE"]` (`Authorization: Bearer <JWT>`). Returns raw API key **once**.
- `GET /api/keys` — List metadata and permissions for all API keys owned by the authenticated user.
- `GET /api/keys/{id}` — View single API key metadata (`status`, `permissions`, `createdAt`, `expiresAt`, `revoked`).
- `PATCH /api/keys/{id}/revoke` — Revoke an API key. Sets status to `REVOKED`.
- `POST /api/keys/{id}/regenerate` — Regenerate an `ACTIVE` or `EXPIRED` key. Replaces old hash with new SHA-256 hash and returns new raw API key **once**.

### 4. Protected Consumer API (API Key Authenticated)
- `GET /api/protected/hello` — Access protected API endpoint (`X-API-Key: <api-key>`).
- `GET /api/protected/read` — Read protected endpoint (Requires `READ` permission).
- `POST /api/protected/write` — Write protected endpoint (Requires `WRITE` permission).

---

## Sample Request & Response

### Create API Key with Permissions (`POST /api/keys`)
**Header:** `Authorization: Bearer <JWT>`
**Request Body:**
```json
{
  "name": "Backend Service Key",
  "permissions": ["READ", "WRITE"]
}
```

**Response (`201 Created`):**
```json
{
  "id": 1,
  "name": "Backend Service Key",
  "apiKey": "kv_live_PVDhHrioIt4Wbps2k3M6QsR3cU6xufo_qDurok5J0vA",
  "expiresAt": null,
  "createdAt": "2026-08-18T16:27:03.280",
  "revoked": false,
  "permissions": ["READ", "WRITE"]
}
```

### Accessing Write Endpoint with READ-Only Key (`POST /api/protected/write`)
**Header:** `X-API-Key: <read-only-key>`

**Response (`403 Forbidden`):**
```json
{
  "error": "Forbidden"
}
```

---

## Security Model

1. **Raw Key One-Time Display**: Raw API keys (`kv_live_...`) are returned only once during creation or regeneration.
2. **SHA-256 Hashing**: Only the hex-encoded SHA-256 hash of the API key is stored in PostgreSQL.
3. **No Console / Log Leaks**: Raw API keys are never printed to system logs or application output.
4. **Ownership Protection**: Requests targeting API keys owned by another user return `404 Not Found`.
5. **Role vs Permission Separation**:
   - `JWT`: Identifies the user managing KeyVault.
   - `API Key`: Identifies the consuming client application.
   - `Permissions` (`READ`, `WRITE`): Determines what operations the API key can execute.
