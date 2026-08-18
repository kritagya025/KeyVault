# KeyVault — API Key Management & Access Control Platform

KeyVault is a lightweight Spring Boot 3 backend application designed for secure user management, authentication, and API key generation with SHA-256 hashed persistence.

---

## Features

- **User Authentication**: Secure user registration and login powered by Spring Security, BCrypt password hashing, and JWT (JSON Web Tokens).
- **API Key Generation**: Cryptographically secure API key generation (`kv_live_...`) with 256 bits of entropy.
- **One-Way Hash Persistence**: Raw API keys are returned **only once** upon creation and are **never stored** in the database. Only SHA-256 hashes (`keyHash`) are persisted.
- **Access Isolation**: Strict ownership enforcement ensuring users can only view and manage their own API keys.
- **PostgreSQL Database**: Relational schema mapping `User (1) <-> (*) ApiKey`.

---

## Tech Stack

- **Java**: 17
- **Framework**: Spring Boot 3.4.2 (Spring Web, Spring Data JPA, Spring Security, Validation)
- **Database**: PostgreSQL
- **Utilities**: Lombok, JJWT 0.12.6, BCrypt

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

### 2. Authentication
- `POST /api/auth/register` — Register a new account (`name`, `email`, `password`).
- `POST /api/auth/login` — Log in with credentials (`email`, `password`), returns JWT `accessToken`.

### 3. User Profile
- `GET /api/users/me` — Retrieve current authenticated user profile (`Authorization: Bearer <JWT>`).

### 4. API Key Management
- `POST /api/keys` — Generate a new API key (`Authorization: Bearer <JWT>`). Returns raw API key **once**.
- `GET /api/keys` — List metadata for all API keys owned by the authenticated user.

---

## Sample Request & Response

### Generate API Key (`POST /api/keys`)
**Header:** `Authorization: Bearer <JWT>`
**Request Body:**
```json
{
  "name": "Production Key",
  "expiresAt": "2026-12-31T23:59:59"
}
```

**Response (`201 Created`):**
```json
{
  "id": 1,
  "name": "Production Key",
  "apiKey": "kv_live_gJgsNQ6r26d1qVH_4yY-hwTI3Y--bET3XPoOo-XAJHM",
  "expiresAt": "2026-12-31T23:59:59",
  "createdAt": "2026-08-18T15:44:44.241",
  "revoked": false
}
```

---

## Security Model

1. **Raw Key One-Time Display**: The raw API key (`kv_live_...`) is generated using `SecureRandom` and returned only once during creation.
2. **SHA-256 Hashing**: Only the hex-encoded SHA-256 hash of the API key is stored in PostgreSQL.
3. **No Console / Log Leaks**: Raw API keys are never printed to system logs or application output.
