# 🔐 @omnixys/security-ts

> **Zero Trust Security Framework for NestJS**
> JWT Validation · JWE Sessions · RBAC · Risk Engine · Distributed Security

---

## 📦 Overview

`@omnixys/security-ts` ist ein **modulares Security Framework** für NestJS mit Fokus auf:

* **Zero Trust Authentication**
* **JWT + JWKS Validation (Keycloak / OAuth2 ready)**
* **JWE Session Encryption (AES-256-GCM)**
* **Role-Based Access Control (RBAC)**
* **Risk-Based Access Decisions**
* **Device Fingerprinting**
* **Rate Limiting**
* **Distributed Security (Redis / Kafka ready)**
* **Audit Logging**
* **Token Revocation**

---

## 🧱 Architektur

```text
SecurityModule
 ├── AuthModule (JWT, Guards, Roles)
 ├── JweModule (Encrypted Sessions)
 ├── ZeroTrustModule (Risk Engine)
 ├── HashModule (Argon2, HMAC, AES)
 ├── RateLimitService
 ├── CookieService
 ├── SecureSessionService
 └── Distributed Integrations
```

---

## 🚀 Installation

```bash
pnpm add @omnixys/security-ts
```

---

## ⚙️ Quick Start

```ts
@Module({
  imports: [
    SecurityModule.forRoot({
      jwt: {
        issuer: 'https://keycloak',
        jwksUri: 'https://keycloak/protocol/openid-connect/certs',
        audience: 'account',
      },

      jwe: {
        keys: [
          {
            kid: 'v1',
            value: process.env.JWE_KEY_BASE64!,
          },
        ],
      },

      session: {
        ttlMs: 1000 * 60 * 60,
      },

      rateLimit: {
        enabled: true,
        defaultLimit: 100,
        defaultWindowMs: 60000,
      },

      cookie: {
        secure: true,
        sameSite: 'none',
      },

      hash: {
        pepper: process.env.HASH_PEPPER,
        encryptionKey: process.env.ENCRYPTION_KEY,
      },

      zeroTrust: {
        device: myDeviceStore,
        riskMemoryStore: myRiskStore,
      },

      distributed: {
        revocationStore: redisStore,
        rateLimitStore: redisRateLimit,
        auditProducer: kafkaProducer,
      },

      fingerprintSecret: process.env.FINGERPRINT_SECRET,

      globalGuards: true,
    }),
  ],
})
export class AppModule {}
```

---

## 🔐 Features Deep Dive

---

### 1. 🔑 Authentication (JWT + JWKS)

* RS256 Validation via JWKS
* Keycloak kompatibel
* Automatische Rollenextraktion

👉 JWT Strategy


👉 JWKS Client (Caching + Rate Limiting)


---

### 2. 👤 Roles & Authorization (RBAC)

#### Rollen extrahieren

* `realm_access.roles`
* `resource_access.*.roles`
* automatische Filterung technischer Rollen

👉 Role Extraction

👉 Role Filtering


---

#### Verwendung

```ts
@Roles('ADMIN')
@Get()
findAll() {}
```

👉 Decorator


👉 Guard


---

### 3. 🛡 Guards

| Guard           | Zweck                |
| --------------- | -------------------- |
| HeaderAuthGuard | Bearer Token         |
| CookieAuthGuard | Cookie-basierte Auth |
| RoleGuard       | RBAC                 |
| ZeroTrustGuard  | Risk-Based Access    |

👉 Header Guard


👉 Cookie Guard


---

### 4. 👤 Current User

```ts
@Get()
getMe(@CurrentUser() user) {
  return user;
}
```

👉 Implementation


---

### 5. 🌍 Public Routes

```ts
@Public()
@Get('/health')
health() {}
```

👉 Decorator


---

## 🔐 JWE Sessions (Encrypted Tokens)

### Warum JWE?

* Stateless Sessions
* AES-256-GCM Encryption
* Key Rotation möglich

```ts
const token = await sessionService.issue({ userId });
const payload = await sessionService.read(token);
```

### Implementation

* AES-256-GCM (`dir`)
* Multi-Key Support (Rotation)
* Expiration Handling

---

## 🔑 Key Management (CRITICAL)

```ts
JWE_KEY_BASE64 = base64(32 bytes)
```

❗ Anforderungen:

* exakt **32 Bytes**
* base64 encoded

Fehler:

```
Invalid key length: must be 32 bytes
```

---

## 🔒 Hashing & Crypto

### Argon2 (Password Hashing)

* argon2id
* configurable cost

👉 Implementation


---

### AES-256-GCM Encryption

* sensitive payload encryption

👉 Encryption Service


---

### HMAC (Security Tokens)

Use Cases:

* Reset Tokens
* Device Fingerprints
* Magic Links

👉 HMAC


---

## 🧠 Zero Trust Engine

```ts
const result = await zeroTrust.evaluate({
  userId,
  ip,
  userAgent,
  deviceId,
});
```

### Pipeline

```text
Context → Risk Engine → Policy → Decision
```

👉 Implementation

* Risk Memory (Failures, IP)
* Policy Enforcement

---

## 🚦 Rate Limiting

```ts
rateLimitService.isAllowed(key);
```

* Memory-based (default)
* optional distributed store

---

## 🍪 Cookie Handling

```ts
cookieService.getDefaults()
```

👉 Implementation


---

## 🌍 Distributed Mode

Optional Integration:

| Feature    | Interface         |
| ---------- | ----------------- |
| Revocation | RevocationStore   |
| Rate Limit | RateLimitStore    |
| Audit      | Kafka / Event Bus |

---

### Token Revocation

👉 Service


---

### Audit Logging

```ts
await audit.log({
  type: 'LOGIN',
  userId,
});
```

👉 Service


👉 Event Type


---

## 🔍 Token Extraction

Automatisch unterstützt:

* Authorization Header
* Cookies

👉 Implementation


---

## ⚠️ Best Practices

### 🔐 Security

* **Nie Default Secrets verwenden**
* JWE Keys regelmäßig rotieren
* HMAC Keys ≥ 32 chars
* Encryption Key = 32 bytes (HEX)

---

### 🧠 Zero Trust

* Immer `ZeroTrustGuard` aktivieren
* Device Fingerprinting nutzen
* IP + Behavior Tracking aktivieren

---

### ⚡ Performance

* JWKS caching aktiv lassen
* Rate limiting aktivieren
* Distributed Store für Produktion nutzen

---

### 🧪 Testing

* Dummy Hash Verify nutzen (Timing Attack Prevention)
* Token Revocation testen
* Step-Up Flows simulieren

---

## ❌ Common Pitfalls

| Problem            | Ursache                 |
| ------------------ | ----------------------- |
| Invalid key length | falscher JWE Key        |
| Decryption failed  | falscher Key / Rotation |
| Roles fehlen       | falsche Keycloak Config |
| Guard greift nicht | `@Public()` gesetzt     |

---

## 🧩 Extensibility

Das Package ist bewusst **pluggable**:

* eigener Risk Engine
* eigener Device Store
* Redis / Valkey
* Kafka Audit Pipeline

---

## 📜 License

GPL-3.0-or-later
© Omnixys Technologies
