# AgeWallet Symfony Demo Client

This is a **Symfony 7 demo application** showing how to integrate with the **AgeWallet OIDC provider**.  
It demonstrates the full Authorization Code Flow with **PKCE**, **ID token validation**, and **age verification via claims** — all in a **privacy-first, standards-compliant** way.  

---

## 🚀 Getting Started

### 1. Clone & Install
```bash
git clone https://github.com/yourorg/agewallet-client-demo.git
cd agewallet-client-demo
composer install
```

### 2. Configure Environment
Copy `.env` and set your OIDC endpoints and client details:

```
OIDC_ISSUER=https://agewallet.ddev.site
OIDC_CLIENT_ID=54b3efc8-1524-4ee0-baad-2854289d2da2
OIDC_REDIRECT_URI=https://127.0.0.1:8000/connect/agewallet/check
OIDC_AUTH_URL=https://agewallet.ddev.site/user/authorize
OIDC_TOKEN_URL=https://agewallet.ddev.site/user/token
OIDC_JWKS_URI=https://agewallet.ddev.site/.well-known/jwks.json
```

### 3. Start the Symfony Server
```bash
symfony server:start
```

Visit: [https://127.0.0.1:8000/connect/agewallet](https://127.0.0.1:8000/connect/agewallet)  
This starts the login flow.

---

## 🔑 Step-by-Step Flow (with “Why?”)

### Step 1. **Authorization Request**
- **What happens:**  
  The demo client redirects to AgeWallet’s `/user/authorize` with:
  - `response_type=code`
  - `scope=openid age`
  - `client_id` and `redirect_uri`
  - `state` (CSRF protection)
  - `nonce` (ID token replay protection)
  - `code_challenge` + `code_challenge_method=S256` (PKCE)

- **Why:**  
  This starts the OIDC flow in a **secure way**:
  - PKCE prevents intercepted codes from being reused.  
  - State prevents CSRF.  
  - Nonce prevents token replay.  

✅ **Conformance:** [OIDC Core §3.1.2](https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint), [RFC 7636 (PKCE)](https://datatracker.ietf.org/doc/html/rfc7636).

---

### Step 2. **Authorization Code Grant**
- **What happens:**  
  The user authenticates in the AgeWallet app.  
  AgeWallet issues a one-time `code` and redirects back to the Symfony demo at `/connect/agewallet/check`.

- **Why:**  
  The authorization code is short-lived and can only be exchanged once.  
  It’s safer than giving the client a token directly in the redirect.  

✅ **Conformance:** Standard Authorization Code Flow.  
✅ **Security:** Reduces attack surface compared to implicit flow.

---

### Step 3. **Token Exchange**
- **What happens:**  
  The demo posts to `/user/token` with:
  - `grant_type=authorization_code`
  - `code`
  - `redirect_uri`
  - `client_id`
  - `code_verifier` (PKCE proof)

  AgeWallet responds with:
  - `access_token` (for APIs)
  - `id_token` (JWT with user claims)

- **Why:**  
  PKCE ensures the client that initiated the flow is the one finishing it.  
  The provider doesn’t trust the `code` alone — it requires the correct verifier.  

✅ **Conformance:** [OIDC Core §3.1.3](https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint).  
✅ **Security:** Protects against stolen/misused codes.

---

### Step 4. **ID Token Validation**
- **What happens:**  
  The demo verifies the `id_token`:
  1. Signature checked with AgeWallet’s public JWKS.  
  2. Claims validated:
     - `iss` matches provider
     - `aud` matches client ID
     - `exp` not expired (with clock skew tolerance)
     - `iat` not in the future
     - `nonce` matches original request

- **Why:**  
  Tokens are **only trusted after cryptographic verification**.  
  Otherwise anyone could forge a JWT and impersonate a verified user.  

✅ **Conformance:** [OIDC Core §3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation).  
✅ **Security:** Prevents forgery, replay, and misuse.

---

### Step 5. **Access Control**
- **What happens:**  
  The demo extracts `age_verified: true` and other claims.  
  Routes can be restricted via Symfony Security:

```yaml
access_control:
  - { path: ^/restricted, roles: ROLE_VERIFIED }
```

- **Why:**  
  Only verified users can access sensitive features.  
  This is the entire purpose of AgeWallet: a privacy-preserving verification signal.  

✅ **Privacy:** Only the boolean verification claim is shared — no PII.

---

## 🔒 Why It’s Secure

- **PKCE**: Prevents intercepted code reuse.  
- **State & Nonce**: Protect against CSRF & replay.  
- **Signed JWTs**: Provider-signed, client-verified with JWKS.  
- **Claim Validation**: Rejects expired, tampered, or mismatched tokens.  
- **Minimal Claims**: Only `age_verified`, not personal data.  

---

## 📖 Under the Hood (Symfony Integration)

### 1. `IdTokenValidator` Service
Implements OIDC ID token validation using [`web-token/jwt-framework`](https://web-token.spomky-labs.com/).  
- Injected with `issuer`, `clientId`, `jwksUri` via `%env()%`.  
- Validates signatures + claims with tolerance for clock skew.

### 2. `SystemClock` Service
Implements `Psr\Clock\ClockInterface` for time-based claim checking.  
Bound in `services.yaml`:

```yaml
Psr\Clock\ClockInterface: '@App\Security\SystemClock'
```

### 3. Service Registration
```yaml
App\Security\IdTokenValidator:
    arguments:
        $issuer: '%env(OIDC_ISSUER)%'
        $clientId: '%env(OIDC_CLIENT_ID)%'
        $jwksUri: '%env(OIDC_JWKS_URI)%'
```

### 4. Controller Flow
- `/connect/agewallet` → starts login via KnpU OAuth2 Client.  
- `/connect/agewallet/check` → exchanges code, validates ID token, extracts claims.  
- Claims can be turned into a Symfony `User` object via a custom Authenticator.

---

## 📖 Notes on `/userinfo`
- Present for OIDC conformance.  
- Returns only `sub` and `age_verified`.  
- **Not recommended** for application use — developers should trust the **ID token** instead.  

---

## 🧩 Try It Yourself
- Start the server, log in with AgeWallet.  
- Watch claims appear in `/connect/agewallet/check`.  
- Protect a route with `ROLE_VERIFIED`.  
- Try tampering with the ID token → validation fails.  

---

✅ This demo shows **the secure path**:  
- PKCE + code flow  
- ID token validation  
- Minimal claims  
- Role-based access  
