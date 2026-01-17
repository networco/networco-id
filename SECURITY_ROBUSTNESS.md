# NetworcoID Security Hardening & OIDC Certification Roadmap

**Status:** Strategic Mandate  
**Objective:** Achieve official OpenID Connect (OIDC) Certification and establish NetworcoID as the gold standard for robust, interoperable identity systems.

---

## 1. Architectural Foundations (Protocol & Crypto)

### **1.1. Path to OIDC Certification**
*   **Current State:** Homegrown OIDC implementation using Minimal APIs.
*   **Ambition:** **Official OpenID Foundation Certification.**
*   **Mechanism:**
    *   Transition core protocol logic to **OpenIddict** to handle the thousands of edge cases required for certification (conformance tests).
    *   Implement **PKCE (S256)** across all clients.
    *   Formalize **Discovery (`.well-known`)** and **JWKS** endpoints to 100% spec compliance.
    *   Support **Mutual TLS (mTLS)** and **JARM (JWT Secured Authorization Response)** for high-security profiles.

### **1.2. Cryptographic Sovereignty**
*   **Current State:** RSA signing with environment-based PEMs.
*   **Ambition:** **HSM-Backed Key Rotation & Multi-Algorithm Support.**
*   **Mechanism:**
    *   **Automatic Key Rotation:** Seamlessly rotate JWT signing keys via the JWKS endpoint without logging out users.
    *   **HSM/KMS Integration:** Keys never touch application memory; signing happens in a secure enclave (Vault/AWS KMS).
    *   **Post-Quantum Readiness:** Prepare for hybrid signing schemes (RSA/ECDSA + Dilithium/Falcon).

---

## 2. Identity & Access Management (The Human Layer)

### **2.1. Uncompromising Password Security**
*   **Current State:** 12-char minimum, complex validation.
*   **Ambition:** **Zero-Trust Credentials.**
*   **Mechanism:**
    *   **Global Breach Monitoring:** Integration with "Have I Been Pwned" to reject previously leaked passwords.
    *   **Argon2id:** Transition from PBKDF2/BCrypt to memory-hard Argon2id (M: 64MB, T: 3, P: 4).
    *   **Contextual Lockout:** Rate limiting that understands "Low-and-Slow" attacks across multiple IPs.

### **2.2. Passwordless & Biometric Excellence**
*   **Current State:** Password-based.
*   **Ambition:** **FIDO2 / Passkey First Identity.**
*   **Mechanism:**
    *   Enable **WebAuthn** as the primary authentication factor.
    *   Eliminate the "Master Password" risk by treating the device (Phone/Laptop/Security Key) as the identity.
    *   Support **Cross-Device Authentication (Hybrid Flow)**.

---

## 3. Defense-in-Depth (System Integrity)

### **3.1. Immutable Audit & Non-Repudiation**
*   **Current State:** SQL-based auditing.
*   **Ambition:** **Verifiable Event Sinking.**
*   **Mechanism:**
    *   **NATS JetStream Sinking:** Decouple audit generation from storage.
    *   **Digital Signatures on Logs:** Every audit event is signed by the service identity, making it legally defensible and tamper-evident.
    *   **Separate Retention:** Audit logs move to an air-gapped or WORM (Write-Once-Read-Many) storage.

### **3.2. Behavioral & Signal-Based Security**
*   **Current State:** IP-based rate limiting.
*   **Ambition:** **Risk-Based Authentication (RBA).**
*   **Mechanism:**
    *   Evaluate "Impossible Travel" and "New Device" signals during login.
    *   Enforce **Step-up Authentication** (MFA) if the risk score is high.

---

## 4. Operational Robustness

### **4.1. Formal Verification**
*   **Ambition:** **Zero-Bug Authentication Flows.**
*   **Mechanism:** Use formal methods (TLA+ or property-based testing) to mathematically prove that no combination of OIDC parameters can bypass authentication.

### **4.2. Workload Identity**
*   **Ambition:** **Zero-Secret Production.**
*   **Mechanism:** Deploy using K8s Workload Identity. Remove all API keys, database passwords, and client secrets from Environment Variables. Authenticate to all dependencies using Managed Identities.

---

## 5. Certification Checklist (Immediate Actions)

1.  [x] **Enforce Password Change:** Blocking JWT issuance if `must_change_password` is true.
2.  [x] **Hardened Discovery:** Advertise PKCE support and remove insecure flows (Implicit).
3.  [ ] **OpenID Conformance Suite:** Setup the local test suite (Python-based) to run against NetworcoID.
4.  [ ] **PKCE Enforcement:** Verify `code_challenge` in the `/authorize` endpoint.
5.  [ ] **JWKS Rotation:** Implement a background worker to generate and publish new keys monthly.

---
*This document is the blueprint for the most robust identity system in existence. We do not settle for "secure"; we build for "certified trust".*
