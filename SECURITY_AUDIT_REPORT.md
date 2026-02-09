# Web3Signer Security Audit Report

**Date:** 2026-02-09
**Scope:** Full source code audit of ConsenSys Web3Signer
**Focus:** Vulnerabilities enabling unprivileged actors to access signing keys, produce unauthorized signatures, or compromise validator assets

---

## Executive Summary

This audit identified **12 distinct vulnerabilities** across the Web3Signer codebase. The most severe chain of findings demonstrates that an **unprivileged network attacker** with HTTP access to the Web3Signer port can:

1. Bypass the host allowlist by spoofing the `Host` header
2. Enumerate all loaded validator public keys
3. Sign arbitrary data (including voluntary exits) with any loaded private key
4. Import or delete keystores at will (the declared bearer-token auth is not implemented)
5. Generate proxy signing keys for any loaded validator
6. Bypass slashing protection for most signing types

These findings apply when Web3Signer is network-reachable (e.g., bound to `0.0.0.0` in containerized deployments) without TLS client certificate authentication configured.

---

## VULN-01: Zero Application-Level Authentication on All Endpoints

| Field | Value |
|-------|-------|
| **Severity** | **CRITICAL** |
| **CVSS 3.1** | 10.0 |
| **Attack Vector** | Network |
| **Privileges Required** | None |
| **Impact** | Complete compromise of all signing keys |

### Description

Web3Signer exposes every endpoint without any application-level authentication. There are no API keys, bearer tokens, session tokens, or any credential checks in any handler. The only protective mechanisms are:

- **Host header allowlist** (trivially bypassable, see VULN-02)
- **Optional mTLS** (disabled by default)
- **Localhost binding** (commonly overridden for container deployments)

### Affected Endpoints

Every endpoint is unprotected:

| Endpoint | Method | Impact |
|----------|--------|--------|
| `/api/v1/eth2/sign/:identifier` | POST | **Sign arbitrary data with any validator key** |
| `/api/v1/eth1/sign/:identifier` | POST | **Sign arbitrary data with any Eth1 key** |
| `/api/v1/eth2/publicKeys` | GET | Enumerate all loaded validator public keys |
| `/api/v1/eth1/publicKeys` | GET | Enumerate all loaded Eth1 account keys |
| `/eth/v1/keystores` | GET/POST/DELETE | List, import, and delete keystores |
| `/reload` | POST | Trigger key reload from configuration |
| `/signer/v1/generate_proxy_key` | POST | Generate proxy keys for any validator |
| `/signer/v1/request_signature` | POST | Sign with proxy keys |
| `/api/v1/eth2/highWatermark` | GET | Leak slashing protection state |

### Affected Code

All route handlers in the `core/src/main/java/.../handlers/` package lack authentication:
- `Eth2SignForIdentifierHandler.java:88` — direct request handling
- `Eth1SignForIdentifierHandler.java:44` — direct request handling
- `ImportKeystoresHandler.java:79` — direct request handling
- `DeleteKeystoresHandler.java:52` — direct request handling
- `ListKeystoresHandler.java` — direct request handling

Router setup in `Runner.java:128-155` registers no auth handlers or middleware.

### Proof of Concept

```bash
# Enumerate all loaded validator public keys
curl -H "Host: localhost" http://<TARGET>:9000/api/v1/eth2/publicKeys

# Sign arbitrary data with a validator key (e.g. VOLUNTARY_EXIT to permanently exit a validator)
curl -X POST -H "Host: localhost" -H "Content-Type: application/json" \
  http://<TARGET>:9000/api/v1/eth2/sign/<PUBKEY> \
  -d '{"type":"VOLUNTARY_EXIT","fork_info":{...},"voluntary_exit":{...}}'
```

---

## VULN-02: Host Allowlist Bypass via HTTP Header Spoofing

| Field | Value |
|-------|-------|
| **Severity** | **CRITICAL** |
| **CVSS 3.1** | 9.1 |
| **Attack Vector** | Network |
| **Privileges Required** | None |

### Description

The `HostAllowListHandler` (`core/.../HostAllowListHandler.java:34-48`) validates only the HTTP `Host` header value against a configured allowlist. The default allowlist is `localhost,127.0.0.1`.

Any HTTP client can trivially set the `Host` header to `localhost`, bypassing this check entirely when the server is bound to a non-loopback interface.

### Affected Code

```java
// HostAllowListHandler.java:34-48
public void handle(final RoutingContext event) {
    final Optional<String> hostHeader = getAndValidateHostHeader(event);
    if (httpHostAllowList.contains("*")
        || (hostHeader.isPresent() && hostIsInAllowlist(hostHeader.get()))) {
      event.next(); // PASSES if Host header matches allowlist
    } else {
      // ... 403
    }
}

// Line 50-52: Only reads the Host header — does NOT validate source IP
private Optional<String> getAndValidateHostHeader(final RoutingContext event) {
    final HostAndPort hostAndPort = event.request().authority();
    return Optional.ofNullable(hostAndPort).map(HostAndPort::host);
}
```

### Proof of Concept

```bash
# From any machine on the network, bypass allowlist:
curl -H "Host: localhost" http://<WEB3SIGNER_IP>:9000/upcheck
# Returns "OK" — allowlist bypassed
```

---

## VULN-03: Key Manager API Bearer Auth Declared but Not Implemented

| Field | Value |
|-------|-------|
| **Severity** | **CRITICAL** |
| **CVSS 3.1** | 9.8 |
| **Attack Vector** | Network |
| **Privileges Required** | None |
| **Impact** | Unauthorized keystore import/deletion; complete validator disruption |

### Description

The OpenAPI specification for the Key Manager API (`/eth/v1/keystores`) declares `bearerAuth` (JWT) as a required security scheme:

```yaml
# openapi-specs/eth2/keymanager/schemas.yaml:2-6
securitySchemes:
  bearerAuth:
    type: http
    scheme: bearer
    bearerFormat: JWT
```

However, the actual Java implementation in `KeyManagerApiRoute.java` registers handlers **with zero authentication**:

```java
// KeyManagerApiRoute.java:79-86
private void registerGet() {
    context.getRouter()
        .route(HttpMethod.GET, KEYSTORES_PATH)
        .handler(new BlockingHandlerDecorator(
            new ListKeystoresHandler(blsSignerProvider, objectMapper), false))
        .failureHandler(context.getErrorHandler());
    // NO AUTH HANDLER
}
```

### Impact

An attacker can:

1. **DELETE keystores** — Disable validators, causing inactivity penalties and forced exits
2. **IMPORT keystores** — Inject attacker-controlled keys to sign slashable messages
3. **LIST keystores** — Enumerate all loaded keys with metadata

### Proof of Concept

```bash
# Delete all keystores for a validator (no auth required)
curl -X DELETE -H "Host: localhost" -H "Content-Type: application/json" \
  http://<TARGET>:9000/eth/v1/keystores \
  -d '{"pubkeys":["0x<VALIDATOR_PUBKEY>"]}'
```

---

## VULN-04: Slashing Protection Bypass for Most Signing Types

| Field | Value |
|-------|-------|
| **Severity** | **CRITICAL** |
| **CVSS 3.1** | 9.1 |
| **Attack Vector** | Network (chained with VULN-01) |
| **Impact** | Force voluntary exits, forge committee signatures without slashing checks |

### Description

In `Eth2SignForIdentifierHandler.java:169-200`, the `maySign()` method only enforces slashing protection for `BLOCK`, `BLOCK_V2`, and `ATTESTATION` types. **All other signing types bypass slashing protection entirely** via the `default` branch:

```java
// Eth2SignForIdentifierHandler.java:169-200
private boolean maySign(...) {
    switch (eth2SigningRequestBody.type()) {
      case BLOCK, BLOCK_V2 -> {
        // ... slashing check ...
      }
      case ATTESTATION -> {
        // ... slashing check ...
      }
      default -> {
        return true;  // NO PROTECTION for all other types
      }
    }
}
```

### Unprotected Signing Types

The following signing types **completely bypass slashing protection**:

| Type | Danger |
|------|--------|
| `VOLUNTARY_EXIT` | **Force-exit a validator permanently; irreversible on-chain action** |
| `AGGREGATE_AND_PROOF` | Forge aggregate attestations |
| `RANDAO_REVEAL` | Forge randomness reveals |
| `DEPOSIT` | Sign malicious deposits |
| `SYNC_COMMITTEE_MESSAGE` | Forge sync committee signatures |
| `SYNC_COMMITTEE_SELECTION_PROOF` | Forge selection proofs |
| `SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF` | Forge contributions |
| `VALIDATOR_REGISTRATION` | Register validators with attacker-controlled fee recipients |

### Impact

An attacker chaining VULN-01 + VULN-04 can:
1. Enumerate all validator keys via `/api/v1/eth2/publicKeys`
2. Sign `VOLUNTARY_EXIT` messages for every validator
3. Broadcast these exits to permanently remove all validators from the beacon chain
4. This causes **permanent, irreversible loss of staked ETH** (until the exit queue processes and the ETH is unlocked)

---

## VULN-05: Sign-Before-Check Pattern in Eth2 Signing Handler

| Field | Value |
|-------|-------|
| **Severity** | **HIGH** |
| **CVSS 3.1** | 7.4 |

### Description

The Eth2 signing flow computes the BLS signature **before** checking slashing protection:

```java
// Eth2SignForIdentifierHandler.java:110-124
if (slashingProtection.isPresent()) {
    handleSigning(routingContext, signingRoot, normalisedIdentifier,
        signature ->  // <-- SIGNATURE ALREADY COMPUTED HERE
            signWithSlashingProtection(routingContext, identifier,
                eth2SigningRequestBody, signingRoot, signature));
}

// handleSigning signs first, then passes result to consumer:
// Line 133-134:
signerForIdentifier.sign(normalisedIdentifier, signingRoot)  // SIGNS FIRST
    .ifPresentOrElse(signatureConsumer, ...);                 // THEN checks
```

While the signature is not returned to the caller if slashing protection rejects it, the actual cryptographic operation has already executed with the private key material. This violates defense-in-depth: if any side channel (timing, logging, memory dump) leaks the computed signature, slashing protection becomes ineffective.

---

## VULN-06: Unauthenticated CommitBoost Proxy Key Generation

| Field | Value |
|-------|-------|
| **Severity** | **HIGH** |
| **CVSS 3.1** | 8.1 |
| **Attack Vector** | Network |

### Description

The CommitBoost API endpoint `POST /signer/v1/generate_proxy_key` allows any caller to generate new BLS or ECDSA proxy signing keys bound to any loaded consensus validator key. No authentication is required.

### Affected Code

`CommitBoostGenerateProxyKeyHandler.java:57-112`:
- Accepts any consensus public key (line 70)
- Generates a new BLS or ECDSA private key (lines 81-85)
- Adds it to the signer provider (line 88)
- Signs a delegation proof with the consensus key (lines 95-97)
- Returns the proxy key identifier and signed delegation (line 107)

### Impact

An attacker can generate unlimited proxy keys for any validator and use them to sign arbitrary commitments on behalf of the validator, without touching the primary consensus key. These proxy keys persist in memory until the process restarts.

---

## VULN-07: Unauthenticated Key Reload Endpoint

| Field | Value |
|-------|-------|
| **Severity** | **HIGH** |
| **CVSS 3.1** | 7.5 |

### Description

`POST /reload` (`ReloadHandler.java:92-183`) triggers a full reload of all signing keys from disk/vault sources. No authentication is required.

### Impact

1. **Denial of Service**: Repeated reload requests cause resource exhaustion (vault API calls, disk I/O, key decryption CPU)
2. **Attack Amplification**: If an attacker has written malicious YAML config files to the key-config-path (via VULN-03 or filesystem access), triggering reload loads the malicious configs
3. **Timing Attack**: The reload status endpoint (`GET /reload`) leaks operational state and error messages

---

## VULN-08: Path Traversal in YAML Signer Configuration

| Field | Value |
|-------|-------|
| **Severity** | **HIGH** |
| **CVSS 3.1** | 7.5 |
| **Attack Vector** | Local / chained with VULN-03 |

### Description

`AbstractArtifactSignerFactory.makeRelativePathAbsolute()` (`signing/.../AbstractArtifactSignerFactory.java:127-129`) resolves file paths from YAML config files without validating against directory traversal:

```java
protected Path makeRelativePathAbsolute(final Path path) {
    return path.isAbsolute() ? path : configsDirectory.resolve(path);
    // NO validation against path traversal (../)
}
```

### Attack Vector

A malicious YAML signer config file can read arbitrary files:

```yaml
type: file-keystore
keystoreFile: "../../../etc/passwd"
keystorePasswordFile: "../../../etc/shadow"
keyType: BLS
```

When combined with VULN-03 (importing keystores writes YAML metadata files to the key-config-path), or with direct filesystem access, this allows reading arbitrary files accessible to the web3signer process.

### Affected Paths

- `FileKeyStoreMetadata.keystoreFile` → `BlsArtifactSignerFactory.java:112`
- `FileKeyStoreMetadata.keystorePasswordFile` → `BlsArtifactSignerFactory.java:113-114`
- `HashicorpSigningMetadata.tlsKnownServerFile` → `AbstractArtifactSignerFactory.java:96`

---

## VULN-09: Credentials Exposed via Process Listing

| Field | Value |
|-------|-------|
| **Severity** | **HIGH** |
| **CVSS 3.1** | 7.5 |
| **Attack Vector** | Local |
| **Privileges Required** | Any local user |

### Description

Sensitive credentials are passed as command-line arguments, making them visible to any local user via `ps aux` or `/proc/<pid>/cmdline`:

| Flag | Exposes | File |
|------|---------|------|
| `--slashing-protection-db-password` | Database password | `PicoCliSlashingProtectionParameters.java:50` |
| `--aws-secrets-secret-access-key` | AWS secret key | `PicoCliAwsSecretsManagerParameters.java:69` |
| `--azure-client-secret` | Azure service principal secret | `PicoCliAzureKeyVaultParameters.java:66` |

### Impact

Any unprivileged user on the same host can read these credentials and gain direct access to:
- The slashing protection database (to corrupt slashing records)
- AWS Secrets Manager (to read all stored private keys)
- Azure Key Vault (to read all stored private keys)

---

## VULN-10: Keystore Passwords and Request Bodies Logged in Plaintext

| Field | Value |
|-------|-------|
| **Severity** | **MEDIUM** |
| **CVSS 3.1** | 6.5 |
| **Attack Vector** | Local (log access) |

### Description

Multiple handlers log complete HTTP request bodies that contain sensitive data:

| Handler | Level | Line | Content Logged |
|---------|-------|------|----------------|
| `ImportKeystoresHandler` | **INFO** | 244 | Encrypted keystores + plaintext passwords |
| `DeleteKeystoresHandler` | DEBUG | 82 | Keystore identifiers |
| `Eth2SignForIdentifierHandler` | TRACE | 90 | Full signing request body |
| `JsonRpcHandler` | TRACE/DEBUG | 50, 64 | Full JSON-RPC request body |

The ImportKeystoresHandler is the most critical since it logs at **INFO level** (active by default), including the keystore passwords submitted in the import request body.

### Affected Code

```java
// ImportKeystoresHandler.java:244
LOG.info("Invalid import keystores request - " + routingContext.body().asString(), e);
// The request body contains: {"keystores": [...], "passwords": ["plaintext-password-1", ...]}
```

---

## VULN-11: CORS Origin Regex Injection

| Field | Value |
|-------|-------|
| **Severity** | **MEDIUM** |
| **CVSS 3.1** | 5.3 |
| **Attack Vector** | Network (browser-based) |

### Description

The CORS handler in `Runner.java:390-403` constructs a regex from configured origins without escaping:

```java
private String buildCorsRegexFromConfig() {
    // ...
    final StringJoiner stringJoiner = new StringJoiner("|");
    baseConfig.getCorsAllowedOrigins().stream()
        .filter(s -> !s.isEmpty())
        .forEach(stringJoiner::add);  // NO REGEX ESCAPING
    return stringJoiner.toString();
}
```

If an operator configures `--http-cors-origins=http://example.com`, the `.` in `example.com` matches any character in regex. This means `http://exampleXcom.evil.com` would pass the CORS check, enabling cross-origin requests from attacker-controlled domains.

---

## VULN-12: Keystore Passwords Written as Plaintext Files

| Field | Value |
|-------|-------|
| **Severity** | **MEDIUM** |
| **CVSS 3.1** | 5.5 |
| **Attack Vector** | Local |

### Description

`KeystoreFileManager.createKeystoreFiles()` (`signing/.../KeystoreFileManager.java:73-99`) writes keystore passwords as plaintext `.password` files:

```java
// KeystoreFileManager.java:91
Files.writeString(keystorePasswordFile, password, StandardCharsets.UTF_8);
```

These files are created with default filesystem permissions (typically `644` — world-readable). No `chmod 600` or restricted ACL is applied.

### Impact

Any local user with read access to the key-config-path directory can read all keystore passwords, enabling offline decryption of the corresponding keystore files to extract raw private keys.

---

## Attack Chain Summary

The most dangerous attack chain for an unprivileged network actor:

```
Step 1: VULN-02 — Spoof Host header to bypass allowlist
         curl -H "Host: localhost" http://<TARGET>:9000/...

Step 2: VULN-01 — No auth required, full API access
         GET /api/v1/eth2/publicKeys → enumerate all validator keys

Step 3: VULN-04 — Sign VOLUNTARY_EXIT (bypasses slashing protection)
         POST /api/v1/eth2/sign/<PUBKEY> with type=VOLUNTARY_EXIT

Step 4: Broadcast the signed voluntary exit to the beacon chain
         → Validator is permanently exited
         → Staked ETH locked until exit queue processes
```

**Alternate attack for maximal damage:**

```
Step 1-2: Same as above

Step 3: VULN-03 — Delete all keystores via Key Manager API
         DELETE /eth/v1/keystores → removes all validator keys

Step 4: Validators go offline → incur inactivity penalties

Step 5: VULN-03 — Import attacker-controlled keystores
         POST /eth/v1/keystores → load rogue keys

Step 6: POST /reload → trigger reload to activate rogue keys
```

---

## Recommendations

### Immediate (Critical)

1. **Implement application-level authentication** — Add bearer token or API key validation middleware to all endpoints. The Key Manager API already specifies this in OpenAPI but lacks implementation.

2. **Replace Host header validation with source-IP validation** — Use Vert.x's `remoteAddress()` to validate the actual client IP, not the spoofable Host header.

3. **Add slashing protection for all signing types** — At minimum, enforce slashing protection for `VOLUNTARY_EXIT` (which causes irreversible validator exit). The `default -> return true` in `maySign()` should be changed to `default -> return false` or implement type-specific protections.

### Short-Term (High)

4. **Fix sign-before-check ordering** — Check slashing protection BEFORE computing the BLS signature.

5. **Add path traversal validation** — In `makeRelativePathAbsolute()`, validate that the resolved path is within the expected config directory after normalization.

6. **Move credentials to files** — Accept database passwords, AWS secrets, and Azure secrets via file paths (e.g., `--slashing-protection-db-password-file`) rather than command-line arguments.

7. **Redact sensitive data in logs** — Never log request bodies that may contain passwords or key material. Especially fix the INFO-level logging in ImportKeystoresHandler.

### Medium-Term

8. **Implement rate limiting** — Add request rate limiting to all endpoints, especially signing and reload.

9. **Escape CORS origins** — Use `Pattern.quote()` on configured origins before constructing the CORS regex.

10. **Set restrictive file permissions** — Apply `chmod 600` to password files created by KeystoreFileManager.

11. **Add authentication to CommitBoost API** — Proxy key generation should require proof of authorization.

12. **Implement audit logging** — Log all signing operations, key management operations, and authentication failures to a tamper-evident audit log.
