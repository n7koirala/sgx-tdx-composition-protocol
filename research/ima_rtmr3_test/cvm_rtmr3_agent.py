#!/usr/bin/env python3
"""
CVM-side test agent for IMA -> RTMR[3] anchoring.

This is intentionally isolated from the working protocol implementation.  It
is for validating the proposed design before moving it into the production
agent/controller code.

Behavior:
  1. Read the kernel binary IMA measurement list.
  2. On startup, extend RTMR[3] once per existing IMA entry using the
     canonical SHA-384 mapping implemented in ima_rtmr3_common.py.
  3. Poll for newly appended IMA entries and extend RTMR[3] for each one.
  4. Serve a TLS endpoint that returns:
       - a nonce-bound DCAP TDX quote,
       - the binary IMA log,
       - live PCR-10 SHA-1 value,
       - RTMR[3] anchoring metadata for this experiment.

Run on the CVM:
    sudo python3 cvm_rtmr3_agent.py --port 8443 --method dcap
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import ctypes.util
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from typing import List, Tuple

sys.path.insert(
    0,
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "sgx-tdx-attestation"),
)

from common.protocol import (  # type: ignore
    DEFAULT_PORT,
    METHOD_DCAP,
    METHOD_ITA,
    PROTOCOL_VERSION,
    create_tls_context_server,
    parse_dcap_quote,
    receive_message,
    send_message,
)

from ima_rtmr3_common import (
    IMABinaryEntry,
    locate_ima_binary_log,
    locate_rtmr_measurements_dir,
    read_ima_binary_log,
    read_ima_count,
    read_mr_hex,
    read_pcr10_sha1,
    replay_rtmr3,
    rtmr_attr_path,
    write_rtmr_digest,
)


TEST_PROTOCOL_VERSION = "ima-rtmr3-test-v1"


class CVMRTMR3Agent:
    def __init__(
        self,
        port: int,
        cert_file: str,
        key_file: str,
        method: str = METHOD_DCAP,
        poll_interval: float = 1.0,
        config_path: str = "",
    ):
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.method = method
        self.poll_interval = poll_interval
        self.config_path = config_path

        self.ima_binary_path = locate_ima_binary_log()
        self.measurements_dir = locate_rtmr_measurements_dir()
        self.rtmr3_path = rtmr_attr_path(3, self.measurements_dir)

        self._tdx_lib = None
        self._lock = threading.Lock()
        self._watcher: threading.Thread | None = None
        self.running = False

        self.anchor_started_at = ""
        self.rtmr3_base_before_start = ""
        self.rtmr3_after_startup_replay = ""
        self.anchored_count = 0
        self.extend_errors: List[str] = []

        self.stats = {
            "requests": 0,
            "successful": 0,
            "failed": 0,
            "startup_extend_ms": 0.0,
            "incremental_extends": 0,
        }

        self._verify_setup()

    def _verify_setup(self) -> None:
        if not os.path.exists("/dev/tdx_guest"):
            raise RuntimeError("TDX device not found: /dev/tdx_guest")
        if not os.path.exists(self.cert_file):
            raise RuntimeError(f"TLS certificate not found: {self.cert_file}")
        if not os.path.exists(self.key_file):
            raise RuntimeError(f"TLS key not found: {self.key_file}")

        if self.method == METHOD_DCAP:
            self._tdx_lib = self._load_libtdx_attest()
            if self._tdx_lib is None:
                raise RuntimeError(
                    "libtdx_attest.so not found. Install TDX DCAP packages first."
                )
        elif self.method == METHOD_ITA:
            if not self.config_path or not os.path.exists(self.config_path):
                raise RuntimeError("ITA mode requires --config pointing to config.json")
            result = subprocess.run(["which", "trustauthority-cli"], capture_output=True)
            if result.returncode != 0:
                raise RuntimeError("trustauthority-cli not found in PATH")
        else:
            raise RuntimeError(f"unsupported method: {self.method}")

    def _load_libtdx_attest(self):
        for path in ("libtdx_attest.so", "libtdx_attest.so.1", ctypes.util.find_library("tdx_attest")):
            if not path:
                continue
            try:
                lib = ctypes.CDLL(path)
                lib.tdx_att_get_quote.restype = ctypes.c_int
                lib.tdx_att_get_quote.argtypes = [
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                    ctypes.c_uint32,
                    ctypes.c_void_p,
                    ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)),
                    ctypes.POINTER(ctypes.c_uint32),
                    ctypes.c_uint32,
                ]
                lib.tdx_att_free_quote.restype = None
                lib.tdx_att_free_quote.argtypes = [ctypes.POINTER(ctypes.c_uint8)]
                return lib
            except OSError:
                continue
        return None

    def _extend_entries_locked(self, entries: List[IMABinaryEntry], start_index: int) -> None:
        for entry in entries[start_index:]:
            digest = entry.rtmr_extend_digest()
            write_rtmr_digest(self.rtmr3_path, digest)
            self.anchored_count += 1
            if self.anchored_count % 1000 == 0:
                print(f"    [RTMR3] anchored {self.anchored_count:,} IMA entries")

    def anchor_startup_log(self) -> None:
        with self._lock:
            self.anchor_started_at = datetime.now(timezone.utc).isoformat()
            self.rtmr3_base_before_start = read_mr_hex(self.rtmr3_path)

            t0 = time.perf_counter()
            _, entries = read_ima_binary_log(self.ima_binary_path)
            self._extend_entries_locked(entries, 0)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0

            self.rtmr3_after_startup_replay = read_mr_hex(self.rtmr3_path)
            self.stats["startup_extend_ms"] = round(elapsed_ms, 3)

            expected = replay_rtmr3(
                entries,
                base=bytes.fromhex(self.rtmr3_base_before_start),
            ).hex()
            if expected != self.rtmr3_after_startup_replay:
                raise RuntimeError(
                    "startup RTMR3 replay mismatch: "
                    f"expected={expected}, actual={self.rtmr3_after_startup_replay}"
                )

            print(
                f"[RTMR3] startup replay anchored {self.anchored_count:,} entries "
                f"in {elapsed_ms:.1f} ms"
            )
            print(f"[RTMR3] base   : {self.rtmr3_base_before_start}")
            print(f"[RTMR3] current: {self.rtmr3_after_startup_replay}")

    def _sync_new_entries_locked(self) -> Tuple[bytes, List[IMABinaryEntry], int]:
        blob, entries = read_ima_binary_log(self.ima_binary_path)
        parsed_count = len(entries)

        if parsed_count < self.anchored_count:
            raise RuntimeError(
                f"IMA log appears shorter than anchored count: "
                f"parsed={parsed_count}, anchored={self.anchored_count}"
            )

        new_count = parsed_count - self.anchored_count
        if new_count > 0:
            start = self.anchored_count
            self._extend_entries_locked(entries, start)
            self.stats["incremental_extends"] += new_count
            print(
                f"[RTMR3] extended {new_count:,} new IMA entr"
                f"{'y' if new_count == 1 else 'ies'} "
                f"(total={self.anchored_count:,})"
            )

        return blob, entries, new_count

    def _watch_loop(self) -> None:
        while self.running:
            try:
                with self._lock:
                    self._sync_new_entries_locked()
            except Exception as exc:
                msg = f"{datetime.now(timezone.utc).isoformat()} {exc}"
                self.extend_errors.append(msg)
                print(f"[RTMR3] watcher error: {exc}")
            time.sleep(self.poll_interval)

    def get_tdx_quote_dcap(self, nonce: str) -> Tuple[bytes, str]:
        if self._tdx_lib is None:
            raise RuntimeError("libtdx_attest not loaded")

        nonce_bytes = base64.b64decode(nonce)
        report_data = (nonce_bytes + b"\x00" * 64)[:64]
        rd_buf = (ctypes.c_uint8 * 64)(*report_data)
        pp_quote = ctypes.POINTER(ctypes.c_uint8)()
        quote_size = ctypes.c_uint32(0)

        ret = self._tdx_lib.tdx_att_get_quote(
            ctypes.byref(rd_buf),
            None,
            0,
            None,
            ctypes.byref(pp_quote),
            ctypes.byref(quote_size),
            0,
        )
        if ret != 0:
            raise RuntimeError(f"tdx_att_get_quote failed: error {ret} (0x{ret:08x})")

        try:
            quote_bytes = bytes(pp_quote[:quote_size.value])
        finally:
            self._tdx_lib.tdx_att_free_quote(pp_quote)

        info = parse_dcap_quote(quote_bytes)
        return quote_bytes, info.mrtd

    def handle_attest(self, req: dict) -> dict:
        nonce = req.get("nonce")
        if not nonce:
            return {"status": "error", "error": "missing nonce"}

        with self._lock:
            t_sync0 = time.perf_counter()
            ima_blob, entries, new_count = self._sync_new_entries_locked()
            t_sync_ms = (time.perf_counter() - t_sync0) * 1000.0

            pcr10 = read_pcr10_sha1()

            t_quote0 = time.perf_counter()
            if self.method == METHOD_DCAP:
                quote_bytes, mrtd = self.get_tdx_quote_dcap(nonce)
                raw_quote_b64 = base64.b64encode(quote_bytes).decode("ascii")
                token = ""
                attestation_method = METHOD_DCAP
            else:
                raise RuntimeError("ITA mode is not implemented in this RTMR3 test agent")
            t_quote_ms = (time.perf_counter() - t_quote0) * 1000.0

            rtmr3_current = read_mr_hex(self.rtmr3_path)
            ima_count_kernel = read_ima_count()

            return {
                "status": "success",
                "protocol": TEST_PROTOCOL_VERSION,
                "protocol_version": PROTOCOL_VERSION,
                "nonce_echo": nonce,
                "attestation_method": attestation_method,
                "mrtd": mrtd,
                "raw_quote": raw_quote_b64,
                "token": token,
                "ima_binary_log_b64": base64.b64encode(ima_blob).decode("ascii"),
                "ima_entry_count": len(entries),
                "ima_count_kernel": ima_count_kernel,
                "pcr10_sha1": pcr10,
                "anchor": {
                    "rtmr_index": 3,
                    "hash_alg": "sha384",
                    "canonical": (
                        "SHA384(CANON_MAGIC || LE32(pcr) || LE32(len(template_hash)) "
                        "|| template_hash || LE32(len(template_name)) || template_name "
                        "|| LE32(len(template_data)) || template_data)"
                    ),
                    "canon_magic_hex": "494d412d52544d52332d43414e4f4e2d763100",
                    "rtmr3_base_before_start": self.rtmr3_base_before_start,
                    "rtmr3_after_startup_replay": self.rtmr3_after_startup_replay,
                    "rtmr3_current": rtmr3_current,
                    "anchored_count": self.anchored_count,
                    "new_entries_synced_for_request": new_count,
                    "anchor_started_at": self.anchor_started_at,
                    "extend_errors": self.extend_errors[-5:],
                },
                "_server_timing": {
                    "sync_ms": round(t_sync_ms, 3),
                    "quote_ms": round(t_quote_ms, 3),
                    "startup_extend_ms": self.stats["startup_extend_ms"],
                },
            }

    def handle_status(self) -> dict:
        with self._lock:
            return {
                "status": "success",
                "protocol": TEST_PROTOCOL_VERSION,
                "ima_binary_path": self.ima_binary_path,
                "ima_count_kernel": read_ima_count(),
                "anchored_count": self.anchored_count,
                "rtmr3_path": self.rtmr3_path,
                "rtmr3_current": read_mr_hex(self.rtmr3_path),
                "rtmr3_base_before_start": self.rtmr3_base_before_start,
                "extend_errors": self.extend_errors[-5:],
                "stats": self.stats,
            }

    def handle_request(self, request_json: str) -> str:
        try:
            req = json.loads(request_json)
            action = req.get("action", "attest")
            if action == "status":
                response = self.handle_status()
            elif action == "attest":
                response = self.handle_attest(req)
            else:
                response = {"status": "error", "error": f"unknown action: {action}"}
            self.stats["successful"] += 1
            return json.dumps(response)
        except Exception as exc:
            self.stats["failed"] += 1
            return json.dumps({"status": "error", "error": str(exc)})

    def handle_client(self, client_socket: ssl.SSLSocket, addr: tuple) -> None:
        self.stats["requests"] += 1
        req_num = self.stats["requests"]
        print(f"[{req_num}] connection from {addr[0]}:{addr[1]}")
        try:
            request_json = receive_message(client_socket)
            response_json = self.handle_request(request_json)
            send_message(client_socket, response_json)
            print(f"[{req_num}] response sent ({len(response_json):,} bytes)")
        except Exception as exc:
            print(f"[{req_num}] request failed: {exc}")
        finally:
            client_socket.close()

    def run(self) -> None:
        self.anchor_startup_log()

        tls_context = create_tls_context_server(self.cert_file, self.key_file)
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(("0.0.0.0", self.port))
        server_socket.listen(8)

        tls_socket = tls_context.wrap_socket(server_socket, server_side=True)
        self.running = True
        self._watcher = threading.Thread(target=self._watch_loop, daemon=True)
        self._watcher.start()

        self._print_banner()
        try:
            while self.running:
                try:
                    client, addr = tls_socket.accept()
                    self.handle_client(client, addr)
                except KeyboardInterrupt:
                    break
                except ssl.SSLError as exc:
                    print(f"TLS error: {exc}")
                except Exception as exc:
                    print(f"server error: {exc}")
        finally:
            self.running = False
            tls_socket.close()
            self._print_stats()

    def _print_banner(self) -> None:
        print("=" * 72)
        print("CVM IMA -> RTMR[3] Test Agent")
        print("=" * 72)
        print(f"Protocol:        {TEST_PROTOCOL_VERSION}")
        print(f"Port:            {self.port}")
        print(f"Method:          {self.method}")
        print(f"IMA binary log:  {self.ima_binary_path}")
        print(f"RTMR[3] attr:    {self.rtmr3_path}")
        print(f"Anchored count:  {self.anchored_count:,}")
        print(f"PCR10 SHA-1:     {read_pcr10_sha1()[:16]}...")
        print(f"TLS cert:        {self.cert_file}")
        print("=" * 72)
        print("Waiting for WEN verifier requests...\n")

    def _print_stats(self) -> None:
        print("\n" + "=" * 72)
        print("RTMR3 Agent Statistics")
        print("=" * 72)
        for key, value in self.stats.items():
            print(f"{key}: {value}")
        print(f"anchored_count: {self.anchored_count}")
        print("=" * 72)


def self_test() -> bool:
    print("=" * 72)
    print("IMA -> RTMR[3] Test Agent Self-Test")
    print("=" * 72)

    checks = []
    checks.append(("/dev/tdx_guest", os.path.exists("/dev/tdx_guest")))

    try:
        ima_path = locate_ima_binary_log()
        blob, entries = read_ima_binary_log(ima_path)
        print(f"IMA binary log: {ima_path}")
        print(f"IMA binary size: {len(blob):,} bytes")
        print(f"Parsed entries: {len(entries):,}")
        checks.append(("IMA binary log parse", len(entries) > 0))
    except Exception as exc:
        print(f"IMA binary log error: {exc}")
        checks.append(("IMA binary log parse", False))

    try:
        mr_dir = locate_rtmr_measurements_dir()
        rtmr3 = rtmr_attr_path(3, mr_dir)
        print(f"RTMR dir: {mr_dir}")
        print(f"RTMR[3]: {rtmr3}")
        print(f"RTMR[3] current: {read_mr_hex(rtmr3)}")
        checks.append(("RTMR[3] readable", True))
    except Exception as exc:
        print(f"RTMR[3] error: {exc}")
        checks.append(("RTMR[3] readable", False))

    pcr10 = read_pcr10_sha1()
    print(f"PCR10 SHA-1: {pcr10 or '<unavailable>'}")
    checks.append(("PCR10 SHA-1 readable", bool(pcr10)))

    print("\nChecks:")
    ok = True
    for label, passed in checks:
        ok = ok and passed
        print(f"  {'OK ' if passed else 'FAIL'} {label}")
    print("=" * 72)
    return ok


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CVM IMA -> RTMR[3] test agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--cert", default=None)
    parser.add_argument("--key", default=None)
    parser.add_argument("--method", choices=(METHOD_DCAP, METHOD_ITA), default=METHOD_DCAP)
    parser.add_argument("--config", default=os.path.expanduser("~/config.json"))
    parser.add_argument("--poll-interval", type=float, default=1.0)
    parser.add_argument("--test", action="store_true")
    args = parser.parse_args()

    if args.test:
        sys.exit(0 if self_test() else 1)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    certs_dir = os.path.join(script_dir, "..", "sgx-tdx-attestation", "certs")
    cert_file = args.cert or os.path.join(certs_dir, "server.crt")
    key_file = args.key or os.path.join(certs_dir, "server.key")

    agent = CVMRTMR3Agent(
        port=args.port,
        cert_file=cert_file,
        key_file=key_file,
        method=args.method,
        poll_interval=args.poll_interval,
        config_path=args.config,
    )
    agent.run()


if __name__ == "__main__":
    main()
