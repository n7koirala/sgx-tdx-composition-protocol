#!/usr/bin/env python3
"""
CVM Attestation Agent for Incremental Attestation Microbenchmark

Runs on the TDX CVM and serves attestation responses to subscribers
(SGX enclave or plain Python verifier). Supports two IMA reading modes:

  Non-Optimized:  Opens/closes the IMA pseudo-file each epoch.
                  Seeks to offset, reads Δn entries, closes fd.
                  Triggers seq_file start() re-traversal → O(N + Δn).

  Optimized:      Keeps the IMA pseudo-file fd open across epochs.
                  Reads only new entries from the current position → O(Δn).

The subscriber tells the agent which mode to use via the request's
`read_mode` field ("non_optimized" or "optimized").

Usage:
    # Start agent (supports both modes based on request):
    sudo python3 cvm_attestation_agent.py --port 8443

    # Self-test:
    sudo python3 cvm_attestation_agent.py --test
"""

import sys
import os
import socket
import ssl
import stat
import argparse
import subprocess
import json
import base64
import time
import ctypes
import ctypes.util
from datetime import datetime

# Add parent directory to path for common module
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                '..', 'sgx-tdx-attestation'))

from common.protocol import (
    AttestationRequest, AttestationResponse, ProtocolError,
    create_tls_context_server, send_message, receive_message,
    DEFAULT_PORT, PROTOCOL_VERSION, METHOD_ITA, METHOD_DCAP, VALID_METHODS,
    parse_dcap_quote
)


# ─── Read Modes ──────────────────────────────────────────────────────────────

READ_MODE_NON_OPTIMIZED = "non_optimized"
READ_MODE_OPTIMIZED = "optimized"


class CVMAttestationAgent:
    """
    CVM attestation agent for incremental attestation benchmarks.

    Supports two IMA reading strategies, selected per-request:
      - non_optimized: reopen fd each time, seek to offset
      - optimized: keep fd open, read only new entries
    """

    def __init__(self, port: int, cert_file: str, key_file: str,
                 config_path: str, method: str = METHOD_DCAP):
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.config_path = config_path
        self.method = method
        self.running = False

        # libtdx_attest library handle
        self._tdx_lib = None

        # IMA paths
        self.IMA_LOG_PATH = "/sys/kernel/security/ima/ascii_runtime_measurements"
        self.IMA_COUNT_PATH = "/sys/kernel/security/ima/runtime_measurements_count"
        # PCR10 SHA-1 bank: matches the SHA-1 template hashes in the ASCII
        # IMA log so the subscriber can replay the extend chain directly
        # from parts[1] without per-entry template_data reconstruction.
        self.PCR10_PATH = "/sys/class/tpm/tpm0/pcr-sha1/10"

        # Persistent IMA fd for optimized mode
        self._ima_fd = None
        self._ima_lines_read = 0

        # Statistics
        self.stats = {
            "requests": 0,
            "successful": 0,
            "failed": 0,
            "start_time": None
        }

        self._verify_setup()

    def _verify_setup(self):
        """Verify TDX and attestation dependencies are available."""
        if not os.path.exists("/dev/tdx_guest"):
            raise RuntimeError("TDX device not found: /dev/tdx_guest")

        if not os.path.exists(self.cert_file):
            raise RuntimeError(f"Certificate not found: {self.cert_file}")
        if not os.path.exists(self.key_file):
            raise RuntimeError(f"Private key not found: {self.key_file}")

        if self.method == METHOD_DCAP:
            self._tdx_lib = self._load_libtdx_attest()
            if self._tdx_lib is None:
                raise RuntimeError(
                    "libtdx_attest.so not found. Install with:\n"
                    "  sudo bash install_dcap_packages.sh")
        elif self.method == METHOD_ITA:
            if not os.path.exists(self.config_path):
                raise RuntimeError(f"Trust Authority config not found: {self.config_path}")
            result = subprocess.run(["which", "trustauthority-cli"],
                                    capture_output=True, text=True)
            if result.returncode != 0:
                raise RuntimeError("trustauthority-cli not found in PATH")

    def _load_libtdx_attest(self):
        """Load the libtdx_attest shared library for DCAP quote generation."""
        lib_paths = [
            "libtdx_attest.so",
            "libtdx_attest.so.1",
            ctypes.util.find_library("tdx_attest"),
        ]

        for path in lib_paths:
            if path is None:
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
                lib.tdx_att_free_quote.argtypes = [
                    ctypes.POINTER(ctypes.c_uint8),
                ]
                return lib
            except OSError:
                continue
        return None

    # ─── IMA Reading ─────────────────────────────────────────────────────

    def read_ima_count(self) -> int:
        """O(1) check: read runtime_measurements_count from kernel."""
        try:
            with open(self.IMA_COUNT_PATH, 'r') as f:
                return int(f.read().strip())
        except Exception:
            return -1

    def read_pcr10(self) -> str:
        """Read vTPM PCR 10 value."""
        try:
            with open(self.PCR10_PATH, 'r') as f:
                return f.read().strip()
        except Exception:
            return ""

    def read_ima_non_optimized(self, offset: int = 0) -> tuple:
        """
        Non-optimized IMA read: open fresh fd, skip to offset, read Δn.

        This triggers seq_file start() re-traversal from HEAD every time
        the file is opened, making it O(N) just to reach the offset position,
        plus O(Δn) to read the new entries.

        Args:
            offset: Number of entries to skip (subscriber's verified count)

        Returns:
            (log_text, total_entry_count, read_time_ms)
        """
        t0 = time.perf_counter()

        try:
            with open(self.IMA_LOG_PATH, 'r') as f:
                if offset > 0:
                    # Skip to offset — this triggers start() traversal
                    for _ in range(offset):
                        line = f.readline()
                        if not line:
                            break
                # Read remaining (Δn) entries
                new_lines = f.readlines()

            t1 = time.perf_counter()
            read_ms = (t1 - t0) * 1000

            if not new_lines:
                return "", offset, read_ms

            delta_text = ''.join(new_lines)
            total_count = offset + len(new_lines)
            return delta_text, total_count, read_ms

        except Exception as e:
            t1 = time.perf_counter()
            print(f"    [IMA] Error: {e}")
            return "", 0, (t1 - t0) * 1000

    def read_ima_optimized(self, offset: int = 0) -> tuple:
        """
        Optimized IMA read: use persistent fd, read only Δn new entries.

        On the first call (or if offset=0), opens a fresh fd and reads all.
        On subsequent calls, reads only new entries from the current
        file position — no start() re-traversal.

        Args:
            offset: Number of entries subscriber already has.
                    0 = full read (open fresh fd)
                    >0 = incremental (use persistent fd)

        Returns:
            (log_text, total_entry_count, read_time_ms)
        """
        t0 = time.perf_counter()

        try:
            if offset == 0:
                # Full read: close any existing fd, reopen fresh
                if self._ima_fd:
                    try:
                        self._ima_fd.close()
                    except Exception:
                        pass
                    self._ima_fd = None

                self._ima_fd = open(self.IMA_LOG_PATH, 'r')
                lines = self._ima_fd.readlines()
                self._ima_lines_read = len(lines)
                log_text = ''.join(lines)
                entry_count = len([l for l in lines if l.strip()])

                t1 = time.perf_counter()
                return log_text, entry_count, (t1 - t0) * 1000
            else:
                # Incremental: use persistent fd
                current_count = self.read_ima_count()
                if current_count >= 0 and current_count <= offset:
                    t1 = time.perf_counter()
                    return "", current_count, (t1 - t0) * 1000

                # If fd was lost, reopen and skip to offset
                if self._ima_fd is None or self._ima_fd.closed:
                    self._ima_fd = open(self.IMA_LOG_PATH, 'r')
                    for _ in range(offset):
                        line = self._ima_fd.readline()
                        if not line:
                            break
                    self._ima_lines_read = offset

                # Read new lines from current position
                new_lines = self._ima_fd.readlines()
                self._ima_lines_read += len(new_lines)

                t1 = time.perf_counter()

                if not new_lines:
                    return "", self._ima_lines_read, (t1 - t0) * 1000

                delta_text = ''.join(new_lines)
                return delta_text, self._ima_lines_read, (t1 - t0) * 1000

        except Exception as e:
            t1 = time.perf_counter()
            print(f"    [IMA] Error: {e}")
            return "", 0, (t1 - t0) * 1000

    # ─── IMA Delta Generation (for benchmark repeats) ─────────────────────

    def generate_ima_delta(self, count: int) -> dict:
        """
        Generate `count` new IMA entries by creating and executing unique
        shell scripts. Used by the benchmark to produce fresh delta entries
        between repeated attestation rounds.

        Returns:
            dict with generated count, total IMA count, and elapsed time
        """
        import tempfile

        tmp_dir = "/tmp/ima_bench_delta"
        os.makedirs(tmp_dir, exist_ok=True)

        before = self.read_ima_count()
        t0 = time.perf_counter()
        created = []

        for i in range(count):
            fname = os.path.join(tmp_dir, f"delta_{time.time_ns()}_{i}.sh")
            content = f"#!/bin/bash\n# delta idx={i} t={time.time_ns()}\necho ok\n"
            with open(fname, 'w') as f:
                f.write(content)
            os.chmod(fname, 0o755)
            subprocess.run([fname], capture_output=True)
            created.append(fname)

        t1 = time.perf_counter()

        # Clean up temp files
        for p in created:
            try:
                os.remove(p)
            except OSError:
                pass

        time.sleep(0.3)  # Allow IMA to finish processing
        after = self.read_ima_count()

        return {
            "status": "ok",
            "requested": count,
            "generated": after - before,
            "total_ima_count": after,
            "elapsed_ms": round((t1 - t0) * 1000, 1),
        }

    def reset_ima_fd(self, target_offset: int = 0) -> dict:
        """
        Close the persistent IMA fd and optionally re-open it at a target
        offset. This resets the agent's state so the next optimized read
        starts from the correct position — needed for benchmark repeats.

        Args:
            target_offset: Position to seek to after reopening (0 = don't reopen)

        Returns:
            dict with status and timing info
        """
        t0 = time.perf_counter()

        if self._ima_fd and not self._ima_fd.closed:
            self._ima_fd.close()
        self._ima_fd = None
        self._ima_lines_read = 0

        if target_offset > 0:
            self._ima_fd = open(self.IMA_LOG_PATH, 'r')
            for _ in range(target_offset):
                if not self._ima_fd.readline():
                    break
            self._ima_lines_read = target_offset

        t1 = time.perf_counter()
        return {
            "status": "ok",
            "fd_position": self._ima_lines_read,
            "elapsed_ms": round((t1 - t0) * 1000, 1),
        }

    # ─── TDX Quote Generation ────────────────────────────────────────────

    def get_tdx_quote_dcap(self, nonce: str) -> tuple:
        """Generate TDX DCAP quote with nonce in report_data."""
        if self._tdx_lib is None:
            raise RuntimeError("libtdx_attest not loaded")

        nonce_bytes = base64.b64decode(nonce)
        report_data = nonce_bytes + b'\x00' * (64 - len(nonce_bytes))
        report_data = report_data[:64]

        rd_buf = (ctypes.c_uint8 * 64)(*report_data)
        pp_quote = ctypes.POINTER(ctypes.c_uint8)()
        quote_size = ctypes.c_uint32(0)

        ret = self._tdx_lib.tdx_att_get_quote(
            ctypes.byref(rd_buf),
            None, 0, None,
            ctypes.byref(pp_quote),
            ctypes.byref(quote_size),
            0,
        )

        if ret != 0:
            raise RuntimeError(f"tdx_att_get_quote failed: error {ret} (0x{ret:08x})")

        size = quote_size.value
        quote_bytes = bytes(pp_quote[:size])
        self._tdx_lib.tdx_att_free_quote(pp_quote)

        info = parse_dcap_quote(quote_bytes)
        return quote_bytes, info.mrtd

    def get_tdx_token_ita(self, nonce: str) -> tuple:
        """Generate TDX attestation token via Intel Trust Authority."""
        cmd = [
            "sudo", "trustauthority-cli", "token", "--tdx",
            "-c", self.config_path,
            "-u", nonce[:32]
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            raise RuntimeError(f"Token generation failed: {result.stderr}")

        token_str = None
        for line in result.stdout.strip().split('\n'):
            if line.startswith('eyJ'):
                token_str = line
                break

        if not token_str:
            raise RuntimeError("No JWT token found in output")

        mrtd = self._extract_mrtd(token_str)
        return token_str, mrtd

    def _extract_mrtd(self, token: str) -> str:
        """Extract MRTD from JWT token payload."""
        try:
            parts = token.split('.')
            payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            if 'tdx' in payload:
                return payload['tdx'].get('tdx_mrtd', '')
        except Exception:
            pass
        return ''

    # ─── Request Handling ────────────────────────────────────────────────

    def handle_control_request(self, req_dict: dict) -> str:
        """
        Handle a control request (non-attestation operation).

        Supported actions:
          - generate_delta: Generate N new IMA entries
          - reset_fd: Close and reopen persistent IMA fd at target offset
        """
        action = req_dict.get("action", "")

        if action == "generate_delta":
            count = int(req_dict.get("count", 0))
            print(f"    [CTRL] Generating {count:,} IMA delta entries...")
            result = self.generate_ima_delta(count)
            print(f"    [CTRL] Generated {result['generated']:,} entries "
                  f"(total={result['total_ima_count']:,}, "
                  f"{result['elapsed_ms']:.0f}ms)")
            return json.dumps(result)

        elif action == "reset_fd":
            target = int(req_dict.get("target_offset", 0))
            print(f"    [CTRL] Resetting IMA fd to offset {target:,}...")
            result = self.reset_ima_fd(target_offset=target)
            print(f"    [CTRL] Fd reset to position {result['fd_position']:,} "
                  f"({result['elapsed_ms']:.1f}ms)")
            return json.dumps(result)

        else:
            return json.dumps({"status": "error", "error": f"Unknown control action: {action}"})

    def handle_request(self, request_json: str) -> str:
        """
        Handle an attestation or control request.

        The request may include:
          - ima_offset: number of entries subscriber already has
          - read_mode: "non_optimized" or "optimized" (default: optimized)
          - request_type: "control" for non-attestation operations
        """
        try:
            # Check for control requests first
            req_dict = json.loads(request_json)
            if req_dict.get("request_type") == "control":
                return self.handle_control_request(req_dict)

            request = AttestationRequest.from_json(request_json)
            valid, error = request.validate()
            if not valid:
                return AttestationResponse.error_response(error).to_json()

            # Parse read_mode from request (extension field)
            req_dict = json.loads(request_json)
            read_mode = req_dict.get("read_mode", READ_MODE_OPTIMIZED)

            # Generate TDX quote
            t_quote_start = time.perf_counter()
            if self.method == METHOD_DCAP:
                quote_bytes, mrtd = self.get_tdx_quote_dcap(request.nonce)
                response = AttestationResponse(
                    status="success",
                    nonce_echo=request.nonce,
                    mrtd=mrtd,
                    attestation_method=METHOD_DCAP,
                    raw_quote=base64.b64encode(quote_bytes).decode('ascii'),
                )
            else:
                token, mrtd = self.get_tdx_token_ita(request.nonce)
                response = AttestationResponse(
                    status="success",
                    token=token,
                    nonce_echo=request.nonce,
                    mrtd=mrtd,
                    attestation_method=METHOD_ITA,
                )
            t_quote_end = time.perf_counter()
            t_quote_ms = (t_quote_end - t_quote_start) * 1000

            # Read IMA log based on mode
            ima_offset = getattr(request, 'ima_offset', 0)

            if read_mode == READ_MODE_NON_OPTIMIZED:
                ima_log_text, total_count, t_ima_read_ms = \
                    self.read_ima_non_optimized(offset=ima_offset)
            else:
                ima_log_text, total_count, t_ima_read_ms = \
                    self.read_ima_optimized(offset=ima_offset)

            pcr10_value = self.read_pcr10()

            # Attach IMA data to response
            if ima_log_text:
                response.ima_log = base64.b64encode(
                    ima_log_text.encode('utf-8')
                ).decode('ascii')
                response.ima_entry_count = total_count
                response.pcr10 = pcr10_value

                delta_lines = len([l for l in ima_log_text.strip().split('\n') if l.strip()])
                print(f"    [IMA] mode={read_mode}: sent {delta_lines} entries "
                      f"(total={total_count}), read={t_ima_read_ms:.1f}ms, "
                      f"quote={t_quote_ms:.1f}ms")
            elif total_count > 0 and ima_offset > 0:
                response.ima_entry_count = total_count
                response.pcr10 = pcr10_value
                response.ima_log = ""
                print(f"    [IMA] mode={read_mode}: no new entries (total={total_count})")
            else:
                print(f"    [IMA] IMA log not available")

            # Embed server-side timing in response as extra JSON field
            # (using timestamp field to carry extra timing info is a hack,
            #  but avoids modifying the protocol dataclass)
            resp_dict = json.loads(response.to_json())
            resp_dict["_server_timing"] = {
                "t_ima_read_ms": round(t_ima_read_ms, 3),
                "t_quote_ms": round(t_quote_ms, 3),
                "read_mode": read_mode,
                "ima_offset": ima_offset,
            }

            self.stats["successful"] += 1
            return json.dumps(resp_dict)

        except Exception as e:
            self.stats["failed"] += 1
            return AttestationResponse.error_response(str(e)).to_json()

    def handle_client(self, client_socket: ssl.SSLSocket, addr: tuple):
        """Handle a single client connection."""
        self.stats["requests"] += 1
        req_num = self.stats["requests"]

        print(f"[{req_num}] Connection from {addr[0]}:{addr[1]}")

        try:
            start = time.time()
            request_json = receive_message(client_socket)
            receive_time = (time.time() - start) * 1000
            print(f"    Received: {len(request_json)} bytes ({receive_time:.1f}ms)")

            start = time.time()
            response_json = self.handle_request(request_json)
            process_time = (time.time() - start) * 1000

            send_message(client_socket, response_json)
            print(f"    ✓ Response sent ({process_time:.1f}ms processing)")

        except Exception as e:
            print(f"    ✗ Exception: {e}")
            try:
                error_response = AttestationResponse.error_response(str(e))
                send_message(client_socket, error_response.to_json())
            except Exception:
                pass

        finally:
            client_socket.close()

        print()

    def run(self):
        """Start the attestation agent."""
        tls_context = create_tls_context_server(self.cert_file, self.key_file)

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('0.0.0.0', self.port))
        server_socket.listen(5)

        tls_socket = tls_context.wrap_socket(server_socket, server_side=True)

        self.running = True
        self.stats["start_time"] = datetime.now().isoformat()

        self._print_banner()

        try:
            while self.running:
                try:
                    client, addr = tls_socket.accept()
                    self.handle_client(client, addr)
                except KeyboardInterrupt:
                    break
                except ssl.SSLError as e:
                    print(f"TLS error: {e}")
                except Exception as e:
                    print(f"Error: {e}")
        finally:
            tls_socket.close()
            # Close persistent fd if open
            if self._ima_fd:
                try:
                    self._ima_fd.close()
                except Exception:
                    pass
            self._print_stats()

    def _print_banner(self):
        """Print startup banner."""
        ima_count = self.read_ima_count()
        print("=" * 70)
        print("CVM Attestation Agent — Incremental Attestation Benchmark")
        print("=" * 70)
        print(f"Protocol Version:  {PROTOCOL_VERSION}")
        print(f"Port:              {self.port}")
        print(f"Method:            {self.method.upper()}")
        print(f"TLS Certificate:   {self.cert_file}")
        print(f"IMA Entry Count:   {ima_count:,}")
        print(f"Supports Modes:    non_optimized, optimized")
        print(f"Started:           {self.stats['start_time']}")
        print("=" * 70)
        print("\nWaiting for attestation requests from subscribers...\n")

    def _print_stats(self):
        """Print shutdown statistics."""
        print("\n" + "=" * 70)
        print("Agent Statistics")
        print("=" * 70)
        print(f"Total requests:  {self.stats['requests']}")
        print(f"Successful:      {self.stats['successful']}")
        print(f"Failed:          {self.stats['failed']}")
        print("=" * 70)


def self_test():
    """Run self-test to verify TDX attestation works."""
    print("=" * 70)
    print("CVM Attestation Agent — Self Test")
    print("=" * 70)

    print("\n[1] Checking TDX device...")
    if os.path.exists("/dev/tdx_guest"):
        print("    ✓ /dev/tdx_guest available")
    else:
        print("    ✗ TDX device not found")
        return False

    print("\n[2] Checking IMA paths...")
    ima_log = "/sys/kernel/security/ima/ascii_runtime_measurements"
    ima_count = "/sys/kernel/security/ima/runtime_measurements_count"
    pcr10 = "/sys/class/tpm/tpm0/pcr-sha1/10"

    for path, label in [(ima_log, "IMA log"), (ima_count, "IMA count"), (pcr10, "PCR 10")]:
        if os.path.exists(path):
            print(f"    ✓ {label}: {path}")
        else:
            print(f"    ✗ {label}: NOT FOUND at {path}")

    try:
        with open(ima_count, 'r') as f:
            count = int(f.read().strip())
        print(f"    ✓ Current IMA entries: {count:,}")
    except Exception as e:
        print(f"    ✗ Could not read IMA count: {e}")

    print("\n[3] Testing non-optimized read (first 100 entries)...")
    try:
        t0 = time.perf_counter()
        with open(ima_log, 'r') as f:
            lines = []
            for i, line in enumerate(f):
                if i >= 100:
                    break
                lines.append(line)
        t1 = time.perf_counter()
        print(f"    ✓ Read {len(lines)} entries in {(t1-t0)*1000:.1f}ms")
    except Exception as e:
        print(f"    ✗ Error: {e}")

    print("\n✓ Self-test complete")
    print("=" * 70)
    return True


def main():
    parser = argparse.ArgumentParser(
        description="CVM Attestation Agent for Incremental Attestation Benchmark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"Server port (default: {DEFAULT_PORT})")
    parser.add_argument("--cert", default=None,
                        help="TLS certificate file")
    parser.add_argument("--key", default=None,
                        help="TLS private key file")
    parser.add_argument("--config", default=os.path.expanduser("~/config.json"),
                        help="Intel Trust Authority config file (ITA mode)")
    parser.add_argument("--method", choices=[METHOD_ITA, METHOD_DCAP],
                        default=METHOD_DCAP,
                        help=f"Attestation method (default: {METHOD_DCAP})")
    parser.add_argument("--test", action="store_true",
                        help="Run self-test mode")

    args = parser.parse_args()

    if args.test:
        sys.exit(0 if self_test() else 1)

    # Resolve certificate paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    certs_dir = os.path.join(script_dir, '..', 'sgx-tdx-attestation', 'certs')

    cert_file = args.cert or os.path.join(certs_dir, 'server.crt')
    key_file = args.key or os.path.join(certs_dir, 'server.key')

    try:
        agent = CVMAttestationAgent(
            port=args.port,
            cert_file=cert_file,
            key_file=key_file,
            config_path=args.config,
            method=args.method,
        )
        agent.run()
    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
