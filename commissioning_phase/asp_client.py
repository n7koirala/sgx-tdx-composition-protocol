"""
ASP (Application Service Provider) Client for CVM Commissioning.

Client library and CLI for interacting with the SGX controller to
launch, manage, and stop TDX CVMs on GCP.

The ASP (service owner) signs privileged requests with their private key.
The controller verifies the signature before performing the operation.

Usage:
    python3 -m commissioning_phase.asp_client --action start-cvm
    python3 -m commissioning_phase.asp_client --action run-commands --cvm-id <ID> --command "uname -a"
    python3 -m commissioning_phase.asp_client --action stop-cvm --cvm-id <ID>
"""

from argparse import ArgumentParser
import base64
import json
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import (
    load_pem_public_key,
    load_pem_private_key,
)

import requests

from .utils.encoding import bytes_to_base64_str, decode_base64


# ---------------------------------------------------------------------------
# Controller Quote Verification
# ---------------------------------------------------------------------------

def _verify_public_key_hash(key_hash_received, enclave_key):
    """Verify that the hash in the SGX quote matches the controller's public key."""
    if not isinstance(enclave_key, bytes):
        enclave_key = bytes(enclave_key, "utf-8")

    h = hashes.Hash(hashes.SHA256())
    h.update(enclave_key)
    calculated = h.finalize().hex()

    return calculated == key_hash_received


def verify_remote_enclave(remote_quote, remote_public_key):
    """Verify the SGX controller's quote and public key binding.

    In direct mode, the quote will be empty and verification is skipped
    with a warning.
    """
    if not isinstance(remote_quote, bytes):
        remote_quote = bytes(remote_quote, "utf-8")
    if not isinstance(remote_public_key, bytes):
        remote_public_key = bytes(remote_public_key, "utf-8")

    # If quote is empty, skip verification (direct mode)
    if len(remote_quote) < 100:
        return False

    remote_quote = base64.b64decode(remote_quote)

    # Verify the public key hash is bound in the quote's report data
    if not _verify_public_key_hash(remote_quote[368:400].hex(), remote_public_key):
        return False

    return True


# ---------------------------------------------------------------------------
# ASP Client
# ---------------------------------------------------------------------------

class ASPClient:
    """Client for the ASP (Application Service Provider) to interact
    with the SGX controller."""

    def __init__(self, base_url, asp_private_key_file=None):
        self._base_url = base_url.rstrip("/")

        # Load ASP private key for signing privileged requests
        if asp_private_key_file:
            with open(asp_private_key_file, "rb") as f:
                self._asp_private_key = load_pem_private_key(
                    f.read(), None, default_backend()
                )
            self._asp_public_key = self._asp_private_key.public_key()

        # Controller state
        self._controller_public_key = None
        self._controller_quote_verified = False

        # Verify controller on init
        self._verify_controller()

    def _sign_data(self, data: bytes) -> bytes:
        """Sign data with the ASP's private key."""
        return self._asp_private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

    def _prepare_request(self, params, is_privileged=False):
        """Prepare a request payload, optionally signing it."""
        data = {"params": params}
        if is_privileged:
            signature = self._sign_data(
                bytes(json.dumps(params, sort_keys=True), "utf-8")
            )
            data["signature"] = bytes_to_base64_str(signature)
        return data

    def _post(self, endpoint, params, is_privileged=False):
        """Send a POST request to the controller."""
        url = f"{self._base_url}/{endpoint}"
        data = self._prepare_request(params, is_privileged)
        try:
            response = requests.post(url, json=data, timeout=600)
            if response.status_code != 200 or "application/json" not in response.headers.get("content-type", ""):
                print(f"[ERROR] Server returned HTTP {response.status_code}")
                print(f"  Response body: {response.text[:500]}")
                raise RuntimeError(
                    f"Controller returned HTTP {response.status_code} "
                    f"(expected 200 with JSON). Check the controller logs."
                )
            return response.json(), response.status_code
        except requests.exceptions.RequestException as exc:
            print(f"Request failed: {exc}")
            raise

    def _verify_controller(self):
        """Verify the SGX controller's identity via its quote."""
        try:
            url = f"{self._base_url}/quote"
            response = requests.get(url, timeout=30)
            response_data = response.json()

            quote = response_data["quote"]
            public_key = bytes(response_data["public_key"], "utf-8")

            self._controller_quote_verified = verify_remote_enclave(quote, public_key)
            print(f"SGX controller verified: {self._controller_quote_verified}")
            if not self._controller_quote_verified:
                print("[WARNING]: Unverified SGX controller (direct mode or quote invalid).")

            self._controller_public_key = load_pem_public_key(public_key)
        except Exception as exc:
            print(f"Controller verification failed: {exc}")
            raise

    def _verify_controller_signature(self, signature, data):
        """Verify the controller's response signature."""
        if not isinstance(signature, bytes):
            signature = bytes(signature, "utf-8")
        if not isinstance(data, bytes):
            data = bytes(data, "utf-8")

        try:
            self._controller_public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False

    def _process_response(self, response_data):
        """Verify controller signature on response and return result."""
        result = response_data["result"]
        signature = decode_base64(response_data["signature"])
        result_bytes = bytes(json.dumps(result, sort_keys=True), "utf-8")
        verified = self._verify_controller_signature(signature, result_bytes)
        if not verified:
            print("[ERROR]: Controller response signature verification failed!")
            return None
        return result

    # ------------------------------------------------------------------
    # CVM Operations
    # ------------------------------------------------------------------

    def start_cvm(self):
        """Launch a new TDX CVM on GCP."""
        params = {"cvm_type": "tdx"}
        response_data, code = self._post("start_cvm", params, is_privileged=True)
        return self._process_response(response_data)

    def get_cvm_state(self, cvm_id, should_be_long=False):
        """Get the state of a CVM."""
        params = {"cvm_id": cvm_id, "should_be_long": should_be_long}
        response_data, code = self._post("get_cvm_state", params, is_privileged=False)
        result = self._process_response(response_data)
        if result and result["success"]:
            state = result["state"]
            list_name = "command_outputs" if should_be_long else "command_output_hashes"
            param_name = "output" if should_be_long else "output_hash"

            if list_name in state:
                for entry in state[list_name]:
                    print(f"  command: {entry['command']}")
                    print(f"  {param_name}: {entry[param_name]}")
                    print("-" * 40)
        return result

    def run_commands(self, cvm_id, commands):
        """Execute commands on a CVM (must be in 'in-update' mode)."""
        params = {"cvm_id": cvm_id, "commands": commands}
        response_data, code = self._post("run_commands", params, is_privileged=True)
        return self._process_response(response_data)

    def mark_cvm(self, cvm_id, cvm_mode):
        """Toggle CVM between 'in-update' and 'in-service' mode."""
        params = {"cvm_id": cvm_id, "cvm_mode": cvm_mode}
        response_data, code = self._post("mark_cvm", params, is_privileged=True)
        return self._process_response(response_data)

    def stop_cvm(self, cvm_id):
        """Stop a CVM and delete all its GCP resources."""
        params = {"cvm_id": cvm_id}
        response_data, code = self._post("stop_cvm", params, is_privileged=True)
        return self._process_response(response_data)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    parser = ArgumentParser(description="ASP Client for CVM Commissioning")
    parser.add_argument(
        "--url", default="http://127.0.0.1:6037",
        help="Controller URL",
    )
    parser.add_argument(
        "--asp-private-key-file",
        default="commissioning_phase/asp_private_key",
        help="Path to ASP private key",
    )
    parser.add_argument(
        "--action", required=True,
        choices=["start-cvm", "stop-cvm", "run-commands", "mark-cvm",
                 "get-cvm-state", "get-cvm-state-long"],
        help="Action to perform",
    )
    parser.add_argument("--cvm-id", help="CVM ID (required for most actions)")
    parser.add_argument("--cvm-mode", choices=["in-update", "in-service"],
                        help="CVM mode (for mark-cvm)")
    parser.add_argument("--command", nargs="+", action="append",
                        help="Command(s) to run on the CVM")
    return parser.parse_args()


def main():
    args = parse_args()

    print("=" * 60)
    print(f"  ASP Client — Action: {args.action}")
    print("=" * 60)

    client = ASPClient(args.url, args.asp_private_key_file)

    if args.action == "start-cvm":
        result = client.start_cvm()
        if result and result["success"]:
            print(f"\n✓ CVM launched successfully!")
            print(f"  CVM ID: {result['state']['cvm_id']}")
            print(f"  IP: {result['state']['ip_address']}")
        else:
            print(f"\n✗ Failed: {result.get('error', 'Unknown error')}")

    elif args.action == "stop-cvm":
        if not args.cvm_id:
            print("ERROR: --cvm-id is required")
            return
        result = client.stop_cvm(args.cvm_id)
        if result and result["success"]:
            print(f"\n✓ CVM stopped and resources deleted.")
        else:
            print(f"\n✗ Failed: {result.get('error', 'Unknown error')}")

    elif args.action == "run-commands":
        if not args.cvm_id or not args.command:
            print("ERROR: --cvm-id and --command are required")
            return
        commands = ["".join(c) for c in args.command]
        result = client.run_commands(args.cvm_id, commands)
        if result and result["success"]:
            print(f"\n✓ Commands executed successfully.")
            for line in result.get("output", []):
                print(f"  {line}", end="")
        else:
            print(f"\n✗ Failed: {result.get('error', 'Unknown error')}")

    elif args.action == "mark-cvm":
        if not args.cvm_id or not args.cvm_mode:
            print("ERROR: --cvm-id and --cvm-mode are required")
            return
        result = client.mark_cvm(args.cvm_id, args.cvm_mode)
        if result and result["success"]:
            print(f"\n✓ CVM mode changed to: {result['mode']['cvm_mode']}")
        else:
            print(f"\n✗ Failed: {result.get('error', 'Unknown error')}")

    elif args.action in ("get-cvm-state", "get-cvm-state-long"):
        if not args.cvm_id:
            print("ERROR: --cvm-id is required")
            return
        should_be_long = args.action == "get-cvm-state-long"
        result = client.get_cvm_state(args.cvm_id, should_be_long)
        if result and result["success"]:
            print(f"\n✓ CVM State:")
            print(json.dumps(result["state"], indent=2))
        else:
            print(f"\n✗ Failed: {result.get('error', 'Unknown error')}")

    print()


if __name__ == "__main__":
    main()
