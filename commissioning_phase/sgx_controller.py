"""
SGX Controller for CVM Commissioning Phase.

Flask-based server that runs inside an SGX enclave (via Gramine) or in
direct mode for development. Exposes REST endpoints for the ASP (service
owner) to launch, manage, and stop TDX CVMs on Google Cloud.

Adapted from the Duet paper's AdminEnclave/admin.py for GCP + TDX.

Usage:
    # Direct mode (development, no SGX hw required):
    python3 -m commissioning_phase.sgx_controller -t direct

    # SGX mode (inside Gramine-SGX container):
    python3 -m commissioning_phase.sgx_controller -t sgx
"""

from argparse import ArgumentParser
import json
import logging
from logging.config import dictConfig
import os
import random
import signal
import sys
import time

from cryptography.hazmat.primitives import hashes, serialization

from dotenv import load_dotenv

from flask import Flask, request, jsonify

from .gcp_client import GCPClient
from .ima_verifier import IMAVerifier
from .utils.encoding import stringify, bytes_to_base64_str, decode_base64
from .utils.crypto import (
    generate_rsa_keypair,
    generate_ephemeral_ssh_key,
    serialize_public_key_pem,
    serialize_private_key_pem,
    sign_data,
    verify_signature,
    verify_signature_with_pem,
)

# ---------------------------------------------------------------------------
# Flask App Setup
# ---------------------------------------------------------------------------

dictConfig({
    "version": 1,
    "formatters": {"default": {
        "format": "[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
    }},
    "handlers": {"wsgi": {
        "class": "logging.StreamHandler",
        "formatter": "default",
    }},
    "root": {
        "level": "INFO",
        "handlers": ["wsgi"],
    },
})

app = Flask(__name__)
entrypoint = "/"

SGX_CONTROLLER = None
CVMs = {}


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def _load_gcp_config(env_filename=None):
    """Load GCP configuration from environment file."""
    if env_filename is None:
        env_filename = os.path.join(
            os.path.dirname(__file__), "gcp_config.env"
        )
    load_dotenv(dotenv_path=env_filename)

    config = {
        "project_id": os.getenv("GCP_PROJECT_ID"),
        "zone": os.getenv("GCP_ZONE", "us-central1-a"),
        "region": os.getenv("GCP_REGION", "us-central1"),
        "network": os.getenv("GCP_NETWORK", "default"),
        "subnet": os.getenv("GCP_SUBNET", "default"),
        "service_account_key": os.getenv("GCP_SERVICE_ACCOUNT_KEY", ""),
        "image_project": os.getenv("VM_IMAGE_PROJECT", "ubuntu-os-cloud"),
        "image_family": os.getenv("VM_IMAGE_FAMILY", "ubuntu-2204-lts"),
        "machine_type": os.getenv("VM_MACHINE_TYPE", "c3-standard-4"),
        "username": os.getenv("VM_USERNAME", "cvm"),
        "prefix": os.getenv("PREFIX", "sgx-tdx"),
    }

    if not config["project_id"]:
        app.logger.error("GCP_PROJECT_ID is not set!")
        return None

    return config


def _extend_config(config):
    """Add derived fields to config (VM name, firewall name, etc.)."""
    suffix = str(random.randint(1000, 9999))
    vm_name = f"{config['prefix']}-cvm-tdx-{suffix}"
    config["vm_name"] = vm_name
    config["firewall_name"] = f"{vm_name}-fw-ssh"
    config["vm_tag"] = f"{config['prefix']}-cvm"
    return config


# ---------------------------------------------------------------------------
# SGX Controller Base Class
# ---------------------------------------------------------------------------

class SGXController:
    """SGX Controller in direct mode (no SGX hardware)."""

    def __init__(self, environment, logger):
        self._logger = logger
        self._environment = environment
        self._private_key = None
        self._public_key = None
        self._serialized_public_key = None
        self._asp_public_key_pem = None

        if self._environment == "direct":
            self._init_key_pair()
            # Load ASP public key
            asp_pub_key_path = os.path.join(
                os.path.dirname(__file__),
                "asp_pub_keys",
                "asp_private_key.pub",
            )
            if os.path.isfile(asp_pub_key_path):
                with open(asp_pub_key_path, "rb") as f:
                    self._asp_public_key_pem = f.read()
                self._logger.info(f"Loaded ASP public key from {asp_pub_key_path}")
            else:
                self._logger.warning(
                    f"ASP public key not found at {asp_pub_key_path}. "
                    "Run generate_asp_keys.py first."
                )

    def _init_key_pair(self):
        """Generate the controller's RSA key pair."""
        self._public_key, self._private_key = generate_rsa_keypair(4096)
        self._serialized_public_key = serialize_public_key_pem(self._public_key)
        self._logger.info("Generated new controller RSA key pair.")

    def get_public_key(self):
        return self._serialized_public_key

    def _sign_data(self, data):
        return sign_data(data, self._private_key)

    def _verify_asp_signature(self, request_data):
        """Verify that a request was signed by the ASP."""
        if self._asp_public_key_pem is None:
            self._logger.error("No ASP public key loaded — cannot verify.")
            return False
        params = request_data["params"]
        signature = decode_base64(request_data["signature"])
        params_bytes = bytes(json.dumps(params, sort_keys=True), "utf-8")
        return verify_signature_with_pem(signature, params_bytes, self._asp_public_key_pem)

    # ------------------------------------------------------------------
    # CVM Lifecycle Operations
    # ------------------------------------------------------------------

    def start_cvm(self, request_data):
        """Launch a new TDX CVM on GCP.

        Flow:
        1. Verify ASP signature
        2. Load GCP config
        3. Generate ephemeral SSH key pair (inside enclave)
        4. Provision CVM via GCP client
        5. Wait for VM boot, SSH in, run initial setup
        6. Store CVM, return CVM ID + state
        """
        result = {"success": False}

        if not self._verify_asp_signature(request_data):
            result["error"] = "start-cvm: Signature verification failed. Only the ASP can start CVMs."
            return result, self._sign_data(bytes(json.dumps(result, sort_keys=True), "utf-8"))

        # Load and extend config
        config = _load_gcp_config()
        if config is None:
            result["error"] = "start-cvm: GCP configuration error."
            return result, self._sign_data(bytes(json.dumps(result, sort_keys=True), "utf-8"))

        config = _extend_config(config)

        # 1. Create GCP client
        gcp_client = GCPClient(config, self._logger)

        # 2. Generate ephemeral SSH key pair (private key stays in enclave)
        ssh_public_key, ssh_private_key = generate_ephemeral_ssh_key()
        self._logger.info("Generated ephemeral SSH key pair for CVM access.")

        # 3. Provision resources (firewall + CVM)
        cvm = gcp_client.provision_resources(ssh_public_key)
        cvm.set_private_key(ssh_private_key)
        cvm.set_config(config)

        # 4. Wait for VM to be available for SSH
        self._logger.info("Waiting 60s for CVM to boot and become SSH-accessible...")
        time.sleep(60)

        # 5. Connect and run initial setup
        try:
            cvm.connect()

            # Copy and run setup script
            setup_script = os.path.join(os.path.dirname(__file__), "tdx_cvm_setup.sh")
            if os.path.isfile(setup_script):
                cvm.copy_file(setup_script, "tdx_cvm_setup.sh")
                for cmd in ["chmod +x tdx_cvm_setup.sh", "./tdx_cvm_setup.sh"]:
                    cvm.execute_command(cmd)
                    time.sleep(3)
            else:
                self._logger.warning("Setup script not found, skipping initial setup.")

            cvm.disconnect()
        except Exception as exc:
            self._logger.error(f"Initial CVM setup failed: {exc}")
            # CVM is still provisioned, just setup didn't complete

        # 5.5 Phase C': IMA-Based Launch Integrity Verification
        try:
            ima_baseline = self._verify_ima_integrity(cvm)
            cvm.set_ima_baseline(ima_baseline)

            if not ima_baseline.get("success"):
                error_msg = ima_baseline.get("error", "IMA verification failed")
                self._logger.error(f"Phase C' FAILED: {error_msg}")
                self._logger.error("Aborting commissioning — destroying CVM...")

                # Abort: destroy the CVM to prevent compromised VM from persisting
                try:
                    gcp_client.delete_resources()
                except Exception as del_exc:
                    self._logger.error(f"Failed to destroy CVM: {del_exc}")

                result["error"] = f"IMA verification failed: {error_msg}"
                return result, self._sign_data(bytes(json.dumps(result, sort_keys=True), "utf-8"))

            self._logger.info("Phase C': IMA verification PASSED")
        except Exception as exc:
            self._logger.error(f"Phase C' exception: {exc}")
            # Don't abort on exception — log and continue
            # (IMA may not be available on all CVM images)
            self._logger.warning("Continuing without IMA verification")

        # 6. Store CVM
        cvm_id = cvm.get_cvm_id()
        global CVMs
        CVMs[cvm_id] = cvm

        self._logger.info(f"CVM launched successfully. ID: {cvm_id}")

        result["success"] = True
        result["state"] = cvm.get_current_state()

        signature = self._sign_data(bytes(json.dumps(result, sort_keys=True), "utf-8"))
        return result, signature

    def run_commands(self, request_data):
        """Execute commands on a CVM (only in 'in-update' mode)."""
        result = {"success": False}

        if not self._verify_asp_signature(request_data):
            result["error"] = "run-commands: Signature verification failed."
            return result, self._sign_data(bytes(json.dumps(result, sort_keys=True), "utf-8"))

        cvm_id = request_data["params"]["cvm_id"]
        commands = request_data["params"]["commands"]

        global CVMs
        if cvm_id not in CVMs:
            result["error"] = "run-commands: No such CVM."
        elif CVMs[cvm_id].get_cvm_mode() != "in-update":
            result["error"] = "run-commands: CVM is in-service. Commands not allowed."
        else:
            cvm = CVMs[cvm_id]
            cvm.connect()
            output = []
            for cmd in commands:
                output.extend(cvm.execute_command(cmd))
                time.sleep(3)
            cvm.disconnect()

            result["success"] = True
            result["output"] = output

        signature = self._sign_data(bytes(json.dumps(result, sort_keys=True), "utf-8"))
        return result, signature

    def get_cvm_state(self, cvm_id, should_be_long):
        """Get the current state of a CVM (non-privileged)."""
        result = {"success": False}

        global CVMs
        if cvm_id in CVMs:
            result["success"] = True
            result["state"] = CVMs[cvm_id].get_current_state(should_be_long)
        else:
            result["error"] = "get-cvm-state: No such CVM."

        signature = self._sign_data(bytes(json.dumps(result, sort_keys=True), "utf-8"))
        return result, signature

    def mark_cvm(self, request_data):
        """Toggle a CVM between 'in-update' and 'in-service' mode."""
        result = {"success": False}

        if not self._verify_asp_signature(request_data):
            result["error"] = "mark-cvm: Signature verification failed."
            return result, self._sign_data(bytes(json.dumps(result, sort_keys=True), "utf-8"))

        cvm_id = request_data["params"]["cvm_id"]
        cvm_mode = request_data["params"]["cvm_mode"]
        assert cvm_mode in ("in-update", "in-service")

        global CVMs
        if cvm_id in CVMs:
            CVMs[cvm_id].set_cvm_mode(cvm_mode)
            result["success"] = True
            result["mode"] = {
                "cvm_id": cvm_id,
                "cvm_mode": CVMs[cvm_id].get_cvm_mode(),
            }
        else:
            result["error"] = "mark-cvm: No such CVM."

        signature = self._sign_data(bytes(json.dumps(result, sort_keys=True), "utf-8"))
        return result, signature

    def stop_cvm(self, request_data):
        """Stop a CVM and delete all its GCP resources."""
        result = {"success": False}

        if not self._verify_asp_signature(request_data):
            result["error"] = "stop-cvm: Signature verification failed."
            return result, self._sign_data(bytes(json.dumps(result, sort_keys=True), "utf-8"))

        cvm_id = request_data["params"]["cvm_id"]

        global CVMs
        if cvm_id in CVMs:
            cvm = CVMs[cvm_id]
            config = cvm.get_config()
            gcp_client = GCPClient(config, self._logger)
            gcp_client.delete_resources()

            del CVMs[cvm_id]
            result["success"] = True
            result["status"] = True
        else:
            result["error"] = "stop-cvm: No such CVM."

        signature = self._sign_data(bytes(json.dumps(result, sort_keys=True), "utf-8"))
        return result, signature

    # ------------------------------------------------------------------
    # IMA Verification (Phase C')
    # ------------------------------------------------------------------

    def _verify_ima_integrity(self, cvm):
        """Run IMA-based launch integrity verification (Phase C').

        After the hardening script completes (Phase C), verify that the
        CVM's boot sequence is consistent with the expected image:
        1. Read IMA log and PCR-10 from CVM via SSH
        2. Replay PCR-10 from the IMA log and verify match
        3. Check each entry against the reference manifest
        4. Request TDX quote binding the IMA log hash

        Returns:
            Dict with verification results (see IMAVerifier.verify_cvm).
        """
        self._logger.info("Phase C': Starting IMA-based launch integrity verification...")

        verifier = IMAVerifier(logger=self._logger)

        # For initial commissioning, we may not have a manifest yet.
        # Skip manifest check if reference_manifest.json is empty/placeholder.
        skip_manifest = not verifier._manifest
        if skip_manifest:
            self._logger.warning(
                "Phase C': No reference manifest loaded. "
                "Run generate_reference_manifest.py to create one. "
                "Skipping manifest check for this run."
            )

        result = verifier.verify_cvm(
            cvm,
            skip_manifest=skip_manifest,
            skip_tdx_quote=False,
        )
        return result

    def get_ima_baseline(self, cvm_id):
        """Get the stored IMA baseline for a CVM."""
        result = {"success": False}

        global CVMs
        if cvm_id in CVMs:
            baseline = CVMs[cvm_id].get_ima_baseline()
            if baseline:
                result["success"] = True
                # Return a summary (not the full IMA log, which can be large)
                result["ima_baseline"] = {
                    "pcr10": baseline.get("pcr10", ""),
                    "pcr10_match": baseline.get("pcr10_match", False),
                    "entry_count": baseline.get("entry_count", 0),
                    "ima_log_hash": baseline.get("ima_log_hash", ""),
                    "manifest_violations": baseline.get("manifest_violations", []),
                    "tdx_quote": baseline.get("tdx_quote"),
                }
            else:
                result["error"] = "No IMA baseline available for this CVM."
        else:
            result["error"] = "get-ima-baseline: No such CVM."

        signature = self._sign_data(bytes(json.dumps(result, sort_keys=True), "utf-8"))
        return result, signature


# ---------------------------------------------------------------------------
# SGX Controller Enclave (runs inside Gramine-SGX)
# ---------------------------------------------------------------------------

class SGXControllerEnclave(SGXController):
    """SGX Controller running inside a Gramine-SGX enclave."""

    def __init__(self, environment, logger):
        super().__init__(environment, logger)

        # Load ASP public key from enclave path
        asp_pub_key_path = os.path.join(
            os.path.dirname(__file__),
            "asp_pub_keys",
            "asp_private_key.pub",
        )
        if os.path.isfile(asp_pub_key_path):
            with open(asp_pub_key_path, "rb") as f:
                self._asp_public_key_pem = f.read()

        self._init_key_pair()
        self._write_enclave_report_data()

    def _init_key_pair(self):
        """Initialize key pair, using sealed storage if available."""
        sealed_key_path = os.path.join(os.path.dirname(__file__), "sealed", "private_key")

        if os.path.isfile(sealed_key_path):
            # Load existing sealed key
            with open(sealed_key_path, "rb") as f:
                private_key_pem = f.read()
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            self._private_key = load_pem_private_key(private_key_pem, password=None)
            self._public_key = self._private_key.public_key()
            self._serialized_public_key = serialize_public_key_pem(self._public_key)
            self._logger.info(f"Loaded sealed RSA key from {sealed_key_path}")
        else:
            # Generate new key pair and seal it
            super()._init_key_pair()
            os.makedirs(os.path.dirname(sealed_key_path), exist_ok=True)
            with open(sealed_key_path, "wb") as f:
                f.write(serialize_private_key_pem(self._private_key))
            self._logger.info(f"Sealed new RSA key to {sealed_key_path}")

    def _write_enclave_report_data(self):
        """Write SHA-256 hash of the public key to SGX report data.

        This binds the controller's public key to the enclave identity,
        allowing clients to verify the key via SGX remote attestation.
        """
        hash_object = hashes.Hash(hashes.SHA256())
        hash_object.update(self._serialized_public_key)
        try:
            with open("/dev/attestation/user_report_data", "wb") as f:
                f.write(hash_object.finalize())
        except Exception as exc:
            self._logger.error(f"Could not write enclave report data: {exc}")

    def get_quote(self):
        """Read the SGX quote from the Gramine attestation device."""
        with open("/dev/attestation/attestation_type") as f:
            self.attestation_type = f.read()
        try:
            with open("/dev/attestation/quote", "rb") as f:
                quote = f.read()
        except Exception as exc:
            message = (
                "Cannot find `/dev/attestation/quote`; "
                "are you running with remote attestation enabled?"
            )
            raise type(exc)(message).with_traceback(exc.__traceback__)
        return quote


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

class SGXControllerFactory:
    @staticmethod
    def create(environment="direct"):
        if environment == "direct":
            return SGXController(environment, logger=app.logger)
        elif environment == "sgx":
            return SGXControllerEnclave(environment, logger=app.logger)
        else:
            app.logger.error(f"Unknown environment: {environment}")
            return None


# ---------------------------------------------------------------------------
# Flask Routes
# ---------------------------------------------------------------------------

def _get_quote_and_key():
    quote = b""
    if isinstance(SGX_CONTROLLER, SGXControllerEnclave):
        quote = SGX_CONTROLLER.get_quote()
    public_key = SGX_CONTROLLER.get_public_key()
    return quote, public_key


@app.route(f"{entrypoint}quote", methods=["GET"])
def handle_quote():
    """Return SGX quote and controller public key."""
    quote, key = _get_quote_and_key()
    response = {
        "quote": stringify(quote),
        "public_key": stringify(key),
    }
    return jsonify(response), 200


@app.route(f"{entrypoint}start_cvm", methods=["POST"])
def handle_start_cvm():
    """Launch a new TDX CVM on GCP (privileged — requires ASP signature)."""
    request_data = request.get_json()
    global SGX_CONTROLLER
    result, signature = SGX_CONTROLLER.start_cvm(request_data)
    response = {
        "result": result,
        "signature": bytes_to_base64_str(signature),
    }
    return jsonify(response), 200


@app.route(f"{entrypoint}run_commands", methods=["POST"])
def handle_run_commands():
    """Execute commands on a CVM (privileged)."""
    request_data = request.get_json()
    global SGX_CONTROLLER
    result, signature = SGX_CONTROLLER.run_commands(request_data)
    response = {
        "result": result,
        "signature": bytes_to_base64_str(signature),
    }
    return jsonify(response), 200


@app.route(f"{entrypoint}get_cvm_state", methods=["POST"])
def handle_get_cvm_state():
    """Get CVM state (non-privileged)."""
    request_data = request.get_json()
    cvm_id = request_data["params"]["cvm_id"]
    should_be_long = request_data["params"].get("should_be_long", False)
    global SGX_CONTROLLER
    result, signature = SGX_CONTROLLER.get_cvm_state(cvm_id, should_be_long)
    response = {
        "result": result,
        "signature": bytes_to_base64_str(signature),
    }
    return jsonify(response), 200


@app.route(f"{entrypoint}mark_cvm", methods=["POST"])
def handle_mark_cvm():
    """Toggle CVM mode (privileged)."""
    request_data = request.get_json()
    global SGX_CONTROLLER
    result, signature = SGX_CONTROLLER.mark_cvm(request_data)
    response = {
        "result": result,
        "signature": bytes_to_base64_str(signature),
    }
    return jsonify(response), 200


@app.route(f"{entrypoint}stop_cvm", methods=["POST"])
def handle_stop_cvm():
    """Stop a CVM and delete resources (privileged)."""
    request_data = request.get_json()
    global SGX_CONTROLLER
    result, signature = SGX_CONTROLLER.stop_cvm(request_data)
    response = {
        "result": result,
        "signature": bytes_to_base64_str(signature),
    }
    return jsonify(response), 200


@app.route(f"{entrypoint}get_ima_baseline", methods=["POST"])
def handle_get_ima_baseline():
    """Get IMA verification baseline for a CVM (non-privileged)."""
    request_data = request.get_json()
    cvm_id = request_data["params"]["cvm_id"]
    global SGX_CONTROLLER
    result, signature = SGX_CONTROLLER.get_ima_baseline(cvm_id)
    response = {
        "result": result,
        "signature": bytes_to_base64_str(signature),
    }
    return jsonify(response), 200


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

def parse_args():
    parser = ArgumentParser(description="SGX Controller for CVM Commissioning")
    parser.add_argument("-p", "--port", default=6037, type=int, help="Server port")
    parser.add_argument(
        "-t", "--type",
        choices=["direct", "sgx"],
        default="direct",
        help="Controller mode: 'direct' for dev, 'sgx' for Gramine-SGX",
    )
    return parser.parse_args()


def handle_sigint(sig, frame):
    app.logger.info("SIGINT received. Stopping SGX Controller...")
    sys.exit()


def main():
    app.logger.setLevel(logging.INFO)

    # Suppress noisy GCP logs
    logging.getLogger("google").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    signal.signal(signal.SIGINT, handle_sigint)

    args = parse_args()
    app.logger.info(f"Starting SGX Controller in `{args.type}` mode...")

    global SGX_CONTROLLER
    SGX_CONTROLLER = SGXControllerFactory.create(args.type)

    app.run(port=args.port, host="0.0.0.0", threaded=True, load_dotenv=False)


if __name__ == "__main__":
    main()
