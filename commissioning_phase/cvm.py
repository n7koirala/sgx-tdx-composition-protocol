"""
Confidential VM (CVM) model for the commissioning phase.

Represents a launched TDX CVM on GCP. Handles SSH connections via
Paramiko using the ephemeral private key generated inside the SGX
controller enclave. Tracks command execution history with SHA-256
hashes for audit.
"""

import io
import uuid

from cryptography.hazmat.primitives import hashes

import paramiko


class ConfidentialVM:
    """Represents a running TDX Confidential VM."""

    def __init__(self, username, ip_address, serialized_public_key, logger):
        self._logger = logger
        self._username = username
        self._ip_address = ip_address
        self._serialized_public_key = serialized_public_key

        # Derive CVM ID from hash of the SSH public key
        hash_object = hashes.Hash(hashes.SHA256())
        hash_object.update(bytes(self._serialized_public_key, "utf-8"))
        self._cvm_id = hash_object.finalize().hex()
        self._logger.info(f"CVM ID: {self._cvm_id}")

        # Command audit trail
        self._command_outputs = []
        self._command_output_hashes = []

        # GCP config (set after provisioning)
        self._config = None

        # SSH state
        self._ssh_client = None
        self._private_key = None
        self._sftp_client = None

        # Lifecycle mode: "in-update" allows commands, "in-service" blocks them
        self._mode = "in-update"

    # ------------------------------------------------------------------
    # Properties / Getters / Setters
    # ------------------------------------------------------------------

    def get_cvm_id(self):
        return self._cvm_id

    def get_cvm_type(self):
        return "tdx"

    def set_config(self, config):
        self._config = config

    def get_config(self):
        return self._config

    def set_cvm_mode(self, mode):
        assert mode in ("in-update", "in-service")
        self._mode = mode

    def get_cvm_mode(self):
        return self._mode

    def get_ip_address(self):
        return self._ip_address

    def get_current_state(self, should_be_long=False):
        """Return the CVM state including command audit trail."""
        state = {
            "cvm_id": self._cvm_id,
            "ip_address": self._ip_address,
            "mode": self._mode,
        }
        if should_be_long:
            state["command_outputs"] = self._command_outputs
        else:
            state["command_output_hashes"] = self._command_output_hashes
        return state

    # ------------------------------------------------------------------
    # SSH Key Management
    # ------------------------------------------------------------------

    def set_private_key(self, pkey_str):
        """Load the ephemeral private key from a PEM string for SSH."""
        pkeyfile = io.StringIO(pkey_str)
        self._private_key = paramiko.RSAKey.from_private_key(pkeyfile)

    # ------------------------------------------------------------------
    # SSH Connection
    # ------------------------------------------------------------------

    def _get_ssh_client(self):
        if not self._ssh_client:
            self._ssh_client = paramiko.SSHClient()
            self._ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        return self._ssh_client

    def connect(self):
        """Establish SSH connection to the CVM."""
        self._ssh_client = self._get_ssh_client()
        self._logger.info(f"Connecting to CVM at {self._ip_address} as {self._username}...")
        self._ssh_client.connect(
            self._ip_address,
            username=self._username,
            pkey=self._private_key,
            timeout=30,
        )
        self._logger.info(f"Connected to CVM at {self._ip_address}")

    def disconnect(self):
        """Close the SSH connection."""
        if self._sftp_client:
            self._sftp_client.close()
            self._sftp_client = None
        if self._ssh_client:
            self._ssh_client.close()
            self._ssh_client = None
        self._logger.info(f"Disconnected from CVM at {self._ip_address}")

    # ------------------------------------------------------------------
    # Command Execution
    # ------------------------------------------------------------------

    def execute_command(self, command):
        """Execute a command on the CVM via SSH.

        Records the command and its output in the audit trail.
        Returns the output lines.
        """
        if not self._ssh_client:
            self.connect()

        self._logger.info(f"Executing on CVM: {command}")
        _stdin, _stdout, _stderr = self._ssh_client.exec_command(command, get_pty=True)

        output = []
        for line in iter(_stdout.readline, ""):
            output.append(line)
            self._logger.info(line.strip("\n"))

        # Store full output
        self._command_outputs.append({
            "command": command,
            "output": output,
        })

        # Store output hash for compact audit trail
        hash_object = hashes.Hash(hashes.SHA256())
        hash_object.update(bytes(str(output), "utf-8"))
        output_hash = hash_object.finalize().hex()
        self._command_output_hashes.append({
            "command": command,
            "output_hash": output_hash,
        })

        return output

    # ------------------------------------------------------------------
    # File Transfer
    # ------------------------------------------------------------------

    def _get_sftp_client(self):
        if not self._sftp_client:
            if not self._ssh_client:
                self.connect()
            self._sftp_client = self._ssh_client.open_sftp()
        return self._sftp_client

    def copy_file(self, local_path, remote_filename):
        """Copy a local file to the CVM's home directory."""
        sftp = self._get_sftp_client()
        remote_path = f"/home/{self._username}/{remote_filename}"
        self._logger.info(f"Copying {local_path} -> {remote_path}")
        sftp.put(local_path, remote_path)
