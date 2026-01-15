#!/usr/bin/env python3
"""
SGX-TDX Runtime Update Protocol

Data structures and utilities for secure command execution on TDX VMs
through SGX enclave gateway with ASP authentication.
"""

import json
import time
import hashlib
import base64
import secrets
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
from datetime import datetime


# Protocol version
PROTOCOL_VERSION = "1.0"

# Default ports
GATEWAY_PORT = 8445
DEFAULT_SSH_PORT = 22


# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class SignedCommand:
    """
    Command payload signed by an ASP.
    
    The ASP creates this structure, signs it, and sends to the SGX gateway.
    """
    asp_id: str                    # ASP identifier
    target_vm: str                 # Target TDX VM IP/hostname
    command: str                   # Command to execute (e.g., "apt-get update")
    timestamp: float               # Unix timestamp when command was created
    nonce: str                     # Random nonce for replay protection
    signature: str = ""            # Base64-encoded signature of the payload
    
    def to_json(self) -> str:
        return json.dumps(asdict(self))
    
    @classmethod
    def from_json(cls, json_str: str) -> 'SignedCommand':
        data = json.loads(json_str)
        return cls(**data)
    
    def get_signable_data(self) -> bytes:
        """Get the data that should be signed (excludes signature field)."""
        data = {
            "asp_id": self.asp_id,
            "target_vm": self.target_vm,
            "command": self.command,
            "timestamp": self.timestamp,
            "nonce": self.nonce
        }
        return json.dumps(data, sort_keys=True).encode('utf-8')
    
    def validate(self, max_age_seconds: int = 300) -> tuple:
        """
        Validate command structure (not signature).
        
        Returns:
            (is_valid, error_message)
        """
        # Check timestamp freshness
        age = time.time() - self.timestamp
        if age > max_age_seconds:
            return False, f"Command expired: {age:.0f}s old (max {max_age_seconds}s)"
        if age < -60:  # Allow 60s clock skew
            return False, f"Command timestamp in future: {-age:.0f}s"
        
        # Check required fields
        if not self.asp_id:
            return False, "Missing asp_id"
        if not self.target_vm:
            return False, "Missing target_vm"
        if not self.command:
            return False, "Missing command"
        if not self.nonce:
            return False, "Missing nonce"
        
        return True, None


@dataclass
class CommandResult:
    """Result of executing a command on TDX VM."""
    success: bool
    exit_code: int
    stdout: str
    stderr: str
    execution_time_ms: float
    timestamp: float = field(default_factory=time.time)
    
    def to_json(self) -> str:
        return json.dumps(asdict(self))
    
    @classmethod
    def from_json(cls, json_str: str) -> 'CommandResult':
        data = json.loads(json_str)
        return cls(**data)


@dataclass
class AuditLogEntry:
    """
    Audit log entry for command execution.
    
    Stored in sealed enclave storage and signed for integrity.
    """
    log_id: str                     # Unique log entry ID
    asp_id: str                     # ASP who issued the command
    target_vm: str                  # Target VM
    command: str                    # Command executed
    command_timestamp: float        # When ASP created the command
    execution_timestamp: float      # When enclave executed it
    result: CommandResult           # Execution result
    enclave_signature: str = ""     # Signature by enclave's key
    
    def to_json(self) -> str:
        data = asdict(self)
        data['result'] = asdict(self.result)
        return json.dumps(data)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'AuditLogEntry':
        data = json.loads(json_str)
        data['result'] = CommandResult(**data['result'])
        return cls(**data)
    
    def get_signable_data(self) -> bytes:
        """Get the data that should be signed (excludes enclave_signature)."""
        data = {
            "log_id": self.log_id,
            "asp_id": self.asp_id,
            "target_vm": self.target_vm,
            "command": self.command,
            "command_timestamp": self.command_timestamp,
            "execution_timestamp": self.execution_timestamp,
            "result": asdict(self.result)
        }
        return json.dumps(data, sort_keys=True).encode('utf-8')


@dataclass
class ASPInfo:
    """Information about a registered ASP."""
    asp_id: str
    name: str
    public_key_pem: str
    allowed_vms: List[str]
    
    @classmethod
    def from_dict(cls, data: dict) -> 'ASPInfo':
        return cls(**data)


@dataclass
class GatewayRequest:
    """Request to the SGX gateway."""
    request_type: str  # "execute_command", "get_logs", "verify_log"
    payload: str       # JSON payload (SignedCommand for execute_command)
    
    def to_json(self) -> str:
        return json.dumps(asdict(self))
    
    @classmethod
    def from_json(cls, json_str: str) -> 'GatewayRequest':
        data = json.loads(json_str)
        return cls(**data)


@dataclass
class GatewayResponse:
    """Response from the SGX gateway."""
    success: bool
    message: str
    data: Optional[str] = None  # JSON payload (CommandResult, logs, etc.)
    
    def to_json(self) -> str:
        return json.dumps(asdict(self))
    
    @classmethod
    def from_json(cls, json_str: str) -> 'GatewayResponse':
        data = json.loads(json_str)
        return cls(**data)


# =============================================================================
# Utility Functions
# =============================================================================

def generate_nonce() -> str:
    """Generate a cryptographic nonce for replay protection."""
    return base64.b64encode(secrets.token_bytes(32)).decode('utf-8')


def generate_log_id() -> str:
    """Generate a unique log entry ID."""
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    random_part = secrets.token_hex(8)
    return f"log-{timestamp}-{random_part}"


# =============================================================================
# TLS Utilities (reused from attestation protocol)
# =============================================================================

def create_tls_context_server(cert_file: str, key_file: str,
                               ca_cert_file: str = None,
                               require_client_cert: bool = False):
    """Create TLS context for gateway server with optional mTLS."""
    import ssl
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    
    if require_client_cert:
        if not ca_cert_file:
            raise ValueError("CA certificate required for mTLS")
        context.load_verify_locations(ca_cert_file)
        context.verify_mode = ssl.CERT_REQUIRED
    
    return context


def create_tls_context_client(ca_cert_file: str = None,
                               client_cert_file: str = None,
                               client_key_file: str = None,
                               verify: bool = True):
    """Create TLS context for client with optional mTLS."""
    import ssl
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    
    if verify and ca_cert_file:
        context.load_verify_locations(ca_cert_file)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_REQUIRED
    else:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    
    if client_cert_file and client_key_file:
        context.load_cert_chain(client_cert_file, client_key_file)
    
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


# Message framing
MESSAGE_DELIMITER = b'\n---END---\n'

def send_message(sock, message: str):
    """Send a framed message over socket."""
    data = message.encode('utf-8') + MESSAGE_DELIMITER
    sock.sendall(data)


def receive_message(sock, timeout: float = 30.0) -> str:
    """Receive a framed message from socket."""
    sock.settimeout(timeout)
    buffer = b""
    while MESSAGE_DELIMITER not in buffer:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buffer += chunk
        if len(buffer) > 1000000:  # 1MB max
            raise RuntimeError("Message too large")
    
    if MESSAGE_DELIMITER in buffer:
        message, _ = buffer.split(MESSAGE_DELIMITER, 1)
        return message.decode('utf-8')
    
    raise RuntimeError("Incomplete message received")
