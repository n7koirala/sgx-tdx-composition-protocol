#!/usr/bin/env python3
"""
TDX Command Executor

Executes commands on TDX VMs via the TDX Runtime Server.
This replaces SSH-based execution for the SGX controller.
"""

import socket
import ssl
import json
import time
import uuid
from dataclasses import dataclass, asdict
from typing import Tuple, Optional

# Default port for TDX server
TDX_SERVER_PORT = 8446

# Message delimiter
MESSAGE_DELIMITER = b'\n---END---\n'


@dataclass
class CommandRequest:
    """Request to TDX server."""
    command: str
    asp_id: str
    controller_id: str
    request_id: str
    timestamp: float
    
    def to_json(self) -> str:
        return json.dumps(asdict(self))


@dataclass
class CommandResponse:
    """Response from TDX server."""
    request_id: str
    success: bool
    exit_code: int
    stdout: str
    stderr: str
    execution_time_ms: float
    timestamp: float
    
    @classmethod
    def from_json(cls, json_str: str) -> 'CommandResponse':
        return cls(**json.loads(json_str))


class TDXCommandExecutor:
    """
    Executes commands on TDX VMs via the TDX Runtime Server.
    
    Uses TLS for secure communication with optional mTLS.
    """
    
    def __init__(self, host: str, port: int = TDX_SERVER_PORT,
                 controller_id: str = "sgx-controller",
                 ca_cert: str = None,
                 client_cert: str = None,
                 client_key: str = None,
                 timeout: int = 120):
        self.host = host
        self.port = port
        self.controller_id = controller_id
        self.ca_cert = ca_cert
        self.client_cert = client_cert
        self.client_key = client_key
        self.timeout = timeout
    
    def _create_tls_context(self) -> ssl.SSLContext:
        """Create TLS context for connecting to TDX server."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        
        # Load CA cert for server verification
        if self.ca_cert:
            context.load_verify_locations(self.ca_cert)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        
        # Load client cert for mTLS
        if self.client_cert and self.client_key:
            context.load_cert_chain(self.client_cert, self.client_key)
        
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context
    
    def execute(self, command: str, asp_id: str) -> Tuple[bool, int, str, str, float]:
        """
        Execute a command on the TDX VM.
        
        Args:
            command: Command to execute
            asp_id: ASP who authorized this command
            
        Returns:
            (success, exit_code, stdout, stderr, execution_time_ms)
        """
        request = CommandRequest(
            command=command,
            asp_id=asp_id,
            controller_id=self.controller_id,
            request_id=str(uuid.uuid4()),
            timestamp=time.time()
        )
        
        try:
            # Create connection
            tls_context = self._create_tls_context()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            tls_sock = tls_context.wrap_socket(sock, server_hostname=self.host)
            tls_sock.connect((self.host, self.port))
            
            try:
                # Send request
                self._send_message(tls_sock, request.to_json())
                
                # Receive response
                response_json = self._receive_message(tls_sock)
                response = CommandResponse.from_json(response_json)
                
                return (
                    response.success,
                    response.exit_code,
                    response.stdout,
                    response.stderr,
                    response.execution_time_ms
                )
            finally:
                tls_sock.close()
                
        except socket.timeout:
            return False, -1, "", "Connection to TDX server timed out", 0.0
        except ConnectionRefusedError:
            return False, -1, "", f"TDX server not running on {self.host}:{self.port}", 0.0
        except ssl.SSLError as e:
            return False, -1, "", f"TLS error: {str(e)}", 0.0
        except Exception as e:
            return False, -1, "", f"Error: {str(e)}", 0.0
    
    def _send_message(self, sock, message: str):
        """Send a framed message."""
        data = message.encode('utf-8') + MESSAGE_DELIMITER
        sock.sendall(data)
    
    def _receive_message(self, sock) -> str:
        """Receive a framed message."""
        buffer = b""
        while MESSAGE_DELIMITER not in buffer:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buffer += chunk
            if len(buffer) > 1000000:
                raise RuntimeError("Message too large")
        
        if MESSAGE_DELIMITER in buffer:
            message, _ = buffer.split(MESSAGE_DELIMITER, 1)
            return message.decode('utf-8')
        
        raise RuntimeError("Incomplete message received")
    
    def test_connection(self) -> Tuple[bool, str]:
        """Test connectivity to TDX server."""
        success, exit_code, stdout, stderr, _ = self.execute("echo 'connection_test'", "test")
        if success and "connection_test" in stdout:
            return True, None
        return False, stderr or "Connection test failed"
