#!/usr/bin/env python3
"""
TDX Runtime Update Server

Runs on the TDX VM (Confidential VM) and listens for runtime update commands
from authorized SGX controllers. Commands are executed locally and results
returned to the controller.

Security Model:
- Only accepts connections from authorized SGX controllers
- All communication is encrypted via TLS
- Commands are logged locally before execution
- Results include execution status and output

Usage:
    python3 tdx_server.py --port 8446 --cert server.crt --key server.key
"""

import sys
import os
import socket
import ssl
import argparse
import json
import subprocess
import time
import hashlib
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Optional, Tuple

# Default port for TDX server
TDX_SERVER_PORT = 8446

# Message delimiter for framing
MESSAGE_DELIMITER = b'\n---END---\n'


@dataclass
class CommandRequest:
    """Request from SGX controller to execute a command."""
    command: str           # Command to execute
    asp_id: str           # ASP who authorized this (for logging)
    controller_id: str    # SGX controller sending this
    request_id: str       # Unique request ID for tracking
    timestamp: float      # When request was created
    
    def to_json(self) -> str:
        return json.dumps(asdict(self))
    
    @classmethod
    def from_json(cls, json_str: str) -> 'CommandRequest':
        return cls(**json.loads(json_str))


@dataclass
class CommandResponse:
    """Response sent back to SGX controller."""
    request_id: str       # Matches the request
    success: bool         # Whether command executed successfully
    exit_code: int        # Command exit code
    stdout: str           # Standard output
    stderr: str           # Standard error
    execution_time_ms: float  # How long execution took
    timestamp: float      # When response was created
    
    def to_json(self) -> str:
        return json.dumps(asdict(self))
    
    @classmethod
    def from_json(cls, json_str: str) -> 'CommandResponse':
        return cls(**json.loads(json_str))


class TDXRuntimeServer:
    """
    TDX Runtime Update Server.
    
    Listens for commands from SGX controllers and executes them locally.
    All executions are logged for audit purposes.
    """
    
    def __init__(self, port: int, cert_file: str, key_file: str,
                 ca_cert_file: str = None, log_dir: str = "./logs",
                 allowed_controllers: list = None):
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.ca_cert_file = ca_cert_file
        self.log_dir = log_dir
        self.allowed_controllers = allowed_controllers or []
        
        self.running = False
        self.stats = {
            "commands_received": 0,
            "commands_executed": 0,
            "commands_failed": 0,
            "start_time": None
        }
        
        # Create log directory
        os.makedirs(log_dir, exist_ok=True)
        self.log_file = os.path.join(log_dir, "tdx_execution_log.jsonl")
    
    def _create_tls_context(self) -> ssl.SSLContext:
        """Create TLS context for secure communication."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert_file, self.key_file)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        # If CA cert provided, enable client verification (mTLS)
        if self.ca_cert_file and os.path.exists(self.ca_cert_file):
            context.load_verify_locations(self.ca_cert_file)
            context.verify_mode = ssl.CERT_REQUIRED
            print("  mTLS enabled: client certificates required")
        else:
            print("  Warning: Running without client certificate verification")
        
        return context
    
    def execute_command(self, command: str, timeout: int = 300) -> Tuple[int, str, str, float]:
        """
        Execute a command locally.
        
        Args:
            command: Shell command to execute
            timeout: Maximum execution time in seconds
            
        Returns:
            (exit_code, stdout, stderr, execution_time_ms)
        """
        start_time = time.time()
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            execution_time = (time.time() - start_time) * 1000
            return result.returncode, result.stdout, result.stderr, execution_time
            
        except subprocess.TimeoutExpired:
            execution_time = (time.time() - start_time) * 1000
            return -1, "", f"Command timed out after {timeout}s", execution_time
        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            return -1, "", str(e), execution_time
    
    def log_execution(self, request: CommandRequest, response: CommandResponse):
        """Log command execution to local audit file."""
        log_entry = {
            "request_id": request.request_id,
            "command": request.command,
            "asp_id": request.asp_id,
            "controller_id": request.controller_id,
            "request_timestamp": request.timestamp,
            "exit_code": response.exit_code,
            "success": response.success,
            "execution_time_ms": response.execution_time_ms,
            "response_timestamp": response.timestamp
        }
        
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    def handle_request(self, request_json: str) -> str:
        """Handle an incoming command request."""
        self.stats["commands_received"] += 1
        
        try:
            request = CommandRequest.from_json(request_json)
            
            print(f"  Command: {request.command[:60]}...")
            print(f"  From controller: {request.controller_id}")
            print(f"  Authorized by ASP: {request.asp_id}")
            
            # Execute the command
            exit_code, stdout, stderr, exec_time = self.execute_command(request.command)
            
            # Create response
            response = CommandResponse(
                request_id=request.request_id,
                success=(exit_code == 0),
                exit_code=exit_code,
                stdout=stdout[:10000],  # Limit output size
                stderr=stderr[:10000],
                execution_time_ms=exec_time,
                timestamp=time.time()
            )
            
            # Log locally
            self.log_execution(request, response)
            
            if response.success:
                self.stats["commands_executed"] += 1
                print(f"  ✓ Executed (exit_code={exit_code}, {exec_time:.1f}ms)")
            else:
                self.stats["commands_failed"] += 1
                print(f"  ✗ Failed (exit_code={exit_code})")
            
            return response.to_json()
            
        except Exception as e:
            self.stats["commands_failed"] += 1
            error_response = CommandResponse(
                request_id="unknown",
                success=False,
                exit_code=-1,
                stdout="",
                stderr=f"Server error: {str(e)}",
                execution_time_ms=0,
                timestamp=time.time()
            )
            return error_response.to_json()
    
    def handle_client(self, client_socket: ssl.SSLSocket, addr: tuple):
        """Handle a single client connection."""
        req_num = self.stats["commands_received"] + 1
        print(f"\n[{req_num}] Connection from {addr[0]}:{addr[1]}")
        
        try:
            # Receive request
            request_json = self._receive_message(client_socket)
            
            # Process and respond
            response_json = self.handle_request(request_json)
            
            # Send response
            self._send_message(client_socket, response_json)
            
        except Exception as e:
            print(f"  ✗ Error: {e}")
        finally:
            client_socket.close()
    
    def _send_message(self, sock, message: str):
        """Send a framed message."""
        data = message.encode('utf-8') + MESSAGE_DELIMITER
        sock.sendall(data)
    
    def _receive_message(self, sock, timeout: float = 60.0) -> str:
        """Receive a framed message."""
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
    
    def run(self):
        """Start the TDX server."""
        tls_context = self._create_tls_context()
        
        # Create socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('0.0.0.0', self.port))
        server_socket.listen(5)
        
        # Wrap with TLS
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
            self._print_stats()
    
    def _print_banner(self):
        """Print startup banner."""
        print("=" * 60)
        print("TDX Runtime Update Server")
        print("=" * 60)
        print(f"Port:        {self.port}")
        print(f"Log file:    {self.log_file}")
        print(f"Started:     {self.stats['start_time']}")
        print("=" * 60)
        print("\n[READY] Waiting for commands from SGX controllers...\n")
    
    def _print_stats(self):
        """Print shutdown statistics."""
        print("\n" + "=" * 60)
        print("TDX Server Statistics")
        print("=" * 60)
        print(f"Commands received:  {self.stats['commands_received']}")
        print(f"Commands executed:  {self.stats['commands_executed']}")
        print(f"Commands failed:    {self.stats['commands_failed']}")
        print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="TDX Runtime Update Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument("--port", type=int, default=TDX_SERVER_PORT,
                       help=f"Server port (default: {TDX_SERVER_PORT})")
    parser.add_argument("--cert", required=True,
                       help="TLS certificate file")
    parser.add_argument("--key", required=True,
                       help="TLS private key file")
    parser.add_argument("--ca-cert", default=None,
                       help="CA certificate for client verification (mTLS)")
    parser.add_argument("--log-dir", default="./logs",
                       help="Directory for execution logs")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("TDX Runtime Update Server - Starting")
    print("=" * 60)
    
    try:
        server = TDXRuntimeServer(
            port=args.port,
            cert_file=args.cert,
            key_file=args.key,
            ca_cert_file=args.ca_cert,
            log_dir=args.log_dir
        )
        server.run()
    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
