#!/usr/bin/env python3
"""
SGX Gateway Server

Main server running inside SGX enclave that:
1. Receives signed commands from ASPs
2. Verifies signatures using stored public keys
3. Executes commands on TDX VMs via SSH
4. Logs all operations with cryptographic signatures

Usage:
    python3 gateway_server.py [options]
    
    Options:
        --port PORT         Gateway port (default: 8445)
        --cert CERT_FILE    TLS certificate
        --key KEY_FILE      TLS private key
        --ca-cert CA_FILE   CA certificate for mTLS
        --registry FILE     ASP registry JSON file
        --ssh-key FILE      SSH private key for TDX access
        --log-dir DIR       Directory for audit logs
"""

import sys
import os
import socket
import ssl
import argparse
import json
import time
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.protocol import (
    SignedCommand, CommandResult, GatewayRequest, GatewayResponse,
    ASPInfo, GATEWAY_PORT, PROTOCOL_VERSION,
    create_tls_context_server, send_message, receive_message
)
from common.crypto import verify_signature, load_public_key_from_file
from command_executor import CommandExecutor, SSHConfig
from audit_logger import AuditLogger
from common.transition_log import TransitionLogManager


class SGXGatewayServer:
    """
    SGX Gateway Server for secure command execution.
    
    Runs inside an SGX enclave and acts as the sole access point
    to TDX VMs for runtime updates.
    """
    
    def __init__(self, port: int, cert_file: str, key_file: str,
                 ca_cert_file: str, registry_file: str,
                 ssh_key_file: str, log_dir: str,
                 signing_key_file: str = None,
                 controller_id: str = "sgx-controller-1"):
        
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.ca_cert_file = ca_cert_file
        self.registry_file = registry_file
        self.ssh_key_file = ssh_key_file
        self.log_dir = log_dir
        self.signing_key_file = signing_key_file
        
        self.running = False
        self.asp_registry = {}  # asp_id -> ASPInfo
        self.used_nonces = set()  # For replay protection
        
        # Statistics
        self.stats = {
            "requests": 0,
            "executed": 0,
            "rejected_auth": 0,
            "rejected_policy": 0,
            "errors": 0,
            "start_time": None
        }
        
        # Initialize components
        self._load_asp_registry()
        self.audit_logger = AuditLogger(log_dir, signing_key_file)
        
        # Initialize hash-chained transition log for tracking CVM state changes
        transition_log_dir = os.path.join(log_dir, "transitions")
        self.transition_log_manager = TransitionLogManager(
            storage_dir=transition_log_dir,
            controller_id=controller_id
        )
        self.controller_id = controller_id
        print(f"  Transition log initialized: {transition_log_dir}")
    
    def _load_asp_registry(self):
        """Load ASP registry from JSON file."""
        if not os.path.exists(self.registry_file):
            raise RuntimeError(f"ASP registry not found: {self.registry_file}")
        
        with open(self.registry_file, 'r') as f:
            data = json.load(f)
        
        for asp_data in data.get('asp_registry', []):
            asp = ASPInfo.from_dict(asp_data)
            self.asp_registry[asp.asp_id] = asp
            print(f"  Loaded ASP: {asp.asp_id} ({asp.name})")
        
        print(f"  Total ASPs registered: {len(self.asp_registry)}")
    
    def verify_command(self, cmd: SignedCommand) -> tuple:
        """
        Verify a signed command from an ASP.
        
        Returns:
            (is_valid, error_message)
        """
        # Step 1: Validate command structure
        valid, error = cmd.validate()
        if not valid:
            return False, f"Invalid command: {error}"
        
        # Step 2: Check if ASP is registered
        if cmd.asp_id not in self.asp_registry:
            self.stats["rejected_auth"] += 1
            return False, f"Unknown ASP: {cmd.asp_id}"
        
        asp = self.asp_registry[cmd.asp_id]
        
        # Step 3: Check if ASP is allowed to access this VM
        if cmd.target_vm not in asp.allowed_vms:
            self.stats["rejected_policy"] += 1
            return False, f"ASP {cmd.asp_id} not authorized for VM {cmd.target_vm}"
        
        # Step 4: Check for replay attack
        if cmd.nonce in self.used_nonces:
            self.stats["rejected_auth"] += 1
            return False, "Nonce already used (replay attack?)"
        
        # Step 5: Verify signature
        signable_data = cmd.get_signable_data()
        valid, error = verify_signature(asp.public_key_pem, signable_data, cmd.signature)
        if not valid:
            self.stats["rejected_auth"] += 1
            return False, f"Signature verification failed: {error}"
        
        # Mark nonce as used
        self.used_nonces.add(cmd.nonce)
        
        # Limit nonce cache size
        if len(self.used_nonces) > 10000:
            # Remove old nonces (simple approach - in production use TTL)
            self.used_nonces = set(list(self.used_nonces)[-5000:])
        
        return True, None
    
    def execute_command(self, cmd: SignedCommand) -> CommandResult:
        """
        Execute a verified command on the target TDX VM.
        
        Args:
            cmd: The verified SignedCommand
        
        Returns:
            CommandResult with execution details
        """
        # Create SSH config
        ssh_config = SSHConfig(
            host=cmd.target_vm,
            username="nkoirala",  # Configure as needed
            private_key_path=self.ssh_key_file
        )
        
        # Execute
        executor = CommandExecutor(ssh_config)
        
        try:
            connected, error = executor.connect()
            if not connected:
                return CommandResult(
                    success=False,
                    exit_code=-1,
                    stdout="",
                    stderr=f"SSH connection failed: {error}",
                    execution_time_ms=0.0
                )
            
            exit_code, stdout, stderr, exec_time = executor.execute(cmd.command)
            
            return CommandResult(
                success=(exit_code == 0),
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                execution_time_ms=exec_time
            )
            
        finally:
            executor.disconnect()
    
    def handle_request(self, request_json: str) -> str:
        """Handle an incoming gateway request."""
        self.stats["requests"] += 1
        
        try:
            request = GatewayRequest.from_json(request_json)
            
            if request.request_type == "execute_command":
                return self._handle_execute_command(request.payload)
            elif request.request_type == "get_logs":
                return self._handle_get_logs(request.payload)
            elif request.request_type == "get_stats":
                return self._handle_get_stats()
            else:
                return GatewayResponse(
                    success=False,
                    message=f"Unknown request type: {request.request_type}"
                ).to_json()
                
        except Exception as e:
            self.stats["errors"] += 1
            return GatewayResponse(
                success=False,
                message=f"Error processing request: {str(e)}"
            ).to_json()
    
    def _handle_execute_command(self, payload: str) -> str:
        """Handle execute_command request."""
        try:
            cmd = SignedCommand.from_json(payload)
        except Exception as e:
            return GatewayResponse(
                success=False,
                message=f"Invalid command format: {str(e)}"
            ).to_json()
        
        # Verify command
        valid, error = self.verify_command(cmd)
        if not valid:
            print(f"  ✗ Command rejected: {error}")
            return GatewayResponse(
                success=False,
                message=f"Command rejected: {error}"
            ).to_json()
        
        print(f"  ✓ Command verified for ASP {cmd.asp_id}")
        print(f"    Target: {cmd.target_vm}")
        print(f"    Command: {cmd.command[:50]}...")
        
        # Execute command
        result = self.execute_command(cmd)
        self.stats["executed"] += 1
        
        # Log the execution in audit logger
        log_entry = self.audit_logger.log_command(
            asp_id=cmd.asp_id,
            target_vm=cmd.target_vm,
            command=cmd.command,
            command_timestamp=cmd.timestamp,
            result=result
        )
        
        # Record in hash-chained transition log
        transition_entry = self.transition_log_manager.record_transition(
            cvm_id=cmd.target_vm,
            command=cmd.command,
            asp_id=cmd.asp_id,
            asp_signature=cmd.signature,
            result_success=result.success,
            result_exit_code=result.exit_code
        )
        
        print(f"  ✓ Executed (exit_code={result.exit_code})")
        print(f"    Log ID: {log_entry.log_id}")
        print(f"    Transition seq: {transition_entry.seq}, chain head: {transition_entry.entry_hash[:16]}...")
        
        return GatewayResponse(
            success=True,
            message="Command executed",
            data=result.to_json()
        ).to_json()
    
    def _handle_get_logs(self, payload: str) -> str:
        """Handle get_logs request."""
        try:
            filters = json.loads(payload) if payload else {}
        except:
            filters = {}
        
        entries = self.audit_logger.get_logs(**filters)
        
        return GatewayResponse(
            success=True,
            message=f"Retrieved {len(entries)} log entries",
            data=json.dumps([json.loads(e.to_json()) for e in entries])
        ).to_json()
    
    def _handle_get_stats(self) -> str:
        """Handle get_stats request."""
        stats = {
            **self.stats,
            "log_stats": self.audit_logger.get_log_stats(),
            "registered_asps": len(self.asp_registry)
        }
        
        return GatewayResponse(
            success=True,
            message="Statistics retrieved",
            data=json.dumps(stats)
        ).to_json()
    
    def handle_client(self, client_socket: ssl.SSLSocket, addr: tuple):
        """Handle a single client connection."""
        req_num = self.stats["requests"] + 1
        print(f"\n[{req_num}] Connection from {addr[0]}:{addr[1]}")
        
        try:
            # Receive request
            request_json = receive_message(client_socket)
            
            # Process request
            response_json = self.handle_request(request_json)
            
            # Send response
            send_message(client_socket, response_json)
            
        except Exception as e:
            print(f"  ✗ Error: {e}")
            try:
                error_response = GatewayResponse(
                    success=False,
                    message=str(e)
                )
                send_message(client_socket, error_response.to_json())
            except:
                pass
        
        finally:
            client_socket.close()
    
    def run(self):
        """Start the gateway server."""
        # Create TLS context with mTLS
        tls_context = create_tls_context_server(
            self.cert_file,
            self.key_file,
            ca_cert_file=self.ca_cert_file,
            require_client_cert=True
        )
        
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
        print("=" * 70)
        print("SGX Gateway Server - Secure Runtime Update System")
        print("=" * 70)
        print(f"Protocol Version: {PROTOCOL_VERSION}")
        print(f"Port:             {self.port}")
        print(f"ASPs Registered:  {len(self.asp_registry)}")
        print(f"Log Directory:    {self.log_dir}")
        print(f"mTLS:             Enabled")
        print(f"Started:          {self.stats['start_time']}")
        print("=" * 70)
        print("\n[SECURE] Waiting for signed commands from ASPs...\n")
    
    def _print_stats(self):
        """Print shutdown statistics."""
        print("\n" + "=" * 70)
        print("Gateway Statistics")
        print("=" * 70)
        print(f"Total requests:     {self.stats['requests']}")
        print(f"Commands executed:  {self.stats['executed']}")
        print(f"Rejected (auth):    {self.stats['rejected_auth']}")
        print(f"Rejected (policy):  {self.stats['rejected_policy']}")
        print(f"Errors:             {self.stats['errors']}")
        print("=" * 70)


def check_enclave_environment():
    """Check if running inside SGX enclave."""
    is_gramine = os.path.exists("/dev/attestation/quote")
    if is_gramine:
        print("✓ Running inside Gramine SGX enclave")
    else:
        print("⚠ Not running inside SGX enclave (development mode)")
    return is_gramine


def main():
    parser = argparse.ArgumentParser(
        description="SGX Gateway Server - Secure Runtime Update System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument("--port", type=int, default=GATEWAY_PORT,
                       help=f"Gateway port (default: {GATEWAY_PORT})")
    parser.add_argument("--cert", default="../certs/server.crt",
                       help="TLS certificate file")
    parser.add_argument("--key", default="../certs/server.key",
                       help="TLS private key file")
    parser.add_argument("--ca-cert", default="../certs/ca.crt",
                       help="CA certificate for mTLS")
    parser.add_argument("--registry", default="../config/asp_registry.json",
                       help="ASP registry JSON file")
    parser.add_argument("--ssh-key", default="../certs/enclave_ssh_key",
                       help="SSH private key for TDX access")
    parser.add_argument("--signing-key", default="../certs/enclave_signing_key.pem",
                       help="Enclave signing key for audit logs")
    parser.add_argument("--log-dir", default="../logs",
                       help="Directory for audit logs")
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("SGX Gateway Server - Startup")
    print("=" * 70)
    
    check_enclave_environment()
    
    # Resolve paths relative to script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    def resolve_path(path):
        if os.path.isabs(path):
            return path
        return os.path.join(script_dir, path)
    
    cert_file = resolve_path(args.cert)
    key_file = resolve_path(args.key)
    ca_cert_file = resolve_path(args.ca_cert)
    registry_file = resolve_path(args.registry)
    ssh_key_file = resolve_path(args.ssh_key)
    signing_key_file = resolve_path(args.signing_key)
    log_dir = resolve_path(args.log_dir)
    
    # Create log directory
    os.makedirs(log_dir, exist_ok=True)
    
    print(f"\nConfiguration:")
    print(f"  Port:         {args.port}")
    print(f"  Registry:     {registry_file}")
    print(f"  SSH Key:      {ssh_key_file}")
    print(f"  Log Dir:      {log_dir}")
    print()
    
    print("Loading ASP registry...")
    
    try:
        server = SGXGatewayServer(
            port=args.port,
            cert_file=cert_file,
            key_file=key_file,
            ca_cert_file=ca_cert_file,
            registry_file=registry_file,
            ssh_key_file=ssh_key_file,
            log_dir=log_dir,
            signing_key_file=signing_key_file
        )
        server.run()
    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
