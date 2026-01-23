#!/usr/bin/env python3
"""
ASP Client

Command-line tool for Application Service Providers (ASPs) to:
1. Generate key pairs for signing
2. Sign and send commands to the SGX gateway
3. Retrieve audit logs

Usage:
    # Generate key pair
    python3 asp_client.py generate-keys --asp-id my-asp
    
    # Execute a command
    python3 asp_client.py execute --gateway HOST --command "apt-get update" --target-vm IP
    
    # Get logs
    python3 asp_client.py get-logs --gateway HOST
"""

import sys
import os
import socket
import json
import argparse
import time

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.protocol import (
    SignedCommand, GatewayRequest, GatewayResponse,
    generate_nonce, GATEWAY_PORT,
    create_tls_context_client, send_message, receive_message
)
from common.crypto import sign_data, generate_key_pair, load_private_key_from_file


class ASPClient:
    """Client for ASPs to interact with SGX Gateway."""
    
    def __init__(self, asp_id: str, private_key_path: str = None,
                 gateway_host: str = None, gateway_port: int = GATEWAY_PORT,
                 ca_cert: str = None, client_cert: str = None, client_key: str = None):
        
        self.asp_id = asp_id
        self.private_key_path = private_key_path
        self.gateway_host = gateway_host
        self.gateway_port = gateway_port
        self.ca_cert = ca_cert
        self.client_cert = client_cert
        self.client_key = client_key
        
        self._private_key = None
        if private_key_path and os.path.exists(private_key_path):
            key, error = load_private_key_from_file(private_key_path)
            if error:
                print(f"Warning: Could not load private key: {error}")
            else:
                self._private_key = key
    
    def create_signed_command(self, command: str, target_vm: str) -> SignedCommand:
        """
        Create a signed command payload.
        
        Args:
            command: The command to execute (e.g., "apt-get update")
            target_vm: Target TDX VM IP/hostname
        
        Returns:
            SignedCommand with signature
        """
        if not self._private_key:
            raise RuntimeError("Private key not loaded")
        
        # Create command structure
        cmd = SignedCommand(
            asp_id=self.asp_id,
            target_vm=target_vm,
            command=command,
            timestamp=time.time(),
            nonce=generate_nonce()
        )
        
        # Sign the command
        signable_data = cmd.get_signable_data()
        signature, error = sign_data(self._private_key, signable_data)
        
        if error:
            raise RuntimeError(f"Signing failed: {error}")
        
        cmd.signature = signature
        return cmd
    
    def send_command(self, cmd: SignedCommand) -> dict:
        """
        Send a signed command to the SGX gateway.
        
        Returns:
            Response dictionary
        """
        request = GatewayRequest(
            request_type="execute_command",
            payload=cmd.to_json()
        )
        
        response_json = self._send_request(request)
        response = GatewayResponse.from_json(response_json)
        
        result = {
            "success": response.success,
            "message": response.message
        }
        
        if response.data:
            result["result"] = json.loads(response.data)
        
        return result
    
    def get_logs(self, target_vm: str = None) -> list:
        """Retrieve audit logs from the gateway."""
        filters = {}
        if target_vm:
            filters["target_vm"] = target_vm
        
        request = GatewayRequest(
            request_type="get_logs",
            payload=json.dumps(filters)
        )
        
        response_json = self._send_request(request)
        response = GatewayResponse.from_json(response_json)
        
        if response.success and response.data:
            return json.loads(response.data)
        return []
    
    def get_stats(self) -> dict:
        """Get gateway statistics."""
        request = GatewayRequest(
            request_type="get_stats",
            payload=""
        )
        
        response_json = self._send_request(request)
        response = GatewayResponse.from_json(response_json)
        
        if response.success and response.data:
            return json.loads(response.data)
        return {}
    
    def _send_request(self, request: GatewayRequest) -> str:
        """Send request to gateway and return response."""
        if not self.gateway_host:
            raise RuntimeError("Gateway host not configured")
        
        # Create TLS context
        tls_context = create_tls_context_client(
            ca_cert_file=self.ca_cert,
            client_cert_file=self.client_cert,
            client_key_file=self.client_key,
            verify=bool(self.ca_cert)
        )
        
        # Connect
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(120)  # Increased to allow for SSH operations
        
        tls_sock = tls_context.wrap_socket(sock, server_hostname=self.gateway_host)
        tls_sock.connect((self.gateway_host, self.gateway_port))
        
        try:
            # Send request
            send_message(tls_sock, request.to_json())
            
            # Receive response
            response = receive_message(tls_sock)
            return response
            
        finally:
            tls_sock.close()


def cmd_generate_keys(args):
    """Generate ASP key pair."""
    print(f"Generating key pair for ASP: {args.asp_id}")
    
    private_key, public_key, error = generate_key_pair(
        key_type=args.key_type,
        key_size=args.key_size
    )
    
    if error:
        print(f"Error: {error}")
        return 1
    
    # Create output directory
    output_dir = args.output_dir or "."
    os.makedirs(output_dir, exist_ok=True)
    
    # Save keys
    private_key_file = os.path.join(output_dir, f"{args.asp_id}_private.pem")
    public_key_file = os.path.join(output_dir, f"{args.asp_id}_public.pem")
    
    with open(private_key_file, 'w') as f:
        f.write(private_key)
    os.chmod(private_key_file, 0o600)
    
    with open(public_key_file, 'w') as f:
        f.write(public_key)
    
    print(f"\nKeys generated successfully:")
    print(f"  Private key: {private_key_file} (keep secure!)")
    print(f"  Public key:  {public_key_file} (share with enclave admin)")
    print(f"\nAdd the public key to the ASP registry in the SGX gateway.")
    
    return 0


def cmd_execute(args):
    """Execute a command on TDX VM."""
    print(f"Executing command on {args.target_vm}...")
    print(f"  Command: {args.command}")
    
    client = ASPClient(
        asp_id=args.asp_id,
        private_key_path=args.private_key,
        gateway_host=args.gateway,
        gateway_port=args.port,
        ca_cert=args.ca_cert,
        client_cert=args.client_cert,
        client_key=args.client_key
    )
    
    try:
        # Create signed command
        cmd = client.create_signed_command(args.command, args.target_vm)
        print(f"  Nonce: {cmd.nonce[:16]}...")
        print(f"  Signed: ✓")
        
        # Send to gateway
        print(f"\nSending to gateway {args.gateway}:{args.port}...")
        result = client.send_command(cmd)
        
        print("\n" + "=" * 60)
        if result["success"]:
            print("✓ Command executed successfully")
            if "result" in result:
                r = result["result"]
                print(f"  Exit code: {r['exit_code']}")
                print(f"  Execution time: {r['execution_time_ms']:.1f}ms")
                if r['stdout']:
                    print(f"\nSTDOUT:\n{r['stdout']}")
                if r['stderr']:
                    print(f"\nSTDERR:\n{r['stderr']}")
        else:
            print(f"✗ Command failed: {result['message']}")
            return 1
        
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0


def cmd_get_logs(args):
    """Retrieve audit logs."""
    client = ASPClient(
        asp_id=args.asp_id or "viewer",
        gateway_host=args.gateway,
        gateway_port=args.port,
        ca_cert=args.ca_cert,
        client_cert=args.client_cert,
        client_key=args.client_key
    )
    
    try:
        logs = client.get_logs(target_vm=args.target_vm)
        
        print(f"Retrieved {len(logs)} log entries:\n")
        for log in logs:
            print(f"  [{log['log_id']}]")
            print(f"    ASP: {log['asp_id']}")
            print(f"    VM: {log['target_vm']}")
            print(f"    Command: {log['command'][:50]}...")
            print(f"    Success: {log['result']['success']}")
            print(f"    Signed: {'✓' if log.get('enclave_signature') else '✗'}")
            print()
        
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="ASP Client - Execute commands on TDX VMs through SGX Gateway"
    )
    
    subparsers = parser.add_subparsers(dest="subcommand", help="Commands")
    
    # generate-keys command
    gen_parser = subparsers.add_parser("generate-keys", help="Generate ASP key pair")
    gen_parser.add_argument("--asp-id", required=True, help="ASP identifier")
    gen_parser.add_argument("--key-type", default="rsa", choices=["rsa", "ec"],
                           help="Key type (default: rsa)")
    gen_parser.add_argument("--key-size", type=int, default=2048,
                           help="Key size for RSA (default: 2048)")
    gen_parser.add_argument("--output-dir", help="Output directory for keys")
    
    # execute command
    exec_parser = subparsers.add_parser("execute", help="Execute command on TDX VM")
    exec_parser.add_argument("--asp-id", required=True, help="ASP identifier")
    exec_parser.add_argument("--private-key", required=True, help="Path to ASP private key")
    exec_parser.add_argument("--gateway", required=True, help="Gateway hostname/IP")
    exec_parser.add_argument("--port", type=int, default=GATEWAY_PORT, help="Gateway port")
    exec_parser.add_argument("--target-vm", required=True, help="Target TDX VM IP")
    exec_parser.add_argument("--command", required=True, help="Command to execute")
    exec_parser.add_argument("--ca-cert", help="CA certificate for TLS")
    exec_parser.add_argument("--client-cert", help="Client certificate for mTLS")
    exec_parser.add_argument("--client-key", help="Client key for mTLS")
    
    # get-logs command
    logs_parser = subparsers.add_parser("get-logs", help="Retrieve audit logs")
    logs_parser.add_argument("--asp-id", help="ASP identifier (optional)")
    logs_parser.add_argument("--gateway", required=True, help="Gateway hostname/IP")
    logs_parser.add_argument("--port", type=int, default=GATEWAY_PORT, help="Gateway port")
    logs_parser.add_argument("--target-vm", help="Filter by target VM")
    logs_parser.add_argument("--ca-cert", help="CA certificate for TLS")
    logs_parser.add_argument("--client-cert", help="Client certificate for mTLS")
    logs_parser.add_argument("--client-key", help="Client key for mTLS")
    
    args = parser.parse_args()
    
    if args.subcommand == "generate-keys":
        sys.exit(cmd_generate_keys(args))
    elif args.subcommand == "execute":
        sys.exit(cmd_execute(args))
    elif args.subcommand == "get-logs":
        sys.exit(cmd_get_logs(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
