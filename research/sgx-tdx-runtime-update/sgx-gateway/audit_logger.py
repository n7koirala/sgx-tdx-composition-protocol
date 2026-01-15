#!/usr/bin/env python3
"""
Audit Logger

Records all command executions with cryptographic signatures.
Logs are stored in sealed enclave storage for later verification.
"""

import os
import json
import time
from datetime import datetime
from typing import List, Optional, Tuple
from dataclasses import asdict

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.protocol import AuditLogEntry, CommandResult, generate_log_id
from common.crypto import sign_data, load_private_key_from_file, compute_hash


class AuditLogger:
    """
    Audit logger for command execution.
    
    All logs are signed with the enclave's signing key and stored
    in a sealed log file that can be verified by end users.
    """
    
    def __init__(self, log_dir: str, signing_key_path: str = None):
        """
        Initialize the audit logger.
        
        Args:
            log_dir: Directory to store audit logs
            signing_key_path: Path to enclave's private key for signing
        """
        self.log_dir = log_dir
        self.signing_key_path = signing_key_path
        self._signing_key = None
        
        # Create log directory if it doesn't exist
        os.makedirs(log_dir, exist_ok=True)
        
        # Load signing key if provided
        if signing_key_path and os.path.exists(signing_key_path):
            key, error = load_private_key_from_file(signing_key_path)
            if error:
                print(f"Warning: Could not load signing key: {error}")
            else:
                self._signing_key = key
    
    def log_command(self, asp_id: str, target_vm: str, command: str,
                    command_timestamp: float, result: CommandResult) -> AuditLogEntry:
        """
        Create and store an audit log entry.
        
        Args:
            asp_id: ID of the ASP who issued the command
            target_vm: Target VM IP/hostname
            command: The command that was executed
            command_timestamp: When the ASP created the command
            result: The execution result
        
        Returns:
            The created AuditLogEntry
        """
        # Create log entry
        entry = AuditLogEntry(
            log_id=generate_log_id(),
            asp_id=asp_id,
            target_vm=target_vm,
            command=command,
            command_timestamp=command_timestamp,
            execution_timestamp=time.time(),
            result=result
        )
        
        # Sign the entry
        if self._signing_key:
            signable_data = entry.get_signable_data()
            signature, error = sign_data(self._signing_key, signable_data)
            if signature:
                entry.enclave_signature = signature
            else:
                print(f"Warning: Could not sign log entry: {error}")
        
        # Store the entry
        self._store_entry(entry)
        
        return entry
    
    def _store_entry(self, entry: AuditLogEntry):
        """Store a log entry to the log file."""
        log_file = os.path.join(self.log_dir, "audit_log.jsonl")
        
        with open(log_file, 'a') as f:
            f.write(entry.to_json() + '\n')
    
    def get_logs(self, asp_id: str = None, target_vm: str = None,
                 start_time: float = None, end_time: float = None) -> List[AuditLogEntry]:
        """
        Retrieve audit logs with optional filtering.
        
        Args:
            asp_id: Filter by ASP ID
            target_vm: Filter by target VM
            start_time: Filter by execution time >= start_time
            end_time: Filter by execution time <= end_time
        
        Returns:
            List of matching AuditLogEntry objects
        """
        log_file = os.path.join(self.log_dir, "audit_log.jsonl")
        
        if not os.path.exists(log_file):
            return []
        
        entries = []
        with open(log_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    entry = AuditLogEntry.from_json(line)
                    
                    # Apply filters
                    if asp_id and entry.asp_id != asp_id:
                        continue
                    if target_vm and entry.target_vm != target_vm:
                        continue
                    if start_time and entry.execution_timestamp < start_time:
                        continue
                    if end_time and entry.execution_timestamp > end_time:
                        continue
                    
                    entries.append(entry)
                    
                except Exception as e:
                    print(f"Warning: Could not parse log entry: {e}")
        
        return entries
    
    def verify_log(self, entry: AuditLogEntry, public_key_pem: str) -> Tuple[bool, str]:
        """
        Verify the signature on a log entry.
        
        Args:
            entry: The log entry to verify
            public_key_pem: Enclave's public key for verification
        
        Returns:
            (is_valid, error_message)
        """
        from common.crypto import verify_signature
        
        if not entry.enclave_signature:
            return False, "Log entry is not signed"
        
        signable_data = entry.get_signable_data()
        return verify_signature(public_key_pem, signable_data, entry.enclave_signature)
    
    def export_logs(self, output_file: str, asp_id: str = None) -> int:
        """
        Export logs to a file for external verification.
        
        Args:
            output_file: Output file path
            asp_id: Optional filter by ASP ID
        
        Returns:
            Number of entries exported
        """
        entries = self.get_logs(asp_id=asp_id)
        
        with open(output_file, 'w') as f:
            export_data = {
                "export_time": datetime.utcnow().isoformat(),
                "total_entries": len(entries),
                "entries": [json.loads(e.to_json()) for e in entries]
            }
            json.dump(export_data, f, indent=2)
        
        return len(entries)
    
    def get_log_stats(self) -> dict:
        """Get statistics about the audit logs."""
        entries = self.get_logs()
        
        if not entries:
            return {"total_entries": 0}
        
        asp_counts = {}
        vm_counts = {}
        success_count = 0
        
        for entry in entries:
            asp_counts[entry.asp_id] = asp_counts.get(entry.asp_id, 0) + 1
            vm_counts[entry.target_vm] = vm_counts.get(entry.target_vm, 0) + 1
            if entry.result.success:
                success_count += 1
        
        return {
            "total_entries": len(entries),
            "success_count": success_count,
            "failure_count": len(entries) - success_count,
            "asps": asp_counts,
            "vms": vm_counts,
            "earliest": min(e.execution_timestamp for e in entries),
            "latest": max(e.execution_timestamp for e in entries)
        }
