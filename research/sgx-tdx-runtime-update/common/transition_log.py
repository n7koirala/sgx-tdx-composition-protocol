#!/usr/bin/env python3
"""
Hash-Chained Transition Log

A cryptographically-linked append-only log for tracking all runtime updates
made to Confidential VMs (CVMs). Each entry includes the hash of the previous
entry, creating a tamper-evident chain that can be verified and synchronized
across multiple SGX controllers.

Key Properties:
- Tamper-evident: Modifying any entry breaks the hash chain
- Append-only: New entries link to previous, preventing reordering
- Syncable: Controllers can efficiently sync by comparing head hashes
- Auditable: Full history of authorized transitions is preserved
"""

import hashlib
import json
import time
import os
from dataclasses import dataclass, asdict
from typing import List, Optional, Tuple
from pathlib import Path


@dataclass
class TransitionEntry:
    """
    A single entry in the hash-chained transition log.
    
    Each entry represents one command executed on a CVM, with cryptographic
    linking to the previous entry via prev_hash.
    """
    seq: int                    # Monotonic sequence number (0-indexed)
    prev_hash: str              # Hex hash of previous entry (64 zeros for genesis)
    cvm_id: str                 # Target CVM identifier (e.g., IP or VM ID)
    command: str                # Command that was executed
    command_hash: str           # SHA-256 hash of command (for privacy if needed)
    asp_id: str                 # ASP who authorized this command
    asp_signature: str          # ASP's signature over the command
    controller_id: str          # Which SGX controller executed this
    timestamp: float            # Unix timestamp of execution
    result_success: bool        # Whether command succeeded
    result_exit_code: int       # Exit code from command
    result_rtmr: str            # TDX RTMR after execution (if available)
    entry_hash: str = ""        # SHA-256 hash of this entry (computed)
    
    def compute_hash(self) -> str:
        """Compute SHA-256 hash of this entry (excluding entry_hash field)."""
        data = {
            "seq": self.seq,
            "prev_hash": self.prev_hash,
            "cvm_id": self.cvm_id,
            "command": self.command,
            "command_hash": self.command_hash,
            "asp_id": self.asp_id,
            "asp_signature": self.asp_signature,
            "controller_id": self.controller_id,
            "timestamp": self.timestamp,
            "result_success": self.result_success,
            "result_exit_code": self.result_exit_code,
            "result_rtmr": self.result_rtmr
        }
        json_str = json.dumps(data, sort_keys=True)
        return hashlib.sha256(json_str.encode('utf-8')).hexdigest()
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: dict) -> 'TransitionEntry':
        return cls(**data)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_json(cls, json_str: str) -> 'TransitionEntry':
        return cls.from_dict(json.loads(json_str))


class HashChainedLog:
    """
    Hash-chained append-only log for CVM transition tracking.
    
    Maintains a separate log per CVM, with each entry cryptographically
    linked to its predecessor. Supports:
    - Append new entries with chain integrity verification
    - Verify entire chain for auditing
    - Sync with other controllers via head hash comparison
    - Persist to and load from disk
    """
    
    GENESIS_HASH = "0" * 64  # SHA-256 of empty/genesis state
    
    def __init__(self, cvm_id: str, storage_dir: str, controller_id: str):
        """
        Initialize log for a specific CVM.
        
        Args:
            cvm_id: Identifier for the CVM this log tracks
            storage_dir: Directory to store log files
            controller_id: ID of this SGX controller
        """
        self.cvm_id = cvm_id
        self.storage_dir = Path(storage_dir)
        self.controller_id = controller_id
        self.entries: List[TransitionEntry] = []
        self.head_hash: str = self.GENESIS_HASH
        
        # Create storage directory if needed
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        # Load existing log if present
        self._load_from_disk()
    
    @property
    def log_file(self) -> Path:
        """Path to the log file for this CVM."""
        safe_cvm_id = self.cvm_id.replace("/", "_").replace(".", "_")
        return self.storage_dir / f"transition_log_{safe_cvm_id}.jsonl"
    
    def append(self, command: str, asp_id: str, asp_signature: str,
               result_success: bool, result_exit_code: int,
               result_rtmr: str = "") -> TransitionEntry:
        """
        Append a new transition entry to the log.
        
        Args:
            command: The command that was executed
            asp_id: ASP who authorized the command
            asp_signature: ASP's signature over the command
            result_success: Whether command succeeded
            result_exit_code: Command exit code
            result_rtmr: TDX RTMR after execution (optional)
        
        Returns:
            The newly created TransitionEntry
        """
        entry = TransitionEntry(
            seq=len(self.entries),
            prev_hash=self.head_hash,
            cvm_id=self.cvm_id,
            command=command,
            command_hash=hashlib.sha256(command.encode()).hexdigest(),
            asp_id=asp_id,
            asp_signature=asp_signature,
            controller_id=self.controller_id,
            timestamp=time.time(),
            result_success=result_success,
            result_exit_code=result_exit_code,
            result_rtmr=result_rtmr
        )
        
        # Compute and set the entry hash
        entry.entry_hash = entry.compute_hash()
        
        # Update chain state
        self.entries.append(entry)
        self.head_hash = entry.entry_hash
        
        # Persist to disk
        self._append_to_disk(entry)
        
        return entry
    
    def apply_entry(self, entry: TransitionEntry) -> Tuple[bool, str]:
        """
        Apply an entry received from another controller (during sync).
        
        Args:
            entry: TransitionEntry to apply
        
        Returns:
            (success, error_message)
        """
        # Verify sequence number
        expected_seq = len(self.entries)
        if entry.seq != expected_seq:
            return False, f"Sequence mismatch: expected {expected_seq}, got {entry.seq}"
        
        # Verify prev_hash links to our head
        if entry.prev_hash != self.head_hash:
            return False, f"Chain broken: prev_hash {entry.prev_hash[:16]}... != head {self.head_hash[:16]}..."
        
        # Verify entry hash is correct
        computed_hash = entry.compute_hash()
        if entry.entry_hash != computed_hash:
            return False, f"Entry hash mismatch: claimed {entry.entry_hash[:16]}..., computed {computed_hash[:16]}..."
        
        # Verify CVM ID matches
        if entry.cvm_id != self.cvm_id:
            return False, f"CVM ID mismatch: {entry.cvm_id} != {self.cvm_id}"
        
        # Apply the entry
        self.entries.append(entry)
        self.head_hash = entry.entry_hash
        self._append_to_disk(entry)
        
        return True, None
    
    def verify_chain(self) -> Tuple[bool, Optional[int], str]:
        """
        Verify the entire hash chain integrity.
        
        Returns:
            (is_valid, failed_at_seq, error_message)
        """
        expected_prev = self.GENESIS_HASH
        
        for entry in self.entries:
            # Check prev_hash links correctly
            if entry.prev_hash != expected_prev:
                return False, entry.seq, f"Chain broken at seq {entry.seq}"
            
            # Verify entry hash
            computed = entry.compute_hash()
            if entry.entry_hash != computed:
                return False, entry.seq, f"Hash mismatch at seq {entry.seq}"
            
            expected_prev = entry.entry_hash
        
        return True, None, "Chain verified"
    
    def get_sync_state(self) -> dict:
        """Get current state for sync comparison with other controllers."""
        return {
            "cvm_id": self.cvm_id,
            "head_hash": self.head_hash,
            "seq": len(self.entries),
            "controller_id": self.controller_id
        }
    
    def get_entries_since(self, seq: int) -> List[TransitionEntry]:
        """Get all entries from seq onwards (for syncing)."""
        if seq < 0 or seq >= len(self.entries):
            return []
        return self.entries[seq:]
    
    def get_entry(self, seq: int) -> Optional[TransitionEntry]:
        """Get a specific entry by sequence number."""
        if 0 <= seq < len(self.entries):
            return self.entries[seq]
        return None
    
    def get_latest(self) -> Optional[TransitionEntry]:
        """Get the most recent entry."""
        if self.entries:
            return self.entries[-1]
        return None
    
    def _append_to_disk(self, entry: TransitionEntry):
        """Append a single entry to the log file."""
        with open(self.log_file, 'a') as f:
            f.write(entry.to_json() + '\n')
    
    def _load_from_disk(self):
        """Load existing log from disk."""
        if not self.log_file.exists():
            return
        
        with open(self.log_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    entry = TransitionEntry.from_json(line)
                    self.entries.append(entry)
                    self.head_hash = entry.entry_hash
        
        # Verify loaded chain
        if self.entries:
            valid, failed_at, msg = self.verify_chain()
            if not valid:
                raise RuntimeError(f"Loaded log is corrupted: {msg}")
    
    def __len__(self) -> int:
        return len(self.entries)
    
    def __repr__(self) -> str:
        return f"HashChainedLog(cvm={self.cvm_id}, entries={len(self.entries)}, head={self.head_hash[:16]}...)"


class TransitionLogManager:
    """
    Manages hash-chained logs for multiple CVMs.
    
    Each CVM has its own independent log. The manager handles:
    - Creating/retrieving logs for CVMs
    - Cross-CVM statistics
    - Bulk operations
    """
    
    def __init__(self, storage_dir: str, controller_id: str):
        self.storage_dir = Path(storage_dir)
        self.controller_id = controller_id
        self.logs: dict[str, HashChainedLog] = {}
        
        # Load existing logs
        self._load_existing_logs()
    
    def _load_existing_logs(self):
        """Load all existing log files from storage."""
        if not self.storage_dir.exists():
            return
        
        for log_file in self.storage_dir.glob("transition_log_*.jsonl"):
            # Extract CVM ID from filename
            # Format: transition_log_<cvm_id>.jsonl
            cvm_id = log_file.stem.replace("transition_log_", "").replace("_", ".")
            self.logs[cvm_id] = HashChainedLog(cvm_id, str(self.storage_dir), self.controller_id)
    
    def get_log(self, cvm_id: str) -> HashChainedLog:
        """Get or create log for a CVM."""
        if cvm_id not in self.logs:
            self.logs[cvm_id] = HashChainedLog(cvm_id, str(self.storage_dir), self.controller_id)
        return self.logs[cvm_id]
    
    def record_transition(self, cvm_id: str, command: str, asp_id: str,
                         asp_signature: str, result_success: bool,
                         result_exit_code: int, result_rtmr: str = "") -> TransitionEntry:
        """Record a transition for a CVM."""
        log = self.get_log(cvm_id)
        return log.append(
            command=command,
            asp_id=asp_id,
            asp_signature=asp_signature,
            result_success=result_success,
            result_exit_code=result_exit_code,
            result_rtmr=result_rtmr
        )
    
    def get_all_sync_states(self) -> dict:
        """Get sync states for all CVMs."""
        return {cvm_id: log.get_sync_state() for cvm_id, log in self.logs.items()}
    
    def get_stats(self) -> dict:
        """Get statistics across all logs."""
        total_entries = sum(len(log) for log in self.logs.values())
        return {
            "total_cvms": len(self.logs),
            "total_transitions": total_entries,
            "cvms": {cvm_id: len(log) for cvm_id, log in self.logs.items()}
        }
