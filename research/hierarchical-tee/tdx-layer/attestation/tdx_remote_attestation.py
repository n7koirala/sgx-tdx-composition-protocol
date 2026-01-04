#!/usr/bin/env python3
"""
TDX Remote Attestation Module
For Hierarchical TEE Composition Protocol

This module provides TDX attestation capabilities using Intel Trust Authority.
It is designed to integrate with the SGX attestation layer for the composition protocol.

Usage:
    from tdx_remote_attestation import TDXAttestor
    
    attestor = TDXAttestor()
    
    # Get attestation token (for remote verification)
    token = attestor.get_attestation_token()
    
    # Get raw evidence (for local processing or custom verification)
    evidence = attestor.get_evidence()
    
    # Parse and extract claims from token
    claims = attestor.parse_token(token)
"""

import subprocess
import json
import base64
import time
import os
import hashlib
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, Tuple
from datetime import datetime


@dataclass
class TDXEvidence:
    """Raw TDX evidence structure"""
    quote: str  # Base64 encoded TDX quote
    verifier_nonce: Dict[str, str]
    raw_json: Dict[str, Any]
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "quote": self.quote,
            "verifier_nonce": self.verifier_nonce,
            "timestamp": self.timestamp
        }


@dataclass
class TDXAttestationToken:
    """Parsed TDX attestation token (JWT from Intel Trust Authority)"""
    raw_token: str
    header: Dict[str, Any]
    payload: Dict[str, Any]
    signature: str
    
    # Key TDX measurements
    mrtd: str = ""  # TD Measurement (like SGX MRENCLAVE)
    rtmrs: Dict[str, str] = field(default_factory=dict)  # Runtime measurements
    report_data: str = ""  # User-provided data
    tcb_status: str = ""
    is_debuggable: bool = False
    
    def __post_init__(self):
        if 'tdx' in self.payload:
            tdx = self.payload['tdx']
            self.mrtd = tdx.get('tdx_mrtd', '')
            self.rtmrs = {
                'rtmr0': tdx.get('tdx_rtmr0', ''),
                'rtmr1': tdx.get('tdx_rtmr1', ''),
                'rtmr2': tdx.get('tdx_rtmr2', ''),
                'rtmr3': tdx.get('tdx_rtmr3', ''),
            }
            self.report_data = tdx.get('tdx_report_data', '')
            self.tcb_status = tdx.get('attester_tcb_status', '')
            self.is_debuggable = tdx.get('tdx_is_debuggable', False)
    
    def get_measurements(self) -> Dict[str, str]:
        """Get key measurements for binding with SGX"""
        return {
            'mrtd': self.mrtd,
            'report_data': self.report_data,
            **self.rtmrs
        }
    
    def is_valid(self) -> bool:
        """Check if token is valid (not expired)"""
        exp = self.payload.get('exp', 0)
        return exp > time.time()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'raw_token': self.raw_token,
            'mrtd': self.mrtd,
            'rtmrs': self.rtmrs,
            'report_data': self.report_data,
            'tcb_status': self.tcb_status,
            'is_debuggable': self.is_debuggable,
            'exp': self.payload.get('exp'),
            'iat': self.payload.get('iat'),
        }


class TDXAttestor:
    """
    TDX Remote Attestation using Intel Trust Authority
    
    This class provides methods to:
    1. Generate TDX evidence/quotes
    2. Get attestation tokens from Intel Trust Authority
    3. Parse and verify attestation tokens
    4. Extract measurements for composition with SGX
    
    Token caching is enabled by default to avoid hitting API rate limits.
    """
    
    # Class-level token cache to persist across instances
    _token_cache: Dict[str, 'TDXAttestationToken'] = {}
    
    # Cache expiry buffer in seconds (refresh token this many seconds before expiry)
    CACHE_EXPIRY_BUFFER = 60
    
    def __init__(self, config_path: str = None, use_cache: bool = True):
        """
        Initialize TDX Attestor
        
        Args:
            config_path: Path to Intel Trust Authority config JSON
                        Defaults to ~/config.json
            use_cache: Whether to use token caching (default: True)
                      Set to False to always fetch fresh tokens
        """
        if config_path is None:
            config_path = os.path.expanduser("~/config.json")
        
        self.config_path = config_path
        self.use_cache = use_cache
        self._verify_setup()
    
    def _get_cache_key(self, user_data: Optional[str] = None, 
                       request_id: Optional[str] = None) -> str:
        """Generate a cache key from user_data and request_id"""
        key_parts = [
            user_data or "default",
            request_id or "no_request_id"
        ]
        return ":".join(key_parts)
    
    def _get_cached_token(self, cache_key: str) -> Optional['TDXAttestationToken']:
        """
        Get a cached token if it exists and is still valid
        
        Returns None if no valid cached token exists
        """
        if cache_key not in self._token_cache:
            return None
        
        token = self._token_cache[cache_key]
        
        # Check if token is still valid (with buffer time)
        exp = token.payload.get('exp', 0)
        if exp > (time.time() + self.CACHE_EXPIRY_BUFFER):
            return token
        
        # Token expired or will expire soon, remove from cache
        del self._token_cache[cache_key]
        return None
    
    def _cache_token(self, cache_key: str, token: 'TDXAttestationToken') -> None:
        """Store a token in the cache"""
        self._token_cache[cache_key] = token
    
    def clear_cache(self) -> int:
        """
        Clear all cached tokens
        
        Returns:
            Number of tokens cleared
        """
        count = len(self._token_cache)
        self._token_cache.clear()
        return count
    
    def _verify_setup(self):
        """Verify TDX and Trust Authority are available"""
        # Check TDX device
        if not os.path.exists("/dev/tdx_guest"):
            raise RuntimeError("TDX device not found: /dev/tdx_guest")
        
        # Check config file
        if not os.path.exists(self.config_path):
            raise RuntimeError(f"Config file not found: {self.config_path}")
        
        # Check trustauthority-cli
        result = subprocess.run(
            ["which", "trustauthority-cli"],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            raise RuntimeError("trustauthority-cli not found in PATH")
    
    def get_evidence(self, user_data: str = None) -> TDXEvidence:
        """
        Generate TDX evidence (quote) without contacting Trust Authority for verification
        
        Args:
            user_data: Optional base64-encoded user data to include in quote
        
        Returns:
            TDXEvidence object containing the quote
        """
        cmd = ["sudo", "trustauthority-cli", "evidence", "--tdx", "-c", self.config_path]
        
        if user_data:
            cmd.extend(["-u", user_data])
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            raise RuntimeError(f"Evidence generation failed: {result.stderr}")
        
        # Parse JSON output
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse evidence JSON: {e}")
        
        tdx_data = data.get('tdx', {})
        
        return TDXEvidence(
            quote=tdx_data.get('quote', ''),
            verifier_nonce=data.get('verifier_nonce', {}),
            raw_json=data
        )
    
    def get_attestation_token(self, user_data: str = None, 
                               request_id: str = None,
                               force_refresh: bool = False) -> TDXAttestationToken:
        """
        Get verified attestation token from Intel Trust Authority
        
        This is the main method for remote attestation. It:
        1. Checks cache for a valid token (if caching enabled)
        2. If not cached, generates a TDX quote
        3. Sends it to Intel Trust Authority
        4. Caches and returns the signed JWT token
        
        Args:
            user_data: Optional base64-encoded user data to include
            request_id: Optional request ID for tracking
            force_refresh: Force fetch a new token, bypassing cache
        
        Returns:
            TDXAttestationToken containing the verified attestation
        """
        cache_key = self._get_cache_key(user_data, request_id)
        
        # Check cache first (unless force_refresh is True)
        if self.use_cache and not force_refresh:
            cached_token = self._get_cached_token(cache_key)
            if cached_token is not None:
                return cached_token
        
        cmd = ["sudo", "trustauthority-cli", "token", "--tdx", "-c", self.config_path]
        
        if user_data:
            cmd.extend(["-u", user_data])
        if request_id:
            cmd.extend(["-r", request_id])
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.returncode != 0:
            raise RuntimeError(f"Token generation failed: {result.stderr}")
        
        # Extract JWT token from output (last non-empty line starting with eyJ)
        token_str = None
        for line in result.stdout.strip().split('\n'):
            if line.startswith('eyJ'):
                token_str = line
                break
        
        if not token_str:
            raise RuntimeError("No JWT token found in output")
        
        token = self.parse_token(token_str)
        
        # Cache the token
        if self.use_cache:
            self._cache_token(cache_key, token)
        
        return token
    
    def parse_token(self, token: str) -> TDXAttestationToken:
        """
        Parse a JWT attestation token
        
        Args:
            token: Raw JWT token string
        
        Returns:
            TDXAttestationToken with parsed claims
        """
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")
        
        # Decode header and payload
        header = self._decode_jwt_part(parts[0])
        payload = self._decode_jwt_part(parts[1])
        
        return TDXAttestationToken(
            raw_token=token,
            header=header,
            payload=payload,
            signature=parts[2]
        )
    
    def _decode_jwt_part(self, part: str) -> Dict[str, Any]:
        """Decode a base64url encoded JWT part"""
        # Add padding if needed
        padded = part + '=' * (4 - len(part) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        return json.loads(decoded)
    
    def get_binding_data(self, sgx_mrenclave: str = None, 
                         force_refresh: bool = False) -> Tuple[str, TDXAttestationToken]:
        """
        Get TDX attestation with binding data for SGX composition
        
        This method creates attestation evidence that can be bound to an SGX enclave.
        The binding is done by including the SGX MRENCLAVE in the TDX report data.
        
        Uses token caching to avoid rate limits - pass force_refresh=True to bypass cache.
        
        Args:
            sgx_mrenclave: Optional SGX enclave measurement to bind to
            force_refresh: Force fetch a new token, bypassing cache
        
        Returns:
            Tuple of (binding_hash, TDXAttestationToken)
        """
        # Create binding data that includes SGX measurement
        # Note: We don't include timestamp to allow caching with the same user_data
        binding_data = {
            "purpose": "hierarchical-tee-composition",
        }
        
        if sgx_mrenclave:
            binding_data["sgx_mrenclave"] = sgx_mrenclave
        
        # Hash the binding data
        binding_json = json.dumps(binding_data, sort_keys=True)
        binding_hash = hashlib.sha256(binding_json.encode()).hexdigest()
        
        # Encode as base64 for user_data
        user_data = base64.b64encode(binding_hash[:32].encode()).decode()
        
        # Get attestation with binding data (uses cache if available)
        token = self.get_attestation_token(user_data=user_data, force_refresh=force_refresh)
        
        return binding_hash, token
    
    def verify_token_locally(self, token: TDXAttestationToken) -> Tuple[bool, str]:
        """
        Perform basic local verification of token
        
        Note: This only checks structure and expiry.
        Full verification requires checking the signature against Intel's public keys.
        
        Args:
            token: TDXAttestationToken to verify
        
        Returns:
            Tuple of (is_valid, message)
        """
        # Check expiry
        if not token.is_valid():
            return False, "Token expired"
        
        # Check issuer
        issuer = token.payload.get('iss', '')
        if 'trustauthority.intel.com' not in issuer:
            return False, f"Invalid issuer: {issuer}"
        
        # Check for TDX data
        if 'tdx' not in token.payload:
            return False, "No TDX claims in token"
        
        # Check debuggable status
        if token.is_debuggable:
            return True, "Valid but WARNING: TD is debuggable"
        
        return True, "Token appears valid"


class TDXVerifier:
    """
    Remote verifier for TDX attestation tokens
    
    This class can be used to verify TDX attestation tokens
    received from TDX VMs.
    """
    
    def __init__(self):
        pass
    
    def verify(self, token_str: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Verify a TDX attestation token
        
        Args:
            token_str: Raw JWT token string
        
        Returns:
            Tuple of (is_valid, claims_or_error)
        """
        try:
            # Parse token
            parts = token_str.split('.')
            if len(parts) != 3:
                return False, {"error": "Invalid JWT format"}
            
            # Decode payload
            payload_padded = parts[1] + '=' * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_padded))
            
            # Check for TDX claims
            if 'tdx' not in payload:
                return False, {"error": "No TDX data in token"}
            
            # Check expiry
            exp = payload.get('exp', 0)
            if exp < time.time():
                return False, {"error": "Token expired"}
            
            # Extract key claims
            tdx = payload['tdx']
            claims = {
                'mrtd': tdx.get('tdx_mrtd', ''),
                'report_data': tdx.get('tdx_report_data', ''),
                'tcb_status': tdx.get('attester_tcb_status', ''),
                'is_debuggable': tdx.get('tdx_is_debuggable', False),
                'exp': payload.get('exp'),
                'iat': payload.get('iat'),
            }
            
            return True, claims
            
        except Exception as e:
            return False, {"error": str(e)}


def main():
    """Demo and test the TDX attestation module"""
    print("=" * 70)
    print("TDX Remote Attestation Module - Demo")
    print("=" * 70)
    
    try:
        # Initialize attestor
        print("\n[1] Initializing TDX Attestor...")
        attestor = TDXAttestor()
        print("    ✓ TDX Attestor initialized successfully")
        print(f"    Cache enabled: {attestor.use_cache}")
        
        # Get evidence
        print("\n[2] Generating TDX evidence (quote)...")
        start = time.perf_counter()
        evidence = attestor.get_evidence()
        evidence_time = (time.perf_counter() - start) * 1000
        print(f"    ✓ Evidence generated in {evidence_time:.2f} ms")
        print(f"    Quote length: {len(evidence.quote)} bytes (base64)")
        
        # Get attestation token (first call - fresh fetch)
        print("\n[3] Getting attestation token from Intel Trust Authority...")
        start = time.perf_counter()
        token = attestor.get_attestation_token()
        token_time = (time.perf_counter() - start) * 1000
        print(f"    ✓ Token received in {token_time:.2f} ms (fresh fetch)")
        print(f"    Token length: {len(token.raw_token)} bytes")
        
        # Demonstrate caching - second call should be instant
        print("\n[4] Demonstrating token caching...")
        start = time.perf_counter()
        cached_token = attestor.get_attestation_token()
        cached_time = (time.perf_counter() - start) * 1000
        print(f"    ✓ Token retrieved in {cached_time:.2f} ms (from cache)")
        print(f"    Same token: {token.raw_token == cached_token.raw_token}")
        
        # Display key measurements
        print("\n[5] TDX Measurements:")
        print(f"    MRTD:        {token.mrtd[:32]}...")
        print(f"    RTMR0:       {token.rtmrs.get('rtmr0', 'N/A')[:32]}...")
        print(f"    Report Data: {token.report_data[:32]}...")
        print(f"    TCB Status:  {token.tcb_status}")
        print(f"    Debuggable:  {token.is_debuggable}")
        
        # Verify token
        print("\n[6] Verifying token...")
        is_valid, message = attestor.verify_token_locally(token)
        if is_valid:
            print(f"    ✓ {message}")
        else:
            print(f"    ✗ {message}")

        # Get binding data (uses caching)
        print("\n[7] Getting SGX Binding Data (uses caching)...")
        start = time.perf_counter()
        binding_hash, binding_token = attestor.get_binding_data()
        binding_time = (time.perf_counter() - start) * 1000
        print(f"    ✓ Binding data retrieved in {binding_time:.2f} ms")
        print(f"    Binding hash: {binding_hash[:32]}...")
        print(f"    Token length: {len(binding_token.raw_token)} bytes")
        
        # Second call to get_binding_data should be cached
        print("\n[8] Calling get_binding_data again (from cache)...")
        start = time.perf_counter()
        binding_hash2, binding_token2 = attestor.get_binding_data(force_refresh=False)
        binding_time2 = (time.perf_counter() - start) * 1000
        print(f"    ✓ Binding data retrieved in {binding_time2:.2f} ms (from cache)")
        print(f"    Same token: {binding_token.raw_token == binding_token2.raw_token}")

        # Demonstrate force_refresh
        # print("\n[9] Force refresh to bypass cache...")
        # start = time.perf_counter()
        # _, fresh_token = attestor.get_binding_data(force_refresh=True)
        # fresh_time = (time.perf_counter() - start) * 1000
        # print(f"    ✓ Fresh token fetched in {fresh_time:.2f} ms (forced refresh)")
        
        # Show cache info
        print(f"\n[10] Cache Info:")
        print(f"    Tokens cached: {len(attestor._token_cache)}")
        print(f"    Cache expiry buffer: {attestor.CACHE_EXPIRY_BUFFER} seconds")
        
        print("\n" + "=" * 70)
        print("TDX Remote Attestation Demo Complete")
        print("=" * 70)
        
        return token
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
        raise


if __name__ == "__main__":
    main()
