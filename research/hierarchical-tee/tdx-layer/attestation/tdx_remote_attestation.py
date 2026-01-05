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
    
    # Additional TDX module measurements
    mrseam: str = ""  # TDX Module measurement
    mrsignerseam: str = ""  # TDX Module signer measurement
    seamsvn: int = 0  # SEAM module security version
    
    # TD owner info
    mrowner: str = ""  # TD Owner identity
    mrownerconfig: str = ""  # TD Owner configuration
    
    # TD attributes
    xfam: str = ""  # Extended Feature Activation Mask
    td_attributes: Dict[str, Any] = field(default_factory=dict)
    
    # TCB information (platform-linkable!)
    tcb_date: str = ""  # TCB date - reveals patch timeline
    advisory_ids: list = field(default_factory=list)  # Security advisories
    
    # Collateral info (highly linkable - contains platform IDs)
    collateral: Dict[str, Any] = field(default_factory=dict)
    
    # JWT metadata
    issuer: str = ""
    issued_at: int = 0
    expires_at: int = 0
    token_id: str = ""
    
    def __post_init__(self):
        # Extract JWT standard claims
        self.issuer = self.payload.get('iss', '')
        self.issued_at = self.payload.get('iat', 0)
        self.expires_at = self.payload.get('exp', 0)
        self.token_id = self.payload.get('jti', '')
        
        if 'tdx' in self.payload:
            tdx = self.payload['tdx']
            
            # Core TD measurements
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
            
            # TDX module measurements
            self.mrseam = tdx.get('tdx_mrseam', '')
            self.mrsignerseam = tdx.get('tdx_mrsignerseam', '')
            self.seamsvn = tdx.get('tdx_seamsvn', 0)
            
            # TD owner info
            self.mrowner = tdx.get('tdx_mrowner', '')
            self.mrownerconfig = tdx.get('tdx_mrownerconfig', '')
            
            # TD attributes
            self.xfam = tdx.get('tdx_xfam', '')
            self.td_attributes = {
                'debug': tdx.get('tdx_is_debuggable', False),
                'septve_disable': tdx.get('tdx_td_attributes_septve_disable', None),
                'pks': tdx.get('tdx_td_attributes_pks', None),
                'kl': tdx.get('tdx_td_attributes_kl', None),
            }
            
            # TCB info (platform-linkable)
            self.tcb_date = tdx.get('attester_tcb_date', '')
            self.advisory_ids = tdx.get('attester_advisory_ids', [])
            
            # Collateral (highly linkable - contains FMSPC, QE hash, etc.)
            if 'tdx_collateral' in tdx:
                self.collateral = tdx['tdx_collateral']
            else:
                # Some fields might be at top level
                self.collateral = {
                    'fmspc': tdx.get('fmspc', ''),
                    'pce_id': tdx.get('pce_id', ''),
                }
    
    def get_measurements(self) -> Dict[str, str]:
        """Get key measurements for binding with SGX"""
        return {
            'mrtd': self.mrtd,
            'report_data': self.report_data,
            **self.rtmrs
        }
    
    def get_platform_linkable_fields(self) -> Dict[str, Any]:
        """Get fields that could be used to link attestations to the same platform"""
        return {
            'tcb_status': self.tcb_status,
            'tcb_date': self.tcb_date,
            'advisory_ids': self.advisory_ids,
            'seamsvn': self.seamsvn,
            'collateral': self.collateral,
        }
    
    def is_valid(self) -> bool:
        """Check if token is valid (not expired)"""
        return self.expires_at > time.time()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'raw_token': self.raw_token,
            'mrtd': self.mrtd,
            'rtmrs': self.rtmrs,
            'report_data': self.report_data,
            'tcb_status': self.tcb_status,
            'is_debuggable': self.is_debuggable,
            'mrseam': self.mrseam,
            'mrsignerseam': self.mrsignerseam,
            'seamsvn': self.seamsvn,
            'mrowner': self.mrowner,
            'mrownerconfig': self.mrownerconfig,
            'xfam': self.xfam,
            'td_attributes': self.td_attributes,
            'tcb_date': self.tcb_date,
            'advisory_ids': self.advisory_ids,
            'collateral': self.collateral,
            'issuer': self.issuer,
            'exp': self.expires_at,
            'iat': self.issued_at,
            'jti': self.token_id,
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
        
        # Display ALL token fields for research analysis
        print("\n[5] TDX Token Contents (All Fields):")
        
        # 5a. Core TD Measurements (TD-specific, not platform-linkable)
        print("\n    ═══════════════════════════════════════════════════════════════")
        print("    [5a] CORE TD MEASUREMENTS (TD-specific, privacy-preserving)")
        print("    ═══════════════════════════════════════════════════════════════")
        print(f"    MRTD (TD Measurement):     {token.mrtd[:48]}..." if token.mrtd else "    MRTD: N/A")
        print(f"    RTMR0 (Firmware):          {token.rtmrs.get('rtmr0', 'N/A')[:48]}..." if token.rtmrs.get('rtmr0') else "    RTMR0: N/A")
        print(f"    RTMR1 (OS Boot):           {token.rtmrs.get('rtmr1', 'N/A')[:48]}..." if token.rtmrs.get('rtmr1') else "    RTMR1: N/A")
        print(f"    RTMR2 (OS Runtime):        {token.rtmrs.get('rtmr2', 'N/A')[:48]}..." if token.rtmrs.get('rtmr2') else "    RTMR2: N/A")
        print(f"    RTMR3 (Application):       {token.rtmrs.get('rtmr3', 'N/A')[:48]}..." if token.rtmrs.get('rtmr3') else "    RTMR3: N/A")
        print(f"    Report Data (User):        {token.report_data[:48]}..." if token.report_data else "    Report Data: N/A")
        
        # 5b. TDX Module Info
        print("\n    ═══════════════════════════════════════════════════════════════")
        print("    [5b] TDX MODULE MEASUREMENTS (same across platforms with same TDX version)")
        print("    ═══════════════════════════════════════════════════════════════")
        print(f"    MRSEAM (TDX Module):       {token.mrseam[:48]}..." if token.mrseam else "    MRSEAM: N/A")
        print(f"    MRSIGNERSEAM (Module Signer): {token.mrsignerseam[:48]}..." if token.mrsignerseam else "    MRSIGNERSEAM: N/A")
        print(f"    SEAM SVN:                  {token.seamsvn}")
        
        # 5c. TD Owner Info
        print("\n    ═══════════════════════════════════════════════════════════════")
        print("    [5c] TD OWNER INFORMATION")
        print("    ═══════════════════════════════════════════════════════════════")
        print(f"    MROWNER:                   {token.mrowner[:48]}..." if token.mrowner else "    MROWNER: N/A (not set)")
        print(f"    MROWNERCONFIG:             {token.mrownerconfig[:48]}..." if token.mrownerconfig else "    MROWNERCONFIG: N/A (not set)")
        
        # 5d. TD Attributes
        print("\n    ═══════════════════════════════════════════════════════════════")
        print("    [5d] TD ATTRIBUTES")
        print("    ═══════════════════════════════════════════════════════════════")
        print(f"    XFAM:                      {token.xfam}" if token.xfam else "    XFAM: N/A")
        print(f"    Debug Mode:                {token.is_debuggable} {'⚠️  WARNING: Not for production!' if token.is_debuggable else '✓'}")
        print(f"    SEPT VE Disabled:          {token.td_attributes.get('septve_disable', 'N/A')}")
        print(f"    PKS (Protection Keys):     {token.td_attributes.get('pks', 'N/A')}")
        print(f"    KL (Key Locker):           {token.td_attributes.get('kl', 'N/A')}")
        
        # 5e. TCB Information (PLATFORM-LINKABLE!)
        print("\n    ═══════════════════════════════════════════════════════════════")
        print("    [5e] TCB INFORMATION ⚠️  PLATFORM-LINKABLE!")
        print("    ═══════════════════════════════════════════════════════════════")
        print(f"    TCB Status:                {token.tcb_status}")
        print(f"    TCB Date:                  {token.tcb_date}")
        print(f"    Advisory IDs:              {len(token.advisory_ids)} advisories")
        if token.advisory_ids:
            for adv in token.advisory_ids[:5]:  # Show first 5
                print(f"      - {adv}")
            if len(token.advisory_ids) > 5:
                print(f"      ... and {len(token.advisory_ids) - 5} more")
        
        # 5f. Collateral (HIGHLY LINKABLE - PCK-derived!)
        print("\n    ═══════════════════════════════════════════════════════════════")
        print("    [5f] COLLATERAL ⚠️  HIGHLY LINKABLE (PCK-derived platform IDs)")
        print("    ═══════════════════════════════════════════════════════════════")
        if token.collateral:
            fmspc = token.collateral.get('fmspc', 'N/A')
            print(f"    SAME across quotes->    FMSPC (Platform Family):   {fmspc}")
            pce_id = token.collateral.get('pce_id', token.collateral.get('pceid', 'N/A'))
            print(f"                            PCE ID:                    {pce_id}")
            qe_id = token.collateral.get('qeid', token.collateral.get('qeidhash', 'N/A'))
            if qe_id and qe_id != 'N/A':
                print(f"    SAME across quotes->    QE ID Hash:                {str(qe_id)[:32]}...")
            tcb_eval = token.collateral.get('tcbevaluationdatanumber', 'N/A')
            print(f"    TCB Eval Number:           {tcb_eval}")
            # Show any other collateral fields
            other_fields = {k: v for k, v in token.collateral.items() 
                          if k not in ['fmspc', 'pce_id', 'pceid', 'qeid', 'qeidhash', 'tcbevaluationdatanumber']}
            if other_fields:
                print(f"    Other collateral fields:   {list(other_fields.keys())}")
        else:
            print("    (No collateral data in token)")
        
        # 5g. JWT Metadata
        print("\n    ═══════════════════════════════════════════════════════════════")
        print("    [5g] JWT TOKEN METADATA")
        print("    ═══════════════════════════════════════════════════════════════")
        print(f"    Issuer:                    {token.issuer}")
        print(f"    Token ID (JTI):            {token.token_id[:32]}..." if token.token_id else "    Token ID: N/A")
        from datetime import datetime
        if token.issued_at:
            print(f"    Issued At:                 {datetime.fromtimestamp(token.issued_at).isoformat()}")
        if token.expires_at:
            print(f"    Expires At:                {datetime.fromtimestamp(token.expires_at).isoformat()}")
            remaining = token.expires_at - time.time()
            print(f"    Time Remaining:            {remaining:.0f} seconds")
        
        # 5h. Privacy Summary
        print("\n    ═══════════════════════════════════════════════════════════════")
        print("    [5h] PRIVACY ANALYSIS SUMMARY")
        print("    ═══════════════════════════════════════════════════════════════")
        print("    ✓ SAFE (TD-specific):      MRTD, RTMR0-3, Report Data, MROWNER")
        print("    ⚠️  CAUTION (version-based): MRSEAM, SEAMSVN, TCB Status/Date")  
        print("    ✗ LINKABLE (platform-ID):  FMSPC, PCE_ID, QE_ID, Advisory IDs")
        print("    → For privacy-preserving attestation, anonymize/remove ✗ fields")

        # Verify token
        print("\n[6] Verifying token... (only checks structure and expiry.\n    Full verification requires checking the signature against Intel's public keys)")
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
