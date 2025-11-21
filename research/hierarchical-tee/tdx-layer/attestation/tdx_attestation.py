#!/usr/bin/env python3
"""
TDX Attestation Module for Hierarchical TEE Research
Handles TDX report generation and evidence collection
"""

import os
import ctypes
import struct
from typing import Optional, Dict, Any
from dataclasses import dataclass
import hashlib

# TDX IOCTL definitions
TDX_CMD_GET_REPORT0 = 0xC4005401  # _IOWR('T', 1, struct tdx_report_req)

class TdxReportReq(ctypes.Structure):
    _fields_ = [
        ("reportdata", ctypes.c_uint8 * 64),
        ("tdreport", ctypes.c_uint8 * 1024)
    ]

@dataclass
class TDXEvidence:
    """TDX attestation evidence"""
    report: bytes
    report_data: bytes
    measurements: Dict[str, str]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_hex": self.report.hex(),
            "report_data_hex": self.report_data.hex(),
            "measurements": self.measurements
        }

class TDXAttestor:
    """Handles TDX attestation operations"""
    
    def __init__(self, device_path: str = "/dev/tdx_guest"):
        self.device_path = device_path
        self._verify_device()
    
    def _verify_device(self):
        """Verify TDX device is available"""
        if not os.path.exists(self.device_path):
            raise RuntimeError(f"TDX device not found: {self.device_path}")
        
        if not os.access(self.device_path, os.R_OK | os.W_OK):
            raise PermissionError(f"Insufficient permissions for {self.device_path}. Run as root.")
    
    def generate_report(self, report_data: bytes = None) -> TDXEvidence:
        """
        Generate TDX report with optional custom report data
        
        Args:
            report_data: Custom data to include (max 64 bytes)
        
        Returns:
            TDXEvidence object containing the report and measurements
        """
        if report_data is None:
            report_data = b"Hierarchical-TEE-Research-TDX-Layer"
        
        if len(report_data) > 64:
            raise ValueError("Report data must be <= 64 bytes")
        
        # Pad report data to 64 bytes
        padded_data = report_data.ljust(64, b'\x00')
        
        # Open device and generate report
        with open(self.device_path, 'rb+') as fd:
            req = TdxReportReq()
            req.reportdata[:] = (ctypes.c_uint8 * 64).from_buffer_copy(padded_data)
            
            # Call IOCTL (simplified - in real implementation use fcntl.ioctl)
            # For now, we'll note that the C program works
            pass
        
        # Extract measurements (would parse actual report structure)
        measurements = self._extract_measurements(bytes(req.tdreport))
        
        return TDXEvidence(
            report=bytes(req.tdreport),
            report_data=padded_data,
            measurements=measurements
        )
    
    def _extract_measurements(self, report: bytes) -> Dict[str, str]:
        """Extract key measurements from TDX report"""
        # TDX report structure (simplified)
        # Real implementation would parse the actual TD report format
        
        measurements = {
            "report_hash": hashlib.sha256(report).hexdigest()[:16],
            "report_size": len(report),
            "tdx_version": "1.0",  # Would extract from report
        }
        
        return measurements

def main():
    """Test TDX attestation"""
    print("=== TDX Attestation Module Test ===\n")
    
    try:
        attestor = TDXAttestor()
        print("✓ TDX device initialized\n")
        
        # Generate report with custom data
        custom_data = b"Test-Attestation-" + os.urandom(16).hex().encode()
        print(f"Generating report with data: {custom_data.decode()}\n")
        
        # Note: Would need root and proper IOCTL implementation
        print("Note: Full report generation requires root access and IOCTL implementation")
        print("Use the C program (get_tdx_report) for actual report generation\n")
        
    except Exception as e:
        print(f"✗ Error: {e}\n")

if __name__ == "__main__":
    main()
