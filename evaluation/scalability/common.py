#!/usr/bin/env python3
"""Compatibility shim so this directory does not shadow `common.protocol`."""

from pathlib import Path


_PKG_DIR = (
    Path(__file__).resolve().parents[2]
    / "research"
    / "sgx-tdx-attestation"
    / "common"
)

# Expose the SGX/TDX common package path so imports such as
# `from common.protocol import ...` resolve correctly when scripts in
# `evaluation/scalability` are executed directly.
__path__ = [str(_PKG_DIR)]
