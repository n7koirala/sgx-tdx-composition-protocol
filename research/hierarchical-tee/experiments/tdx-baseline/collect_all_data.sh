#!/bin/bash
# Master data collection script for TDX baseline experiments

echo "=========================================="
echo "TDX Baseline Data Collection"
echo "=========================================="
echo "Started at: $(date)"
echo ""

# Create output directory with timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTDIR="tdx_baseline_${TIMESTAMP}"
mkdir -p ${OUTDIR}

echo "[1/4] Running attestation benchmarks..."
sudo python3 attestation_benchmark_fixed.py
mv tdx_baseline_*.json ${OUTDIR}/

echo ""
echo "[2/4] Running linkability analysis..."
sudo python3 linkability_analysis_fixed.py
mv linkability_analysis_*.json ${OUTDIR}/

echo ""
echo "[3/4] Running remote attestation test (localhost)..."
# Start verifier in background
python3 verifier.py &
VERIFIER_PID=$!
sleep 2

# Run test
python3 remote_attestation_test_fixed.py --test localhost --iterations 20
mv remote_attestation_*.json ${OUTDIR}/

# Stop verifier
kill $VERIFIER_PID 2>/dev/null

echo ""
echo "[4/4] Decoding sample token..."
TOKEN=$(sudo trustauthority-cli token --tdx -c ~/config.json 2>/dev/null | tail -1)
python3 decode_token.py "$TOKEN"
mv decoded_token.json ${OUTDIR}/

echo ""
echo "=========================================="
echo "Data collection complete!"
echo "Results saved in: ${OUTDIR}"
echo "Completed at: $(date)"
echo "=========================================="
