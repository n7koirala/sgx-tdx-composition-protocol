#!/usr/bin/env python3
"""
Comprehensive SGX vs TDX Baseline Comparison
Using actual measurement data
"""

import matplotlib.pyplot as plt
import numpy as np
import json
from datetime import datetime

# Set publication quality
plt.rcParams['figure.figsize'] = (14, 8)
plt.rcParams['font.size'] = 11
plt.rcParams['axes.labelsize'] = 12
plt.rcParams['legend.fontsize'] = 10

class HierarchicalTEEAnalysis:
    def __init__(self):
        # SGX Baseline (from your benchmark)
        self.sgx = {
            'ereport_ms': 0.014,
            'quote_prep_ms': 0.007,
            'combined_ms': 0.021,
            'enclave_creation_ms': 23.898,
            'throughput': 70828.29
        }
        
        # TDX Baseline (from your data)
        self.tdx = {
            'evidence_collection_ms': 199.75,  # Phase breakdown
            'full_attestation_ms': 344.18,     # Phase breakdown  
            'network_overhead_ms': 144.43,     # ITA verification
            'token_size_bytes': 5934,
            'header_bytes': 248,
            'payload_bytes': 5172,
            'signature_bytes': 512
        }
    
    def create_comprehensive_comparison(self):
        """Create all comparison visualizations"""
        fig = plt.figure(figsize=(16, 10))
        
        # Create 6 subplots
        gs = fig.add_gridspec(3, 3, hspace=0.3, wspace=0.3)
        
        # Plot 1: Latency Comparison (Log Scale)
        ax1 = fig.add_subplot(gs[0, :2])
        self.plot_latency_comparison(ax1)
        
        # Plot 2: Phase Breakdown
        ax2 = fig.add_subplot(gs[0, 2])
        self.plot_phase_breakdown(ax2)
        
        # Plot 3: Hierarchical Composition
        ax3 = fig.add_subplot(gs[1, :2])
        self.plot_hierarchical_composition(ax3)
        
        # Plot 4: Token Size
        ax4 = fig.add_subplot(gs[1, 2])
        self.plot_token_size(ax4)
        
        # Plot 5: Performance Budget
        ax5 = fig.add_subplot(gs[2, :])
        self.plot_performance_budget(ax5)
        
        plt.savefig('hierarchical_tee_complete_analysis.png', dpi=300, bbox_inches='tight')
        plt.savefig('hierarchical_tee_complete_analysis.pdf', bbox_inches='tight')
        print("✓ Saved: hierarchical_tee_complete_analysis.png/pdf")
        plt.close()
    
    def plot_latency_comparison(self, ax):
        """Plot 1: SGX vs TDX Latency (Log Scale)"""
        operations = ['Local\nAttestation', 'Full\nAttestation\n(with Network)']
        
        sgx_times = [self.sgx['combined_ms'], self.sgx['combined_ms']]  # SGX doesn't need network
        tdx_times = [self.tdx['evidence_collection_ms'], self.tdx['full_attestation_ms']]
        
        x = np.arange(len(operations))
        width = 0.35
        
        bars1 = ax.bar(x - width/2, sgx_times, width, label='SGX', 
                       color='#3498db', alpha=0.8, edgecolor='black', linewidth=1.5)
        bars2 = ax.bar(x + width/2, tdx_times, width, label='TDX', 
                       color='#e74c3c', alpha=0.8, edgecolor='black', linewidth=1.5)
        
        ax.set_ylabel('Latency (ms, log scale)')
        ax.set_title('SGX vs TDX: Attestation Latency Comparison')
        ax.set_xticks(x)
        ax.set_xticklabels(operations)
        ax.set_yscale('log')
        ax.legend()
        ax.grid(axis='y', alpha=0.3, which='both')
        
        # Add value labels
        for bars, times in [(bars1, sgx_times), (bars2, tdx_times)]:
            for bar, time in zip(bars, times):
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height * 1.5,
                       f'{time:.3f}',
                       ha='center', va='bottom', fontsize=9, fontweight='bold')
        
        # Add speedup annotation
        speedup = tdx_times[0] / sgx_times[0]
        ax.text(0.5, 0.95, f'SGX is {speedup:.0f}x faster', 
               transform=ax.transAxes, ha='center', va='top',
               bbox=dict(boxstyle='round', facecolor='yellow', alpha=0.7),
               fontsize=10, fontweight='bold')
    
    def plot_phase_breakdown(self, ax):
        """Plot 2: TDX Phase Breakdown"""
        phases = ['Evidence\nCollection', 'Network +\nVerification']
        times = [
            self.tdx['evidence_collection_ms'],
            self.tdx['network_overhead_ms']
        ]
        colors = ['#2ecc71', '#e74c3c']
        
        bars = ax.barh(phases, times, color=colors, alpha=0.8, edgecolor='black', linewidth=1.5)
        
        ax.set_xlabel('Time (ms)')
        ax.set_title('TDX Phase Breakdown')
        ax.grid(axis='x', alpha=0.3)
        
        # Add value labels
        for bar, time in zip(bars, times):
            width = bar.get_width()
            ax.text(width, bar.get_y() + bar.get_height()/2.,
                   f'{time:.1f} ms\n({time/self.tdx["full_attestation_ms"]*100:.1f}%)',
                   ha='left', va='center', fontsize=9, fontweight='bold',
                   bbox=dict(boxstyle='round', facecolor='white', alpha=0.7))
    
    def plot_hierarchical_composition(self, ax):
        """Plot 3: Hierarchical Protocol Composition"""
        components = ['SGX\nLayer', 'TDX\nLayer', 'Network\n(SGX↔TDX)', 'Binding\nOverhead', 'Total']
        
        sgx_time = self.sgx['combined_ms']
        tdx_time = self.tdx['evidence_collection_ms']
        network_time = 2.0  # Estimated: SGX server to TDX VM
        binding_time = 1.0  # Estimated: cryptographic binding
        total_time = sgx_time + tdx_time + network_time + binding_time
        
        times = [sgx_time, tdx_time, network_time, binding_time, total_time]
        colors = ['#3498db', '#e74c3c', '#9b59b6', '#f39c12', '#2ecc71']
        
        bars = ax.bar(components, times, color=colors, alpha=0.8, edgecolor='black', linewidth=1.5)
        
        ax.set_ylabel('Time (ms)')
        ax.set_title('Hierarchical Protocol: Estimated Component Breakdown')
        ax.grid(axis='y', alpha=0.3)
        
        # Add value labels
        for bar, time in zip(bars, times):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{time:.2f}' if time < 10 else f'{time:.1f}',
                   ha='center', va='bottom', fontsize=9, fontweight='bold')
        
        # Add overhead line
        overhead = total_time - tdx_time
        overhead_pct = (overhead / tdx_time) * 100
        ax.axhline(y=tdx_time, color='red', linestyle='--', linewidth=2, 
                  label=f'TDX-only baseline: {tdx_time:.1f} ms')
        ax.axhline(y=tdx_time * 1.5, color='green', linestyle='--', linewidth=2,
                  label=f'Target (+50%): {tdx_time*1.5:.1f} ms')
        
        ax.text(0.5, 0.95, f'Overhead: +{overhead_pct:.1f}% vs TDX-only', 
               transform=ax.transAxes, ha='center', va='top',
               bbox=dict(boxstyle='round', facecolor='lightgreen', alpha=0.7),
               fontsize=10, fontweight='bold')
        
        ax.legend(loc='upper left', fontsize=9)
    
    def plot_token_size(self, ax):
        """Plot 4: Token Size Analysis"""
        components = ['Header', 'Payload', 'Signature']
        sizes = [
            self.tdx['header_bytes'],
            self.tdx['payload_bytes'],
            self.tdx['signature_bytes']
        ]
        colors = ['#3498db', '#e74c3c', '#f39c12']
        
        wedges, texts, autotexts = ax.pie(sizes, labels=components, colors=colors,
                                          autopct=lambda pct: f'{pct:.1f}%\n({int(pct*sum(sizes)/100)} B)',
                                          startangle=90, textprops={'fontweight': 'bold', 'fontsize': 9})
        
        ax.set_title(f'TDX Token Structure\nTotal: {sum(sizes)} bytes')
        
        # Add hierarchical estimate
        hierarchical_size = sum(sizes) + 1000  # Estimate: +1KB for SGX quote
        ax.text(0, -1.3, f'Hierarchical (est.): {hierarchical_size} bytes (+{(hierarchical_size-sum(sizes))/sum(sizes)*100:.0f}%)',
               ha='center', fontsize=9, 
               bbox=dict(boxstyle='round', facecolor='lightyellow', alpha=0.7))
    
    def plot_performance_budget(self, ax):
        """Plot 5: Performance Budget Analysis"""
        # Define scenarios
        scenarios = [
            'TDX-only\nBaseline',
            'Hierarchical\n(No Anon)',
            'Target\n(50% overhead)',
            'Target\n(100% overhead)',
            'Hierarchical\n+ Anonymization\n(Projected)'
        ]
        
        tdx_only = self.tdx['evidence_collection_ms']
        hierarchical_no_anon = self.sgx['combined_ms'] + tdx_only + 3.0  # 3ms for network+binding
        target_50 = tdx_only * 1.5
        target_100 = tdx_only * 2.0
        
        # Assume anonymization takes 10ms (conservative estimate)
        hierarchical_with_anon = hierarchical_no_anon + 10.0
        
        times = [tdx_only, hierarchical_no_anon, target_50, target_100, hierarchical_with_anon]
        colors = ['#95a5a6', '#3498db', '#f39c12', '#e67e22', '#2ecc71']
        
        bars = ax.bar(scenarios, times, color=colors, alpha=0.8, edgecolor='black', linewidth=1.5)
        
        ax.set_ylabel('Total Latency (ms)')
        ax.set_title('Performance Budget Analysis: From Baseline to Full Hierarchical Protocol')
        ax.grid(axis='y', alpha=0.3)
        
        # Add value labels
        for bar, time in zip(bars, times):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{time:.1f} ms',
                   ha='center', va='bottom', fontsize=9, fontweight='bold')
        
        # Add comparison annotations
        overhead_no_anon = ((hierarchical_no_anon - tdx_only) / tdx_only) * 100
        overhead_with_anon = ((hierarchical_with_anon - tdx_only) / tdx_only) * 100
        
        ax.text(1, hierarchical_no_anon + 10, f'+{overhead_no_anon:.1f}%',
               ha='center', fontsize=9, color='blue', fontweight='bold')
        ax.text(4, hierarchical_with_anon + 10, f'+{overhead_with_anon:.1f}%',
               ha='center', fontsize=9, color='green', fontweight='bold')
        
        # Add budget indicators
        budget_50 = target_50 - hierarchical_no_anon
        budget_100 = target_100 - hierarchical_no_anon
        
        ax.text(0.02, 0.98, 
               f'Available Budget for Anonymization:\n'
               f'  • 50% target: {budget_50:.1f} ms\n'
               f'  • 100% target: {budget_100:.1f} ms\n'
               f'  • Used (projected): 10 ms\n'
               f'  • Status: {"✓ Within budget" if hierarchical_with_anon < target_100 else "⚠ Over budget"}',
               transform=ax.transAxes, ha='left', va='top',
               bbox=dict(boxstyle='round', facecolor='lightyellow', alpha=0.8),
               fontsize=9, family='monospace')
    
    def print_detailed_analysis(self):
        """Print comprehensive text analysis"""
        print("\n" + "=" * 85)
        print("HIERARCHICAL TEE: COMPREHENSIVE BASELINE ANALYSIS")
        print("=" * 85)
        
        print("\n[1] SGX BASELINE (Inner Layer - Application-Level Isolation)")
        print("-" * 85)
        print(f"  EREPORT Generation:          {self.sgx['ereport_ms']:10.3f} ms")
        print(f"  Quote Preparation:           {self.sgx['quote_prep_ms']:10.3f} ms")
        print(f"  Combined (SGX Layer):        {self.sgx['combined_ms']:10.3f} ms")
        print(f"  Enclave Creation (1-time):   {self.sgx['enclave_creation_ms']:10.3f} ms")
        print(f"  Throughput:                  {self.sgx['throughput']:10,.0f} reports/sec")
        
        print("\n[2] TDX BASELINE (Outer Layer - VM-Level Isolation)")
        print("-" * 85)
        print(f"  Evidence Collection:         {self.tdx['evidence_collection_ms']:10.3f} ms")
        print(f"  Full Attestation (w/ ITA):   {self.tdx['full_attestation_ms']:10.3f} ms")
        print(f"  Network + Verification:      {self.tdx['network_overhead_ms']:10.3f} ms")
        print(f"  Token Size:                  {self.tdx['token_size_bytes']:10,d} bytes")
        print(f"    - Header:                  {self.tdx['header_bytes']:10,d} bytes")
        print(f"    - Payload:                 {self.tdx['payload_bytes']:10,d} bytes")
        print(f"    - Signature:               {self.tdx['signature_bytes']:10,d} bytes")
        
        print("\n[3] PERFORMANCE COMPARISON")
        print("-" * 85)
        speedup = self.tdx['evidence_collection_ms'] / self.sgx['combined_ms']
        print(f"  SGX is {speedup:,.0f}x faster than TDX")
        print(f"  TDX bottleneck: Evidence collection ({self.tdx['evidence_collection_ms']:.1f} ms)")
        print(f"  Network overhead: {self.tdx['network_overhead_ms']:.1f} ms ({self.tdx['network_overhead_ms']/self.tdx['full_attestation_ms']*100:.1f}% of full attestation)")
        
        print("\n[4] HIERARCHICAL COMPOSITION (Estimated)")
        print("-" * 85)
        
        sgx_layer = self.sgx['combined_ms']
        tdx_layer = self.tdx['evidence_collection_ms']
        network_sgx_tdx = 2.0  # SGX server <-> TDX VM
        binding = 1.0
        
        total_no_anon = sgx_layer + tdx_layer + network_sgx_tdx + binding
        overhead_no_anon = total_no_anon - tdx_layer
        overhead_pct_no_anon = (overhead_no_anon / tdx_layer) * 100
        
        print(f"  SGX Layer:                   {sgx_layer:10.3f} ms")
        print(f"  TDX Layer:                   {tdx_layer:10.3f} ms")
        print(f"  Network (SGX↔TDX):           {network_sgx_tdx:10.3f} ms (estimate)")
        print(f"  Cryptographic Binding:       {binding:10.3f} ms (estimate)")
        print(f"  " + "-" * 70)
        print(f"  Total (without anon):        {total_no_anon:10.3f} ms")
        print(f"  Overhead vs TDX-only:        {overhead_no_anon:10.3f} ms (+{overhead_pct_no_anon:.1f}%)")
        
        print("\n[5] ANONYMIZATION BUDGET ANALYSIS")
        print("-" * 85)
        
        target_50 = tdx_layer * 1.5
        target_100 = tdx_layer * 2.0
        budget_50 = target_50 - total_no_anon
        budget_100 = target_100 - total_no_anon
        
        print(f"  Performance Targets:")
        print(f"    50% overhead:              {target_50:10.3f} ms")
        print(f"    100% overhead:             {target_100:10.3f} ms")
        print(f"  ")
        print(f"  Available Budget:")
        print(f"    For 50% target:            {budget_50:10.3f} ms")
        print(f"    For 100% target:           {budget_100:10.3f} ms")
        print(f"  ")
        print(f"  Anonymization Estimates:")
        print(f"    Group signature:           ~5-10 ms (estimate)")
        print(f"    ZKP verification:          ~10-20 ms (estimate)")
        print(f"    Hash-based anonymization:  ~1-2 ms (estimate)")
        
        anon_conservative = 10.0
        total_with_anon = total_no_anon + anon_conservative
        overhead_with_anon = (total_with_anon - tdx_layer) / tdx_layer * 100
        
        print(f"  ")
        print(f"  Projected Total (conservative):")
        print(f"    With anonymization:        {total_with_anon:10.3f} ms")
        print(f"    Total overhead:            +{overhead_with_anon:.1f}%")
        
        if total_with_anon <= target_50:
            status = "✓✓ EXCELLENT - Under 50% target!"
        elif total_with_anon <= target_100:
            status = "✓ GOOD - Under 100% target"
        else:
            status = "⚠ NEEDS OPTIMIZATION"
        
        print(f"    Status:                    {status}")
        
        print("\n[6] KEY RESEARCH INSIGHTS")
        print("-" * 85)
        print(f"  • SGX provides {speedup:.0f}x faster attestation than TDX")
        print(f"  • TDX network overhead is dominant: {self.tdx['network_overhead_ms']:.1f} ms")
        print(f"  • Hierarchical composition adds only ~{overhead_no_anon:.1f} ms")
        print(f"  • Main bottleneck: TDX evidence collection ({tdx_layer:.1f} ms)")
        print(f"  • Generous budget for anonymization: {budget_100:.1f} ms (100% target)")
        print(f"  • Protocol feasibility: HIGH - well within performance targets")
        
        print("\n[7] IMPLEMENTATION PRIORITIES")
        print("-" * 85)
        print("  Phase 1 (This Week):")
        print("    1. Implement SGX REST API on SGX server")
        print("    2. Implement TDX client to call SGX API")
        print("    3. Measure actual network latency")
        print("    4. Implement basic composition (binding)")
        print("  ")
        print("  Phase 2 (Next Week):")
        print("    5. Design anonymization layer")
        print("    6. Implement linkability prevention")
        print("    7. Measure final overhead")
        print("  ")
        print("  Phase 3 (Week 3):")
        print("    8. Comprehensive evaluation")
        print("    9. Security analysis")
        print("   10. Generate paper-ready results")
        
        print("\n[8] EXPECTED CONTRIBUTIONS")
        print("-" * 85)
        print("  • Novel hierarchical TEE attestation protocol")
        print("  • Prevents platform linkability (TDX + SGX)")
        print(f"  • Low overhead: ~{overhead_with_anon:.0f}% vs baseline")
        print("  • Practical: Works with commodity cloud TEEs")
        print("  • Comprehensive evaluation on real hardware")
        
        print("\n" + "=" * 85)
        print(f"Analysis generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 85 + "\n")
        
        # Save to JSON
        results = {
            'sgx_baseline': self.sgx,
            'tdx_baseline': self.tdx,
            'hierarchical_estimates': {
                'sgx_layer_ms': sgx_layer,
                'tdx_layer_ms': tdx_layer,
                'network_ms': network_sgx_tdx,
                'binding_ms': binding,
                'total_without_anon_ms': total_no_anon,
                'overhead_percent_no_anon': overhead_pct_no_anon,
                'anonymization_budget_50pct_ms': budget_50,
                'anonymization_budget_100pct_ms': budget_100,
                'projected_total_with_anon_ms': total_with_anon,
                'projected_overhead_percent': overhead_with_anon
            },
            'timestamp': datetime.now().isoformat()
        }
        
        with open('hierarchical_tee_analysis.json', 'w') as f:
            json.dump(results, f, indent=2)
        
        print("✓ Detailed analysis saved to: hierarchical_tee_analysis.json\n")

if __name__ == "__main__":
    analyzer = HierarchicalTEEAnalysis()
    
    # Print detailed text analysis
    analyzer.print_detailed_analysis()
    
    # Create comprehensive visualizations
    print("Generating comprehensive visualization...")
    analyzer.create_comprehensive_comparison()
    
    print("\n" + "=" * 85)
    print("ANALYSIS COMPLETE!")
    print("=" * 85)
    print("\nGenerated files:")
    print("  • hierarchical_tee_complete_analysis.png")
    print("  • hierarchical_tee_complete_analysis.pdf")
    print("  • hierarchical_tee_analysis.json")
    print("\nReady for implementation phase!")
    print("=" * 85 + "\n")
