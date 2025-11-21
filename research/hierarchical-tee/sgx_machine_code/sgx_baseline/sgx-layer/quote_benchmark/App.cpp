#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sgx_urts.h>
#include <sgx_quote_3.h>
#include <sgx_dcap_ql_wrapper.h>
#include <sgx_ql_quote.h>
#include <sys/time.h>
#include "Enclave_u.h"

#define ENCLAVE_FILE "enclave.signed.so"

double get_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

void print_hex(const char* label, uint8_t* data, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < (len < 32 ? len : 32); i++) {
        printf("%02x", data[i]);
    }
    if (len > 32) printf("...");
    printf("\n");
}

int benchmark_quote_generation(sgx_enclave_id_t eid, int iterations) {
    printf("\n[1/3] Benchmarking SGX Quote Generation (%d iterations)...\n", iterations);
    printf("---------------------------------------------------------------\n");
    
    double total_ereport_time = 0;
    double total_quote_time = 0;
    double total_end_to_end = 0;
    int successful = 0;
    
    // Get target info for Quoting Enclave
    sgx_target_info_t qe_target_info;
    uint32_t quote_size = 0;
    
    // Initialize quote library
    quote3_error_t qe3_ret = sgx_qe_get_target_info(&qe_target_info);
    if (qe3_ret != SGX_QL_SUCCESS) {
        printf("  ✗ Failed to get QE target info: 0x%x\n", qe3_ret);
        printf("  Note: DCAP may not be fully configured\n");
        printf("  Possible issues:\n");
        printf("    - PCCS not accessible\n");
        printf("    - AESM service not running\n");
        printf("    - Quote provider library not properly installed\n");
        return -1;
    }
    
    printf("  ✓ Quote Provider initialized\n");
    
    // Get quote size
    qe3_ret = sgx_qe_get_quote_size(&quote_size);
    if (qe3_ret != SGX_QL_SUCCESS) {
        printf("  ✗ Failed to get quote size: 0x%x\n", qe3_ret);
        return -1;
    }
    
    printf("  ✓ Quote size: %u bytes\n\n", quote_size);
    
    uint8_t* quote_buffer = (uint8_t*)malloc(quote_size);
    if (!quote_buffer) {
        printf("  ✗ Failed to allocate quote buffer\n");
        return -1;
    }
    
    // Benchmark loop
    for (int i = 0; i < iterations; i++) {
        double iter_start = get_time_ms();
        
        // Step 1: Generate EREPORT inside enclave
        uint8_t report[sizeof(sgx_report_t)];
        uint8_t custom_data[64] = {0};
        snprintf((char*)custom_data, 64, "Iteration-%d", i);
        
        double ereport_start = get_time_ms();
        
        int enclave_ret;
        sgx_status_t ret = ecall_generate_report_for_quote(
            eid,
            &enclave_ret,
            report,
            sizeof(report),
            (uint8_t*)&qe_target_info,
            sizeof(qe_target_info),
            custom_data,
            64
        );
        
        double ereport_end = get_time_ms();
        
        if (ret != SGX_SUCCESS || enclave_ret != 0) {
            if (i == 0) {
                printf("  [%d] ✗ Failed to generate EREPORT: SGX=0x%x, Enclave=%d\n", 
                       i+1, ret, enclave_ret);
            }
            continue;
        }
        
        // Step 2: Convert EREPORT to Quote using Quoting Enclave
        double quote_start = get_time_ms();
        
        qe3_ret = sgx_qe_get_quote(
            (sgx_report_t*)report,
            quote_size,
            quote_buffer
        );
        
        double quote_end = get_time_ms();
        double iter_end = get_time_ms();
        
        if (qe3_ret != SGX_QL_SUCCESS) {
            if (i == 0) {
                printf("  [%d] ✗ Failed to generate quote: 0x%x\n", i+1, qe3_ret);
            }
            continue;
        }
        
        successful++;
        
        double ereport_time = ereport_end - ereport_start;
        double quote_time = quote_end - quote_start;
        double end_to_end_time = iter_end - iter_start;
        
        total_ereport_time += ereport_time;
        total_quote_time += quote_time;
        total_end_to_end += end_to_end_time;
        
        if ((i + 1) % 20 == 0) {
            printf("  Progress: %d/%d (successes: %d)\n", i+1, iterations, successful);
        }
    }
    
    printf("\n  Results Summary:\n");
    printf("  ---------------\n");
    printf("  Successful: %d/%d\n", successful, iterations);
    
    if (successful > 0) {
        printf("  Average EREPORT time:    %.3f ms\n", total_ereport_time / successful);
        printf("  Average Quote time:      %.3f ms\n", total_quote_time / successful);
        printf("  Average End-to-End:      %.3f ms\n", total_end_to_end / successful);
        printf("  Quote size:              %u bytes\n", quote_size);
        
        // Parse and print quote header (first quote only)
        printf("\n  Quote Structure (first quote):\n");
        // Use generic byte parsing instead of sgx_quote3_t structure
        printf("    Version: %u\n", *(uint16_t*)quote_buffer);
        printf("    Quote size: %u bytes\n", quote_size);
        print_hex("    Quote header", quote_buffer, 48);
    }
    
    free(quote_buffer);
    return successful;
}

int measure_quote_sizes(sgx_enclave_id_t eid) {
    printf("\n[2/3] Measuring Quote Sizes...\n");
    printf("---------------------------------------------------------------\n");
    
    sgx_target_info_t qe_target_info;
    uint32_t quote_size = 0;
    
    quote3_error_t qe3_ret = sgx_qe_get_target_info(&qe_target_info);
    if (qe3_ret != SGX_QL_SUCCESS) {
        printf("  ✗ Failed to get QE target info\n");
        return -1;
    }
    
    qe3_ret = sgx_qe_get_quote_size(&quote_size);
    if (qe3_ret != SGX_QL_SUCCESS) {
        printf("  ✗ Failed to get quote size\n");
        return -1;
    }
    
    printf("  SGX Quote Size: %u bytes\n", quote_size);
    
    // Compare with TDX
    printf("\n  Comparison with TDX:\n");
    printf("    SGX Quote:     %u bytes\n", quote_size);
    printf("    TDX Token:     5934 bytes (from your baseline)\n");
    printf("    TDX Evidence:  11469 bytes (raw output)\n");
    
    if (quote_size < 5934) {
        printf("    SGX quote is %.1fx smaller than TDX token\n", 5934.0 / quote_size);
    } else {
        printf("    SGX quote is %.1fx larger than TDX token\n", (float)quote_size / 5934.0);
    }
    
    // Hierarchical estimate
    uint32_t hierarchical_size = quote_size + 5934 + 200; // SGX + TDX + binding
    printf("\n  Hierarchical Protocol Estimate:\n");
    printf("    SGX quote:     %u bytes\n", quote_size);
    printf("    TDX token:     5934 bytes\n");
    printf("    Binding data:  ~200 bytes (estimate)\n");
    printf("    Total:         ~%u bytes\n", hierarchical_size);
    
    return 0;
}

int test_single_quote_detailed(sgx_enclave_id_t eid) {
    printf("\n[3/3] Detailed Single Quote Test...\n");
    printf("---------------------------------------------------------------\n");
    
    sgx_target_info_t qe_target_info;
    uint32_t quote_size = 0;
    
    quote3_error_t qe3_ret = sgx_qe_get_target_info(&qe_target_info);
    if (qe3_ret != SGX_QL_SUCCESS) {
        printf("  ✗ Failed to get QE target info: 0x%x\n", qe3_ret);
        return -1;
    }
    
    qe3_ret = sgx_qe_get_quote_size(&quote_size);
    if (qe3_ret != SGX_QL_SUCCESS) {
        printf("  ✗ Failed to get quote size: 0x%x\n", qe3_ret);
        return -1;
    }
    
    uint8_t* quote_buffer = (uint8_t*)malloc(quote_size);
    if (!quote_buffer) {
        printf("  ✗ Failed to allocate quote buffer\n");
        return -1;
    }
    
    uint8_t report[sizeof(sgx_report_t)];
    uint8_t custom_data[64] = "Hierarchical-TEE-SGX-Quote-Test";
    
    // Generate EREPORT
    printf("  Step 1: Generating EREPORT...\n");
    double start = get_time_ms();
    
    int enclave_ret;
    sgx_status_t ret = ecall_generate_report_for_quote(
        eid, &enclave_ret,
        report, sizeof(report),
        (uint8_t*)&qe_target_info, sizeof(qe_target_info),
        custom_data, 64
    );
    
    double ereport_time = get_time_ms() - start;
    
    if (ret != SGX_SUCCESS || enclave_ret != 0) {
        printf("  ✗ Failed to generate EREPORT: SGX=0x%x, Enclave=%d\n", ret, enclave_ret);
        free(quote_buffer);
        return -1;
    }
    printf("    ✓ EREPORT generated in %.3f ms\n", ereport_time);
    
    // Generate Quote
    printf("  Step 2: Converting to Quote (via Quoting Enclave)...\n");
    start = get_time_ms();
    
    qe3_ret = sgx_qe_get_quote((sgx_report_t*)report, quote_size, quote_buffer);
    
    double quote_time = get_time_ms() - start;
    
    if (qe3_ret != SGX_QL_SUCCESS) {
        printf("  ✗ Failed to generate quote: 0x%x\n", qe3_ret);
        free(quote_buffer);
        return -1;
    }
    printf("    ✓ Quote generated in %.3f ms\n", quote_time);
    
    // Print quote information
    printf("\n  Quote Details:\n");
    printf("    Total Size: %u bytes\n", quote_size);
    printf("    Version: %u\n", *(uint16_t*)quote_buffer);
    
    // Print some quote data
    print_hex("    Quote header", quote_buffer, 48);
    print_hex("    Report body (partial)", quote_buffer + 48, 64);
    
    printf("\n  Performance Summary:\n");
    printf("    EREPORT generation:     %.3f ms\n", ereport_time);
    printf("    Quote generation (QE):  %.3f ms\n", quote_time);
    printf("    Total:                  %.3f ms\n", ereport_time + quote_time);
    
    printf("\n  For Hierarchical Protocol:\n");
    printf("    SGX layer time:  %.3f ms (this measurement)\n", ereport_time + quote_time);
    printf("    TDX layer time:  199.75 ms (from your baseline)\n");
    printf("    Estimated total: %.2f ms\n", ereport_time + quote_time + 199.75);
    printf("    Added overhead:  +%.1f%%\n", 
           ((ereport_time + quote_time) / 199.75) * 100.0);
    
    free(quote_buffer);
    return 0;
}

int main(int argc, char* argv[]) {
    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = {0};
    int updated = 0;
    
    int iterations = 100;
    if (argc > 1) {
        iterations = atoi(argv[1]);
        if (iterations <= 0 || iterations > 1000) {
            iterations = 100;
        }
    }
    
    printf("===============================================================\n");
    printf("SGX Remote Attestation Benchmark (Quote Generation)\n");
    printf("===============================================================\n");
    
    // Create enclave
    printf("\nInitializing enclave...\n");
    sgx_status_t ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, 
                                          &token, &updated, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("✗ Failed to create enclave: 0x%x\n", ret);
        printf("\nPossible reasons:\n");
        printf("  - Enclave file not found: %s\n", ENCLAVE_FILE);
        printf("  - SGX not properly initialized\n");
        printf("  - Insufficient EPC memory\n");
        printf("  - AESM service not running\n");
        return -1;
    }
    printf("✓ Enclave created (EID: %lu)\n", eid);
    
    // Run benchmarks
    int success = benchmark_quote_generation(eid, iterations);
    
    if (success > 0) {
        measure_quote_sizes(eid);
        test_single_quote_detailed(eid);
    } else {
        printf("\n⚠ Quote generation failed.\n");
        printf("This may be due to PCCS configuration issues.\n");
        printf("You can still proceed with hierarchical design using estimates.\n");
    }
    
    // Cleanup
    sgx_destroy_enclave(eid);
    
    printf("\n===============================================================\n");
    if (success > 0) {
        printf("✓ Benchmark Complete!\n");
    } else {
        printf("⚠ Benchmark completed with errors\n");
        printf("Check PCCS configuration: /etc/sgx_default_qcnl.conf\n");
    }
    printf("===============================================================\n");
    
    return success > 0 ? 0 : -1;
}
