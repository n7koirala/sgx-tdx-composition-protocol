#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sgx_urts.h>
#include <sgx_uae_service.h>
#include <sys/time.h>
#include "Enclave_u.h"

#define ENCLAVE_FILE "enclave.signed.so"
#define MAX_ITERATIONS 1000

// Get current time in milliseconds
double get_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

// Benchmark EREPORT generation
void benchmark_ereport_generation(sgx_enclave_id_t eid, int iterations) {
    printf("\n[1/3] Benchmarking EREPORT Generation (%d iterations)...\n", iterations);
    
    uint8_t report[sizeof(sgx_report_t)];
    uint8_t custom_data[64] = {0};
    snprintf((char*)custom_data, 64, "Benchmark-Data-%d", iterations);
    
    double start = get_time_ms();
    
    int successful = 0;
    for (int i = 0; i < iterations; i++) {
        int enclave_ret;
        sgx_status_t ret = ecall_generate_report(
            eid, 
            &enclave_ret,
            report, 
            sizeof(report),
            custom_data
        );
        
        if (ret == SGX_SUCCESS && enclave_ret == 0) {
            successful++;
        }
    }
    
    double end = get_time_ms();
    double elapsed = end - start;
    double avg = elapsed / iterations;
    
    printf("  Total time: %.2f ms\n", elapsed);
    printf("  Average per EREPORT: %.3f ms\n", avg);
    printf("  Successful: %d/%d\n", successful, iterations);
    printf("  Throughput: %.2f reports/sec\n", 1000.0 / avg);
}

// Benchmark quote preparation
void benchmark_quote_preparation(sgx_enclave_id_t eid, int iterations) {
    printf("\n[2/3] Benchmarking Quote Preparation (%d iterations)...\n", iterations);
    
    uint8_t report_data[64];
    
    double start = get_time_ms();
    
    int successful = 0;
    for (int i = 0; i < iterations; i++) {
        int enclave_ret;
        sgx_status_t ret = ecall_prepare_quote_data(eid, &enclave_ret, report_data);
        
        if (ret == SGX_SUCCESS && enclave_ret == 0) {
            successful++;
        }
    }
    
    double end = get_time_ms();
    double elapsed = end - start;
    double avg = elapsed / iterations;
    
    printf("  Total time: %.2f ms\n", elapsed);
    printf("  Average per preparation: %.3f ms\n", avg);
    printf("  Successful: %d/%d\n", successful, iterations);
}

// Measure enclave creation overhead
void measure_enclave_creation(int iterations) {
    printf("\n[3/3] Measuring Enclave Creation Overhead (%d iterations)...\n", iterations);
    
    sgx_launch_token_t token = {0};
    int updated = 0;
    
    double total_create = 0.0;
    double total_destroy = 0.0;
    
    for (int i = 0; i < iterations; i++) {
        sgx_enclave_id_t eid = 0;
        
        // Measure creation
        double start_create = get_time_ms();
        sgx_status_t ret = sgx_create_enclave(
            ENCLAVE_FILE, 
            SGX_DEBUG_FLAG, 
            &token, 
            &updated, 
            &eid, 
            NULL
        );
        double end_create = get_time_ms();
        
        if (ret != SGX_SUCCESS) {
            printf("  Failed to create enclave: 0x%x\n", ret);
            continue;
        }
        
        total_create += (end_create - start_create);
        
        // Measure destruction
        double start_destroy = get_time_ms();
        sgx_destroy_enclave(eid);
        double end_destroy = get_time_ms();
        
        total_destroy += (end_destroy - start_destroy);
    }
    
    double avg_create = total_create / iterations;
    double avg_destroy = total_destroy / iterations;
    
    printf("  Average creation time: %.3f ms\n", avg_create);
    printf("  Average destruction time: %.3f ms\n", avg_destroy);
    printf("  Total enclave overhead: %.3f ms\n", avg_create + avg_destroy);
}

int main(int argc, char *argv[]) {
    sgx_enclave_id_t eid = 0;
    sgx_status_t ret = SGX_SUCCESS;
    sgx_launch_token_t token = {0};
    int updated = 0;
    
    int iterations = 100;
    if (argc > 1) {
        iterations = atoi(argv[1]);
        if (iterations <= 0 || iterations > MAX_ITERATIONS) {
            printf("Invalid iterations. Using default: 100\n");
            iterations = 100;
        }
    }
    
    printf("======================================================\n");
    printf("SGX Attestation Baseline Benchmark\n");
    printf("======================================================\n");
    
    // Create enclave
    printf("\nInitializing enclave...\n");
    ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("Failed to create enclave: 0x%x\n", ret);
        return -1;
    }
    printf("✓ Enclave created (EID: %lu)\n", eid);
    
    // Run benchmarks
    benchmark_ereport_generation(eid, iterations);
    benchmark_quote_preparation(eid, iterations);
    
    // Destroy enclave
    sgx_destroy_enclave(eid);
    
    // Measure creation overhead
    measure_enclave_creation(10);
    
    printf("\n======================================================\n");
    printf("Benchmark Complete!\n");
    printf("======================================================\n");
    
    return 0;
}
