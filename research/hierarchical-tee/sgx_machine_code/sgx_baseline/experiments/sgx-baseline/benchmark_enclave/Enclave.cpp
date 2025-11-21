#include "Enclave_t.h"
#include <sgx_report.h>
#include <sgx_utils.h>
#include <sgx_trts.h>
#include <string.h>

// Generate EREPORT for benchmarking
int ecall_generate_report(uint8_t *report_data, size_t report_size, uint8_t *custom_data) {
    if (report_size < sizeof(sgx_report_t)) {
        return -1;
    }
    
    sgx_report_t report;
    sgx_target_info_t target_info = {0};
    sgx_report_data_t report_custom_data = {0};
    
    // Copy custom data into report
    if (custom_data != NULL) {
        memcpy(&report_custom_data, custom_data, 64);
    } else {
        const char* default_data = "SGX-Attestation-Benchmark";
        memcpy(&report_custom_data, default_data, strlen(default_data));
    }
    
    // Generate EREPORT
    sgx_status_t ret = sgx_create_report(&target_info, &report_custom_data, &report);
    
    if (ret != SGX_SUCCESS) {
        return -2;
    }
    
    // Copy report to output
    memcpy(report_data, &report, sizeof(sgx_report_t));
    return 0;
}

// Prepare data for remote attestation quote
int ecall_prepare_quote_data(uint8_t *report_data) {
    if (report_data == NULL) {
        return -1;
    }
    
    // Generate some data to include in quote
    const char* test_data = "Hierarchical-TEE-SGX-Layer-Quote-Data";
    memcpy(report_data, test_data, strlen(test_data));
    
    return 0;
}
