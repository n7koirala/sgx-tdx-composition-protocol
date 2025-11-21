#include "Enclave_t.h"
#include <sgx_report.h>
#include <sgx_utils.h>
#include <string.h>

int ecall_generate_report_for_quote(
    uint8_t *report_data,
    size_t report_size,
    uint8_t *target_info,
    size_t target_info_size,
    uint8_t *custom_report_data,
    size_t report_data_size)
{
    if (report_size < sizeof(sgx_report_t)) {
        return -1;
    }
    
    if (target_info_size != sizeof(sgx_target_info_t)) {
        return -2;
    }
    
    sgx_report_t report;
    sgx_report_data_t report_d = {0};
    
    // Copy custom data into report_data (max 64 bytes)
    if (custom_report_data && report_data_size > 0) {
        size_t copy_size = report_data_size > 64 ? 64 : report_data_size;
        memcpy(&report_d, custom_report_data, copy_size);
    }
    
    // Generate EREPORT targeted at Quoting Enclave
    sgx_status_t ret = sgx_create_report(
        (const sgx_target_info_t*)target_info,
        &report_d,
        &report
    );
    
    if (ret != SGX_SUCCESS) {
        return -3;
    }
    
    memcpy(report_data, &report, sizeof(sgx_report_t));
    return 0;
}
