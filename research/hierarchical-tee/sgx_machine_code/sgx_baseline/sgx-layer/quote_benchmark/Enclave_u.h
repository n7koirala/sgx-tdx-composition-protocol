#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t ecall_generate_report_for_quote(sgx_enclave_id_t eid, int* retval, uint8_t* report_data, size_t report_size, uint8_t* target_info, size_t target_info_size, uint8_t* custom_report_data, size_t report_data_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
