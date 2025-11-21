#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int ecall_generate_report(uint8_t* report_data, size_t report_size, uint8_t* custom_data);
int ecall_prepare_quote_data(uint8_t* report_data);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
