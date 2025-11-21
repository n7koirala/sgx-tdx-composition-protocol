#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_generate_report_t {
	int ms_retval;
	uint8_t* ms_report_data;
	size_t ms_report_size;
	uint8_t* ms_custom_data;
} ms_ecall_generate_report_t;

typedef struct ms_ecall_prepare_quote_data_t {
	int ms_retval;
	uint8_t* ms_report_data;
} ms_ecall_prepare_quote_data_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	0,
	{ NULL },
};
sgx_status_t ecall_generate_report(sgx_enclave_id_t eid, int* retval, uint8_t* report_data, size_t report_size, uint8_t* custom_data)
{
	sgx_status_t status;
	ms_ecall_generate_report_t ms;
	ms.ms_report_data = report_data;
	ms.ms_report_size = report_size;
	ms.ms_custom_data = custom_data;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_prepare_quote_data(sgx_enclave_id_t eid, int* retval, uint8_t* report_data)
{
	sgx_status_t status;
	ms_ecall_prepare_quote_data_t ms;
	ms.ms_report_data = report_data;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

