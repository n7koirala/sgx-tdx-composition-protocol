#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_generate_report_for_quote_t {
	int ms_retval;
	uint8_t* ms_report_data;
	size_t ms_report_size;
	uint8_t* ms_target_info;
	size_t ms_target_info_size;
	uint8_t* ms_custom_report_data;
	size_t ms_report_data_size;
} ms_ecall_generate_report_for_quote_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	0,
	{ NULL },
};
sgx_status_t ecall_generate_report_for_quote(sgx_enclave_id_t eid, int* retval, uint8_t* report_data, size_t report_size, uint8_t* target_info, size_t target_info_size, uint8_t* custom_report_data, size_t report_data_size)
{
	sgx_status_t status;
	ms_ecall_generate_report_for_quote_t ms;
	ms.ms_report_data = report_data;
	ms.ms_report_size = report_size;
	ms.ms_target_info = target_info;
	ms.ms_target_info_size = target_info_size;
	ms.ms_custom_report_data = custom_report_data;
	ms.ms_report_data_size = report_data_size;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

