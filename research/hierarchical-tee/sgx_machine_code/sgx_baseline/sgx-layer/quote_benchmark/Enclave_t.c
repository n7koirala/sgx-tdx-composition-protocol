#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


typedef struct ms_ecall_generate_report_for_quote_t {
	int ms_retval;
	uint8_t* ms_report_data;
	size_t ms_report_size;
	uint8_t* ms_target_info;
	size_t ms_target_info_size;
	uint8_t* ms_custom_report_data;
	size_t ms_report_data_size;
} ms_ecall_generate_report_for_quote_t;

static sgx_status_t SGX_CDECL sgx_ecall_generate_report_for_quote(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_generate_report_for_quote_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_generate_report_for_quote_t* ms = SGX_CAST(ms_ecall_generate_report_for_quote_t*, pms);
	ms_ecall_generate_report_for_quote_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_generate_report_for_quote_t), ms, sizeof(ms_ecall_generate_report_for_quote_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_report_data = __in_ms.ms_report_data;
	size_t _tmp_report_size = __in_ms.ms_report_size;
	size_t _len_report_data = _tmp_report_size;
	uint8_t* _in_report_data = NULL;
	uint8_t* _tmp_target_info = __in_ms.ms_target_info;
	size_t _tmp_target_info_size = __in_ms.ms_target_info_size;
	size_t _len_target_info = _tmp_target_info_size;
	uint8_t* _in_target_info = NULL;
	uint8_t* _tmp_custom_report_data = __in_ms.ms_custom_report_data;
	size_t _tmp_report_data_size = __in_ms.ms_report_data_size;
	size_t _len_custom_report_data = _tmp_report_data_size;
	uint8_t* _in_custom_report_data = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_report_data, _len_report_data);
	CHECK_UNIQUE_POINTER(_tmp_target_info, _len_target_info);
	CHECK_UNIQUE_POINTER(_tmp_custom_report_data, _len_custom_report_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_report_data != NULL && _len_report_data != 0) {
		if ( _len_report_data % sizeof(*_tmp_report_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_report_data = (uint8_t*)malloc(_len_report_data)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_report_data, 0, _len_report_data);
	}
	if (_tmp_target_info != NULL && _len_target_info != 0) {
		if ( _len_target_info % sizeof(*_tmp_target_info) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_target_info = (uint8_t*)malloc(_len_target_info);
		if (_in_target_info == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_target_info, _len_target_info, _tmp_target_info, _len_target_info)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_custom_report_data != NULL && _len_custom_report_data != 0) {
		if ( _len_custom_report_data % sizeof(*_tmp_custom_report_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_custom_report_data = (uint8_t*)malloc(_len_custom_report_data);
		if (_in_custom_report_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_custom_report_data, _len_custom_report_data, _tmp_custom_report_data, _len_custom_report_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = ecall_generate_report_for_quote(_in_report_data, _tmp_report_size, _in_target_info, _tmp_target_info_size, _in_custom_report_data, _tmp_report_data_size);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_report_data) {
		if (memcpy_verw_s(_tmp_report_data, _len_report_data, _in_report_data, _len_report_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_report_data) free(_in_report_data);
	if (_in_target_info) free(_in_target_info);
	if (_in_custom_report_data) free(_in_custom_report_data);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[1];
} g_ecall_table = {
	1,
	{
		{(void*)(uintptr_t)sgx_ecall_generate_report_for_quote, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


