#!/bin/bash
# Create SGX enclave for quote generation benchmarking

echo "Creating quote generation enclave..."

# 1. Enclave EDL
cat > Enclave.edl << 'EDLEOF'
enclave {
    trusted {
        /* Generate EREPORT for quote */
        public int ecall_generate_report_for_quote(
            [out, size=report_size] uint8_t *report_data,
            size_t report_size,
            [in, size=target_info_size] uint8_t *target_info,
            size_t target_info_size,
            [in, size=report_data_size] uint8_t *custom_report_data,
            size_t report_data_size
        );
    };
};
EDLEOF

# 2. Enclave Implementation
cat > Enclave.cpp << 'CPPEOF'
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
CPPEOF

# 3. Enclave Config
cat > Enclave.config.xml << 'XMLEOF'
<EnclaveConfiguration>
  <ProdID>0</ProdID>
  <ISVSVN>0</ISVSVN>
  <StackMaxSize>0x40000</StackMaxSize>
  <HeapMaxSize>0x100000</HeapMaxSize>
  <TCSNum>10</TCSNum>
  <TCSPolicy>1</TCSPolicy>
  <DisableDebug>0</DisableDebug>
  <MiscSelect>0</MiscSelect>
  <MiscMask>0xFFFFFFFF</MiscMask>
</EnclaveConfiguration>
XMLEOF

# 4. Application (Host) with Quote Generation
cat > App.cpp << 'APPCPPEOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sgx_urts.h>
#include <sgx_uae_service.h>
#include <sgx_quote.h>
#include <sgx_dcap_ql_wrapper.h>
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
            printf("  [%d] ✗ Failed to generate EREPORT\n", i+1);
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
            printf("  [%d] ✗ Failed to generate quote: 0x%x\n", i+1, qe3_ret);
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
        
        // Print first quote structure
        printf("\n  First Quote Structure:\n");
        sgx_quote3_t* quote = (sgx_quote3_t*)quote_buffer;
        printf("    Version: %d\n", quote->header.version);
        printf("    ATT Key Type: %d\n", quote->header.att_key_type);
        printf("    QE SVN: %d\n", quote->header.qe_svn);
        printf("    PCE SVN: %d\n", quote->header.pce_svn);
        print_hex("    User Data", quote->report_body.report_data.d, 64);
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
    printf("    Difference:    %d bytes\n", 5934 - (int)quote_size);
    
    if (quote_size < 5934) {
        printf("    SGX is %.1fx smaller than TDX token\n", 5934.0 / quote_size);
    }
    
    return 0;
}

int test_single_quote_detailed(sgx_enclave_id_t eid) {
    printf("\n[3/3] Detailed Single Quote Test...\n");
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
    
    uint8_t* quote_buffer = (uint8_t*)malloc(quote_size);
    uint8_t report[sizeof(sgx_report_t)];
    uint8_t custom_data[64] = "Hierarchical-TEE-Test-Data";
    
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
        printf("  ✗ Failed to generate EREPORT\n");
        free(quote_buffer);
        return -1;
    }
    printf("    ✓ EREPORT generated in %.3f ms\n", ereport_time);
    
    // Generate Quote
    printf("  Step 2: Converting to Quote...\n");
    start = get_time_ms();
    
    qe3_ret = sgx_qe_get_quote((sgx_report_t*)report, quote_size, quote_buffer);
    
    double quote_time = get_time_ms() - start;
    
    if (qe3_ret != SGX_QL_SUCCESS) {
        printf("  ✗ Failed to generate quote: 0x%x\n", qe3_ret);
        free(quote_buffer);
        return -1;
    }
    printf("    ✓ Quote generated in %.3f ms\n", quote_time);
    
    // Parse quote
    sgx_quote3_t* quote = (sgx_quote3_t*)quote_buffer;
    
    printf("\n  Quote Details:\n");
    printf("    Total Size: %u bytes\n", quote_size);
    printf("    Header Size: %zu bytes\n", sizeof(quote->header));
    printf("    Report Body Size: %zu bytes\n", sizeof(quote->report_body));
    printf("    Version: %d\n", quote->header.version);
    printf("    Attestation Key Type: %d\n", quote->header.att_key_type);
    
    print_hex("    MRENCLAVE", quote->report_body.mr_enclave.m, 32);
    print_hex("    MRSIGNER", quote->report_body.mr_signer.m, 32);
    print_hex("    Report Data", quote->report_body.report_data.d, 64);
    
    printf("\n  Performance Summary:\n");
    printf("    EREPORT: %.3f ms\n", ereport_time);
    printf("    Quote:   %.3f ms\n", quote_time);
    printf("    Total:   %.3f ms\n", ereport_time + quote_time);
    
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
        printf("  - Enclave file not found\n");
        printf("  - SGX not properly initialized\n");
        printf("  - Insufficient EPC memory\n");
        return -1;
    }
    printf("✓ Enclave created (EID: %lu)\n", eid);
    
    // Run benchmarks
    int success = benchmark_quote_generation(eid, iterations);
    
    if (success > 0) {
        measure_quote_sizes(eid);
        test_single_quote_detailed(eid);
    }
    
    // Cleanup
    sgx_destroy_enclave(eid);
    
    printf("\n===============================================================\n");
    printf("Benchmark Complete!\n");
    printf("===============================================================\n");
    
    return success > 0 ? 0 : -1;
}
APPCPPEOF

# 5. Makefile
cat > Makefile << 'MAKEFILEEOF'
SGX_SDK ?= $(HOME)/sgxsdk/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
	SGX_COMMON_CFLAGS += -O0 -g
else
	SGX_COMMON_CFLAGS += -O2
endif

Trts_Library_Name := sgx_trts
Service_Library_Name := sgx_tservice
Crypto_Library_Name := sgx_tcrypto
Urts_Library_Name := sgx_urts

App_Name := quote_benchmark
Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so

# App settings
App_Cpp_Files := App.cpp
App_Include_Paths := -I$(SGX_SDK)/include -I/usr/include
App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)
App_Cpp_Flags := $(App_C_Flags) -std=c++11
App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) \
	-lsgx_dcap_ql -lsgx_quote_ex -lpthread

# Enclave settings
Enclave_Cpp_Files := Enclave.cpp
Enclave_Include_Paths := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx
Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++11 -nostdinc++
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
	-L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0

.PHONY: all clean

all: $(App_Name)

Enclave_u.c Enclave_u.h: Enclave.edl
	@$(SGX_EDGER8R) --untrusted Enclave.edl --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

Enclave_t.c Enclave_t.h: Enclave.edl
	@$(SGX_EDGER8R) --trusted Enclave.edl --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

App.o: App.cpp Enclave_u.h
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

Enclave_u.o: Enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(App_Name): App.o Enclave_u.o $(Signed_Enclave_Name)
	@$(CXX) App.o Enclave_u.o -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

Enclave.o: Enclave.cpp Enclave_t.h
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

Enclave_t.o: Enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(Enclave_Name): Enclave.o Enclave_t.o
	@$(CXX) Enclave.o Enclave_t.o -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key Enclave_private.pem -enclave $(Enclave_Name) -out $@ -config Enclave.config.xml
	@echo "SIGN =>  $@"

Enclave_private.pem:
	@openssl genrsa -out $@ -3 3072
	@echo "GEN  =>  $@"

clean:
	@rm -f $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) *.o Enclave_u.* Enclave_t.* Enclave_private.pem
MAKEFILEEOF

echo "✓ Quote benchmark enclave structure created!"
echo ""
echo "To build and run:"
echo "  cd $(pwd)"
echo "  make"
echo "  ./quote_benchmark [iterations]"
