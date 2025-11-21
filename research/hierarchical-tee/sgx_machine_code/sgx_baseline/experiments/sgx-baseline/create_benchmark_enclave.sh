#!/bin/bash
# Create SGX benchmarking enclave for attestation measurements

ENCLAVE_DIR="benchmark_enclave"
rm -rf $ENCLAVE_DIR
mkdir -p $ENCLAVE_DIR
cd $ENCLAVE_DIR

echo "Creating SGX benchmark enclave..."

# 1. Create Enclave EDL (Interface Definition)
cat > Enclave.edl << 'EDLEOF'
enclave {
    trusted {
        /* Generate EREPORT (local attestation) */
        public int ecall_generate_report(
            [out, size=report_size] uint8_t *report_data,
            size_t report_size,
            [in, size=64] uint8_t *custom_data
        );
        
        /* Prepare data for quote (remote attestation) */
        public int ecall_prepare_quote_data(
            [out, size=64] uint8_t *report_data
        );
    };
    
    untrusted {
        /* Placeholder for OCALLs if needed */
    };
};
EDLEOF

# 2. Create Enclave Implementation
cat > Enclave.cpp << 'CPPEOF'
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
CPPEOF

# 3. Create Enclave Config
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

# 4. Create Application (Host)
cat > App.cpp << 'APPCPPEOF'
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
APPCPPEOF

# 5. Create Makefile
cat > Makefile << 'MAKEFILEEOF'
SGX_SDK ?= $(HOME)/sgxsdk/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

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
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
	SGX_COMMON_CFLAGS += -O0 -g
else
	SGX_COMMON_CFLAGS += -O2
endif

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif

Crypto_Library_Name := sgx_tcrypto
Urts_Library_Name := sgx_urts

App_Name := benchmark_app
Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so

# App settings
App_Cpp_Files := App.cpp
App_Include_Paths := -I$(SGX_SDK)/include
App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)
App_Cpp_Flags := $(App_C_Flags) -std=c++11
App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread

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

# Edger8r
Enclave_u.c Enclave_u.h: Enclave.edl
	@$(SGX_EDGER8R) --untrusted Enclave.edl --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

Enclave_t.c Enclave_t.h: Enclave.edl
	@$(SGX_EDGER8R) --trusted Enclave.edl --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

# App
App.o: App.cpp Enclave_u.h
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

Enclave_u.o: Enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(App_Name): App.o Enclave_u.o $(Signed_Enclave_Name)
	@$(CXX) App.o Enclave_u.o -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

# Enclave
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

echo "✓ Benchmark enclave structure created!"
echo ""
echo "To build and run:"
echo "  cd $ENCLAVE_DIR"
echo "  make"
echo "  ./benchmark_app [iterations]"
