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
