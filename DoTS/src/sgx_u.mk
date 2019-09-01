######## Intel(R) SGX SDK Settings ########
UNTRUSTED_DIR=untrusted
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
        SGX_COMMON_CFLAGS += -O0 -g -DSGX_DEBUG
else
        SGX_COMMON_CFLAGS += -O2
endif

SGX_RA_TLS_ROOT="../deps/sgx-ra-tls"
WOLFSSL_ROOT="../deps/wolfssl"

######## App Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

Wolfssl_C_Extra_Flags := -DWOLFSSL_SGX
Wolfssl_Include_Paths := -I$(WOLFSSL_ROOT)/ \
						 -I$(WOLFSSL_ROOT)/wolfcrypt/

ifeq ($(HAVE_WOLFSSL_TEST), 1)
	Wolfssl_Include_Paths += -I$(WOLFSSL_ROOT)/wolfcrypt/test/
	Wolfssl_C_Extra_Flags += -DHAVE_WOLFSSL_TEST
endif

ifeq ($(HAVE_WOLFSSL_BENCHMARK), 1)
	Wolfssl_Include_Paths += -I$(WOLFSSL_ROOT)/wolfcrypt/benchmark/
	Wolfssl_C_Extra_Flags += -DHAVE_WOLFSSL_BENCHMARK
endif



App_C_Files := $(UNTRUSTED_DIR)/App.c $(UNTRUSTED_DIR)/client-tls.c $(UNTRUSTED_DIR)/server-tls.c $(UNTRUSTED_DIR)/sgxsdk-ra-attester_u.c $(UNTRUSTED_DIR)/ias-ra.c $(UNTRUSTED_DIR)/dns_u.c
App_Include_Paths := $(Wolfssl_Include_Paths) -I$(UNTRUSTED_DIR) -I$(SGX_SDK)/include -I$(SGX_RA_TLS_ROOT) -I../deps/local/include

App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths) $(Wolfssl_C_Extra_Flags)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -L$(SGX_RA_TLS_ROOT)/deps/local/lib -l$(Urts_Library_Name) -lpthread -lssl -lcrypto -lcurl

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
	App_C_Flags += -DNO_IAS
else
	App_Link_Flags += -lsgx_uae_service
endif

App_C_Objects := $(App_C_Files:.c=.o)



ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif


.PHONY: all run

ifeq ($(Build_Mode), HW_RELEASE)
all: App
	@echo "Build App [$(Build_Mode)|$(SGX_ARCH)] success!"
	@echo
	@echo "*********************************************************************************************************************************************************"
	@echo "PLEASE NOTE: In this mode, please sign the Wolfssl_Enclave.so first using Two Step Sign mechanism before you run the app to launch and access the enclave."
	@echo "*********************************************************************************************************************************************************"
	@echo

else
all: App
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/App
	@echo "RUN  =>  App [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

######## App Objects ########

$(UNTRUSTED_DIR)/Wolfssl_Enclave_u.c: $(SGX_EDGER8R) trusted/Wolfssl_Enclave.edl
	@cd $(UNTRUSTED_DIR) && $(SGX_EDGER8R) --untrusted ../trusted/Wolfssl_Enclave.edl --search-path ../trusted --search-path $(SGX_SDK)/include --search-path ../$(SGX_RA_TLS_ROOT)
	@echo "GEN  =>  $@"

$(UNTRUSTED_DIR)/Wolfssl_Enclave_u.o: $(UNTRUSTED_DIR)/Wolfssl_Enclave_u.c
	@echo $(CC) $(App_C_Flags) -c $< -o $@
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(UNTRUSTED_DIR)/%.o: $(UNTRUSTED_DIR)/%.c
	@echo $(CC) $(App_C_Flags) -c $< -o $@
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

App: $(UNTRUSTED_DIR)/Wolfssl_Enclave_u.o $(App_C_Objects)
	@$(CC) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"


.PHONY: clean

clean:
	@rm -f App $(App_C_Objects) $(UNTRUSTED_DIR)/Wolfssl_Enclave_u.* 
