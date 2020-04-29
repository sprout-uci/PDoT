SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1
DEBUG_DOTS ?= 0


##    If linking the switchless library give an error, download the "download_prebuilt.sh" script
## 	  from the linux-sgx Github repo (https://github.com/intel/linux-sgx) and try the following:
##	  -------------------------------------------------------------------------------------------
##    Use the script download_prebuilt.sh inside source code package to download prebuilt binaries to prebuilt folder
##
##    $ ./download_prebuilt.sh
##
##    Copy the mitigation tools from external/toolset to /usr/local/bin and make sure they have execute permission:
##
##      $ sudo cp external/toolset/{as,ld,ld.gold,objdump} /usr/local/bin
##      $ which as ld ld.gold objdump




all:
	$(MAKE) -ef sgx_u.mk all
	$(MAKE) -ef sgx_t.mk all

clean:
	$(MAKE) -ef sgx_u.mk clean
	$(MAKE) -ef sgx_t.mk clean

