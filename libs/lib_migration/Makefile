#
# Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

# Copyright (c) 2018 Aalto University
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1

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



##################################
######## Library Settings ########
########    Modify here   ########
##################################
# Custom variables
IncludeFolder := ../../common/include

Lib_Dir := ../../sgx-utils/libs
Lib_La := $(Lib_Dir)/lib_la
LATrusted_Link := -L$(Lib_La) -ltla
LAUnTrusted_Link := -L$(Lib_La) -lula

# Modify this Block according to your needs:
# EDL Filename without extension!
LibEdlFilename := lib_migration

# Common include folders for both trusted and untrusted
CommonIncludes := -I$(IncludeFolder) -I$(Lib_La)

# Folders for code and generated code
TrustLib_Folder := ./trusted
GeneratedTrusted := ./generated
GeneratedUntrusted := ./generated

# Name and includes of trusted part
TrustLib_Name := libmigration.a
TrustLib_Additional_Includes := -I$(GeneratedTrusted) -I$(Lib_La)/trusted
TrustLib_Libraries := $(LATrusted_Link)


############
# End modify
############

# This Block should be generic enough to not need modification
TrustLib_Cpp_Files := $(wildcard $(TrustLib_Folder)/*.cpp)
TrustLib_Cpp_Objects := $(TrustLib_Cpp_Files:.cpp=.o)
TrustLib_Include_Paths := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx -I$(SGX_SDK)/include/epid $(CommonIncludes) $(TrustLib_Additional_Includes) -I./$(TrustLib_Folder)
TrustLib_Compile_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector  $(TrustLib_Include_Paths)
TrustLib_Compile_Cxx_Flags :=  -std=c++11 -nostdinc++

# End Block

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Common_Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) $(TrustLib_Libraries) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0

.PHONY: all
all: $(TrustLib_Name)

######## Library Objects ########

$(GeneratedTrusted)/$(LibEdlFilename:=_t.c) \
$(GeneratedTrusted)/$(LibEdlFilename:=_t.h) \
$(GeneratedUntrusted)/$(LibEdlFilename:=_u.c) \
$(GeneratedUntrusted)/$(LibEdlFilename:=_u.h): $(SGX_EDGER8R) $(LibEdlFilename:=.edl)
	$(SGX_EDGER8R) $(LibEdlFilename:=.edl) --search-path $(SGX_SDK)/include --search-path $(Lib_La) --trusted-dir $(GeneratedTrusted) --untrusted-dir $(GeneratedUntrusted)
	@echo "GEN  =>  $@"

$(GeneratedTrusted)/$(LibEdlFilename:=_t.o): $(GeneratedTrusted)/$(LibEdlFilename:=_t.c)
	@$(CC) $(TrustLib_Compile_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(TrustLib_Folder)/%.o: $(TrustLib_Folder)/%.cpp $(GeneratedTrusted)/$(LibEdlFilename:=_t.h)
	@$(CXX) $(TrustLib_Compile_Flags) $(TrustLib_Compile_Cxx_Flags) -c $< -o $@ $(Common_Enclave_Link_Flags)
	@echo "CXX   <= $<"

$(TrustLib_Name): $(GeneratedTrusted)/$(LibEdlFilename:=_t.o) $(TrustLib_Cpp_Objects)
	@$(AR) rcs $@ $^
	@echo "GEN  =>  $@"

######## Clean ########
.PHONY: clean

clean:
	@rm -rf *.a $(TrustLib_Folder)/*.o $(GeneratedTrusted)/*_t.* $(GeneratedUntrusted)/*_u.*
	if test -d $(GeneratedTrusted); then rmdir --ignore-fail-on-non-empty $(GeneratedTrusted); fi
	if test -d $(GeneratedUntrusted); then rmdir --ignore-fail-on-non-empty $(GeneratedUntrusted); fi
