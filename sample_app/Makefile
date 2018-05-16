#
# Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
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
	SGX_COMMON_CFLAGS += -O0 -g
else
	SGX_COMMON_CFLAGS += -O2
endif

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
	Urts_Library_Name := sgx_urts_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
	Urts_Library_Name := sgx_urts
endif

Crypto_Library_Name := sgx_tcrypto


##############################
###### Custom variables ######
######   and settings   ######
##############################
# some variables we need for this project:
IncludeFolder := ../include

Lib_Dir := ../libs
Lib_La := $(Lib_Dir)/lib_la
Lib_Migration := $(Lib_Dir)/lib_migration

LATrusted_Link := -L$(Lib_La) -ltla
LAUnTrusted_Link := -L$(Lib_La) -lula
MigrationTrusted_Link := -L$(Lib_Migration) -lmigration

# Modify this Block according to your needs:
#Folders for generated files
GeneratedTrusted := ./generated
GeneratedUntrusted := ./generated
# EDL Filename without extension!
EdlFilename := enclave

# Folder of the app and enclave code (All cpp code in here gets linked)
App_Folder := ./src/app
Enclave_Folder := ./src/enclave

# Default config name is <edlname>.config.xml residing in the trusted folder of the project -- Adjust this if you need
Enclave_Config_File := $(Enclave_Folder)/$(EdlFilename:=.config.xml)

# Default key name is <edlname>_private.pem residing in the trusted folder of the project -- Adjust this if you need
Enclave_Key_File := $(Enclave_Folder)/$(EdlFilename:=_private.pem)

# Default script file name is <edlname>.lds residing in the trusted folder of the project -- Adjust this if you need
Enclave_Lds_File := $(Enclave_Folder)/$(EdlFilename:=.lds)

# Common include folders for both trusted and untrusted part
CommonIncludes := -I$(IncludeFolder) -I$(Lib_La) -I$(Lib_Migration)/trusted

# Compile name of the app
App_Name := app
# Additional Include directories for app (add as "-Ifile")
App_Includes := -I$(GeneratedUntrusted)
# Additional Libraries for app (add as -L or -l respectively)
App_Libraries := $(LAUnTrusted_Link) -lboost_system -lboost_program_options

# Same for enclave 
Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Includes := -I$(GeneratedTrusted)
Enclave_Libraries := $(LATrusted_Link) $(MigrationTrusted_Link)


##############################
######## App settings ########
##############################
# Theoretically, this should not require any adjustments (as long as all cpp files are in the app folder)
App_Cpp_Files := $(wildcard $(App_Folder)/*.cpp)
App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)
App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes -I$(SGX_SDK)/include $(App_Includes) $(CommonIncludes)

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

App_Cpp_Flags := $(App_C_Flags) -std=c++11
App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) $(App_Libraries) -pthread

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

##############################
###### Enclave Settings ######
##############################
# Theoretically, this should not require any adjustments (as long as all cpp files are in the enclave folder)
Enclave_Cpp_Files := $(wildcard $(Enclave_Folder)/*.cpp)
Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)
Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport $(CommonIncludes) $(Enclave_Includes)
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++11 -nostdinc++

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -lsgx_tkey_exchange -l$(Crypto_Library_Name) -l$(Service_Library_Name) $(Enclave_Libraries) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=$(Enclave_Lds_File) 



ifeq ($(SGX_MODE), HW)
ifeq ($(SGX_DEBUG), 1)
Build_Mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_PRERELEASE
else
	Build_Mode = HW_RELEASE
endif
else
ifeq ($(SGX_DEBUG), 1)
Build_Mode = SIM_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = SIM_PRERELEASE
else
	Build_Mode = SIM_RELEASE
endif
endif


.PHONY: all run

ifeq ($(Build_Mode), HW_RELEASE)
all: $(App_Name) $(Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(App_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: $(App_Name) $(Signed_Enclave_Name)
ifeq ($(Build_Mode), HW_DEBUG)
	@echo "The project has been built in debug hardware mode."
else ifeq ($(Build_Mode), SIM_DEBUG)
	@echo "The project has been built in debug simulation mode."
else ifeq ($(Build_Mode), HW_PRERELEASE)
	@echo "The project has been built in pre-release hardware mode."
else ifeq ($(Build_Mode), SIM_PRERELEASE)
	@echo "The project has been built in pre-release simulation mode."
else
	@echo "The project has been built in release simulation mode."
endif
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(App_Name)  
	@echo "RUN  =>  $(App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif



######## Edger8r #########
$(GeneratedUntrusted)/$(EdlFilename:=_u.c) $(GeneratedTrusted)/$(EdlFilename:=_t.c): $(SGX_EDGER8R) $(Enclave_Folder)/$(EdlFilename:=.edl)
	$(SGX_EDGER8R) $(EdlFilename:=.edl) \
		--search-path $(App_Folder) \
		--search-path $(Enclave_Folder) \
		--search-path $(Lib_La) \
		--search-path $(Lib_Migration) \
		--search-path $(SGX_SDK)/include \
		--trusted-dir $(GeneratedTrusted) \
		--untrusted-dir $(GeneratedUntrusted)
	@echo "GEN  =>  $@"


######## App Objects #########
$(GeneratedUntrusted)/$(EdlFilename:=_u.o): $(GeneratedUntrusted)/$(EdlFilename:=_u.c)
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(App_Folder)/%.o: $(App_Folder)/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Name): $(GeneratedUntrusted)/$(EdlFilename:=_u.o) $(App_Cpp_Objects)
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

######## Enclave Objects ########
$(GeneratedTrusted)/$(EdlFilename:=_t.o): $(GeneratedTrusted)/$(EdlFilename:=_t.c)
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(Enclave_Folder)/%.o: $(Enclave_Folder)/%.cpp
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Enclave_Name): $(GeneratedTrusted)/$(EdlFilename:=_t.o) $(Enclave_Cpp_Objects)
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key $(Enclave_Key_File) -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

.PHONY: clean

clean:
	@rm -f $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_Cpp_Objects) $(Enclave_Cpp_Objects) $(GeneratedTrusted)/*_t.* $(GeneratedUntrusted)/*_u.*
	if test -d $(GeneratedTrusted); then rmdir --ignore-fail-on-non-empty $(GeneratedTrusted); fi
	if test -d $(GeneratedUntrusted); then rmdir --ignore-fail-on-non-empty $(GeneratedUntrusted); fi
