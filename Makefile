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

Lib_Dir := ./libs
Utils_Dir := ./sgx-utils/libs
Lib_NrtTke := $(Utils_Dir)/lib_tke
Lib_NrtUke := $(Utils_Dir)/lib_uke
Lib_NrtRa := $(Utils_Dir)/lib_nrt_ra
Lib_La := $(Utils_Dir)/lib_la
Lib_Migration := $(Lib_Dir)/lib_migration

Me_Dir := migration_enclave
App_Dir := sample_app

.PHONY: all libs clean cleanall

libs:
	$(MAKE) -C $(Lib_La)
	$(MAKE) -C $(Lib_NrtTke)
	$(MAKE) -C $(Lib_NrtUke)
	$(MAKE) -C $(Lib_NrtRa)
	$(MAKE) -C $(Lib_Migration)

all: libs
	$(MAKE) -C $(Me_Dir)
	$(MAKE) -C $(App_Dir)

clean:
	$(MAKE) -C $(Me_Dir) clean
	$(MAKE) -C $(App_Dir) clean

cleanall: clean
	$(MAKE) -C $(Lib_La) clean
	$(MAKE) -C $(Lib_NrtTke) clean
	$(MAKE) -C $(Lib_NrtUke) clean
	$(MAKE) -C $(Lib_NrtRa) clean
	$(MAKE) -C $(Lib_Migration) clean

tags:
	@rm -f tags
	@ctags --extra=+qf -R -a .
	@ctags --extra=+qf -R -a ~/git/sgx/linux-sgx/sdk
	@ctags --extra=+qf -R -a ~/git/sgx/linux-sgx/common
