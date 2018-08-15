SGX Migration - support for migrating VMs with enclaves
=======================================================

Introduction
------------

This is a proof-of-concept project providing support to
live migrate VMs that contain SGX enclaves. By default,
after migration the enclave most probably won't function
properly, because its sealing key has changed and its
monotonic counters are gone. This project contains a library
and a migration enclave that allow to move enclave persistent
state from one physical host to another, maintaining SGX
security guarantees.

### Prerequisites

- Install SGX SDK:
  * Download [Intel SGX SDK for Linux](https://github.com/01org/linux-sgx)
  * By default Makefile's expect to have SDK installed in ``/opt/intel/sgxsdk``.
  * If the SDK is in a different directory, change `SGX_SDK` variable in Makefiles.

- Build the 3rd party libraries
  * Clone [sgx-utils](https://github.com/SSGAalto/sgx-utils).
  * Alternatively, use the `git submodule` command to clone the libraries into
    `sgx-utils` directory.

Build
-----

Generate enclave signing keys:

```sh
 $ openssl genrsa -3 3072 >migration_enclave/trusted/migration_enclave_private.pem
 $ openssl genrsa -3 3072 >sample_app/src/enclave/enclave_private.pem
```

Run `make -B all`. That will build libraries in `sgx-utils`,
migration enclave (me_app), and a sample application that
contains a migratable enclave.

Run
---

Run `migration_enclave/me_app --help` and `sample_app/app --help` to
show the list of configurable options and their defaults.

Test the setup with running `me_app` and `sample_app/app -t`.
