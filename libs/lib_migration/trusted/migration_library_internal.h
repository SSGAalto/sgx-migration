/* Copyright (c) 2018 Aalto University
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * migration_library_internal.h
 *
 *  Created on: Jun 22, 2017
 */

#ifndef MIGRATION_LIBRARY_TRUSTED_MIGRATION_LIBRARY_INTERNAL_H_
#define MIGRATION_LIBRARY_TRUSTED_MIGRATION_LIBRARY_INTERNAL_H_


#if defined(__cplusplus)
extern "C" {
#endif

#include "la_dh.h"
#include "migration_library.h"  //Include public migration types for MIGR_COUNTER_AMOUNT

/*
 * seal internal defines.
 * Copied because of a hardcopy of the sealing functions
 * was required due to the key request
 */
#define FLAGS_NON_SECURITY_BITS     (0xFFFFFFFFFFFFC0ULL | SGX_FLAGS_MODE64BIT | SGX_FLAGS_PROVISION_KEY| SGX_FLAGS_EINITTOKEN_KEY)
#define TSEAL_DEFAULT_FLAGSMASK     (~FLAGS_NON_SECURITY_BITS)

#define MISC_NON_SECURITY_BITS      0x0FFFFFFF  /* bit[27:0]: have no security implications */
#define TSEAL_DEFAULT_MISCMASK      (~MISC_NON_SECURITY_BITS)
/* seal internal end */

/*
 * Frozen States: Not frozen and locked
 */
#define SGX_MIGR_STATE_FROZEN_DEFAULT  0x01
#define SGX_MIGR_STATE_FROZEN_LOCKED   0x02

/*
 * Init states: Not initiated and all done
 */
#define SGX_MIGR_STATE_INIT_UNINITIATED 0x10
#define SGX_MIGR_STATE_INIT_DONE        0x11
#define SGX_MIGR_STATE_INIT_AWAITING_MIGRATION 0x12
#define SGX_MIGR_STATE_INIT_FAILURE     0xF0

// Data stored in migration library
typedef struct _migration_library_data {
    uint8_t MIGR_INIT;
    uint8_t MIGR_FROZEN;
    bool MIGR_COUNTERS_ACTIVE[MIGR_COUNTER_AMOUNT];
    sgx_mc_uuid_t MIGR_COUNTERS[MIGR_COUNTER_AMOUNT];
    uint32_t MIGR_COUNTERS_OFFSETS[MIGR_COUNTER_AMOUNT];
    sgx_key_128bit_t MIGR_SEALING_KEY;
} migration_library_data;


/*
 * Global vars used by the library internals
 */
// static struct to store library data
extern migration_library_data MIGR_LIBRARY_DATA;

// local var to hold the pointer to sealed data
extern sgx_sealed_data_t *SEALED_DATA;
extern uint32_t SEALED_DATA_SIZE;

// vars for migration_enclave connection
extern remote_enclave_t ME_INFO;
extern uint32_t *ME_SESSION;

/*
 * Functions used internally of the library.
 * These include:
 * - internal logging
 * - sealing the internal data buffer
 * - functions to communicate with the ME
 */

//TODO: Just for testing
void log_sealing_key(sgx_key_128bit_t k);

// Seal the internal data into the library buffer
MIGRATION_STATUS seal_internal_buffer();

MIGRATION_STATUS ME_establish_connection();
MIGRATION_STATUS ME_close_connection();

MIGRATION_STATUS ME_exchange_message(uint32_t req_message_type,
        migration_data_t *outgoing_migration_data, remote_enclave_t *outgoing_plaintext,
        uint32_t *resp_message_type, migration_data_t* response_migration_data);

MIGRATION_STATUS ME_read_message(uint32_t *resp_message_type,
        migration_data_t* response_migration_data);

MIGRATION_STATUS ME_send_message(uint32_t req_message_type, migration_data_t *outgoing_migration_data);
MIGRATION_STATUS ME_send_migration_data(char* dest_ip, char* dest_port);
MIGRATION_STATUS ME_receive_migration();
MIGRATION_STATUS ME_process_migration_data(uint32_t message_type, migration_data_t *message);


#if defined(__cplusplus)
}
#endif



#endif /* MIGRATION_LIBRARY_TRUSTED_MIGRATION_LIBRARY_INTERNAL_H_ */
