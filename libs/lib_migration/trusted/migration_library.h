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
 * migration_library.h
 *
 *  Created on: Jul 4, 2017
 */

#ifndef MIGRATION_LIBRARY_TRUSTED_MIGRATION_LIBRARY_H_
#define MIGRATION_LIBRARY_TRUSTED_MIGRATION_LIBRARY_H_

#include <stdbool.h>
#include <stdint.h>
#include "sgx_tseal.h"
#include "sgx_tae_service.h"

#if defined(__cplusplus)
extern "C" {
#endif

#define MIGR_COUNTER_AMOUNT 256
typedef uint32_t MIGRATION_STATUS;

// Make ocall visible to other functions that want to log data
void migrate_log(const char *fmt, ...);

// Counters

MIGRATION_STATUS sgx_create_migratable_counter(
    uint8_t*  counter_id,
    uint32_t* counter_value
    );
MIGRATION_STATUS sgx_destroy_migratable_counter(uint8_t  counter_id);
MIGRATION_STATUS sgx_increment_migratable_counter(uint8_t  counter_id, uint32_t* counter_value);
MIGRATION_STATUS sgx_read_migratable_counter(uint8_t counter_id, uint32_t* counter_value);

// Sealing
MIGRATION_STATUS sgx_seal_migratable_data(const uint32_t additional_MACtext_length,
        const uint8_t *p_additional_MACtext,
        const uint32_t text2encrypt_length,
        const uint8_t *p_text2encrypt,
        const uint32_t sealed_data_size,
        sgx_sealed_data_t *p_sealed_data);
MIGRATION_STATUS sgx_unseal_migratable_data(const sgx_sealed_data_t *p_sealed_data,
        uint8_t *p_additional_MACtext,
        uint32_t *p_additional_MACtext_length,
        uint8_t *p_decrypted_text,
        uint32_t *p_decrypted_text_length);

/*
 * Operation codes for message exchange between ME and MLib.
 * All codes are from the enclave's POV so the flow is:
 *  - MLib -> ME: OUTGOING
 *  - ME -> MLib: OUTGOING_OK
 *  - ME (old) -> ME (new): OUTGOING
 *  - ME (new) -> ME (old): OUTGOING_DONE
 *  - ME -> MLib(new): INCOMING
 *  - MLib (new)-> ME: INCOMING_DONE
 *
 *  These codes can potentially also be used for recovery
 *  after power transitions:
 *  MLib -> ME: INCOMING could restart sending of migration data
 */
//#define SGX_MIGR_OPCODE_REGISTER      0
//#define SGX_MIGR_OPCODE_REGISTER_DONE 1
#define SGX_MIGR_OPCODE_OUTGOING      2
#define SGX_MIGR_OPCODE_OUTGOING_DONE 3
#define SGX_MIGR_OPCODE_INCOMING      4
#define SGX_MIGR_OPCODE_INCOMING_DONE 5
#define SGX_MIGR_OPCODE_ME_MIGRATION  6
#define SGX_MIGR_OPCODE_ME_MIGRATION_OK 7
#define SGX_MIGR_OPCODE_ME_MIGRATION_DONE 8
#define SGX_MIGR_OPCODE_MIGRATION_NONEXISTENT 0xE0
#define SGX_MIGR_OPCODE_TEST          0xF1


#define SGX_MIGR_INIT_NEW       0
#define SGX_MIGR_INIT_RESTORE   1
#define SGX_MIGR_INIT_MIGRATE   2


// Sets if logging is enabled or disabled
#define LOGGING_ENABLED false

// Error codes

#define SGX_MIGR_MK_ERROR(x)              (0x00011000|(x))

typedef enum _migr_status_t
{
    /* Migration Library has not been initialized */
    SGX_MIGR_ERROR_NOT_INITIALIZED   = SGX_MIGR_MK_ERROR(0x01),

    /* Enclave has been frozen for migration */
    SGX_MIGR_ERROR_FROZEN            = SGX_MIGR_MK_ERROR(0x02),

    /* Enclave is NOT frozen which disables some operations */
    SGX_MIGR_ERROR_NOT_FROZEN        = SGX_MIGR_MK_ERROR(0x03),

    /* Error initialising the migratable counters */
	SGX_MIGR_ERROR_INIT_MC			 = SGX_MIGR_MK_ERROR(0x04),

    /* Migration already in progress, duplicate calls */
	SGX_MIGR_ERROR_MIGRATION_IN_PROGRESS = SGX_MIGR_MK_ERROR(0x05),

    /* The opposing enclave is not trusted */
	SGX_MIGR_ERROR_NOT_TRUSTED       = SGX_MIGR_MK_ERROR(0x06),

    /* Unknown or wrong opcode for this enclave */
	SGX_MIGR_ERROR_WRONG_OPCODE      = SGX_MIGR_MK_ERROR(0x07),

    /* Migratable counter is full (overflow potentially due to offset) */
	SGX_MIGR_ERROR_MC_OVERFLOW       = SGX_MIGR_MK_ERROR(0x08),

    /* Migration data is currently not available on ME */
	SGX_MIGR_ERROR_MIGRATION_OUTSTANDING = SGX_MIGR_MK_ERROR(0x09),


} sgx_migr_status_t;

// Actual data sent over to ME
typedef struct _migration_data {
    uint32_t counters_values[MIGR_COUNTER_AMOUNT];
    bool counters_active[MIGR_COUNTER_AMOUNT];
    sgx_key_128bit_t migration_sealing_key;
} migration_data_t;


#if defined(__cplusplus)
}
#endif

#endif /* MIGRATION_LIBRARY_TRUSTED_MIGRATION_LIBRARY_H_ */
