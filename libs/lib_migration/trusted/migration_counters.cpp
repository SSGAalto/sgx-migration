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
    Migratable counter functions
*/
#include "sgx_tae_service.h" // For mc defines
#include "sgx_trts.h"        // For is_within_enclave functions
#include "string.h"

#include "migration_library.h"
#include "migration_library_internal.h"

/* create a monotonic migratable counter using default policy SIGNER and default attribute_mask */
MIGRATION_STATUS sgx_create_migratable_counter(
    uint8_t*  counter_id,
    uint32_t* counter_value)
{
    if(MIGR_LIBRARY_DATA.MIGR_FROZEN != SGX_MIGR_STATE_FROZEN_DEFAULT){
        return SGX_MIGR_ERROR_FROZEN;
    }

    if(MIGR_LIBRARY_DATA.MIGR_INIT != SGX_MIGR_STATE_INIT_DONE){
        return SGX_MIGR_ERROR_NOT_INITIALIZED;
    }

    /* Choose empty array index */
    bool found;
    for(int i = 0; i < MIGR_COUNTER_AMOUNT; i++)
    {
        // If the field is empty (counter index is false -> unused) -> use it for new counter
        if(!MIGR_LIBRARY_DATA.MIGR_COUNTERS_ACTIVE[i]) {
            *counter_id = i;
            found = true;
            break;
        }
    }
    if(!found){
        // Counter limit exceeded, return error
        return SGX_ERROR_MC_OVER_QUOTA;
    }

    // Call default sgx function
    // It already automatically saves
    MIGRATION_STATUS ret;
    ret = sgx_create_monotonic_counter(
        &(MIGR_LIBRARY_DATA.MIGR_COUNTERS[*counter_id]),
        counter_value);

    if(ret == SGX_SUCCESS){
        //migrate_log("[ENCLAVE] [MLib] [CREATE_COUNTER] Created empty counter at ID:%i\n", *counter_id);

        // Update active counters array
        MIGR_LIBRARY_DATA.MIGR_COUNTERS_ACTIVE[*counter_id] = true;

        // Update sealed data with new counter and active array
        ret = seal_internal_buffer();
    }

    return ret;
}

/* destroy a specified monotonic counter */
MIGRATION_STATUS sgx_destroy_migratable_counter(uint8_t  counter_id){
    if(MIGR_LIBRARY_DATA.MIGR_FROZEN != SGX_MIGR_STATE_FROZEN_DEFAULT){
        return SGX_MIGR_ERROR_FROZEN;
    }

    if(MIGR_LIBRARY_DATA.MIGR_INIT != SGX_MIGR_STATE_INIT_DONE){
        return SGX_MIGR_ERROR_NOT_INITIALIZED;
    }

    MIGRATION_STATUS ret;
    ret = sgx_destroy_monotonic_counter(&(MIGR_LIBRARY_DATA.MIGR_COUNTERS[counter_id]));

    if(ret == SGX_SUCCESS){
        /* Delete array entry of counter UUID */
        memset_s(&(MIGR_LIBRARY_DATA.MIGR_COUNTERS[counter_id]), sizeof(sgx_mc_uuid_t),
                 0, sizeof(sgx_mc_uuid_t));

        /* Set active counters entry to false */
        MIGR_LIBRARY_DATA.MIGR_COUNTERS_ACTIVE[counter_id] = false;

        // Update sealed data with deleted counter
        ret = seal_internal_buffer();

       //migrate_log("[ENCLAVE] [MLib] [DELETE_COUNTER] Deleted counter with ID:%i\n", *counter_id);
    }

    return ret;
}

/* increment a specified monotonic counter by 1 */
MIGRATION_STATUS sgx_increment_migratable_counter(uint8_t  counter_id, uint32_t* counter_value)
{
    if(MIGR_LIBRARY_DATA.MIGR_FROZEN != SGX_MIGR_STATE_FROZEN_DEFAULT){
        return SGX_MIGR_ERROR_FROZEN;
    }

    if(MIGR_LIBRARY_DATA.MIGR_INIT != SGX_MIGR_STATE_INIT_DONE){
        return SGX_MIGR_ERROR_NOT_INITIALIZED;
    }

    MIGRATION_STATUS ret = sgx_increment_monotonic_counter(&(MIGR_LIBRARY_DATA.MIGR_COUNTERS[counter_id]), counter_value);

    // Add offset but check for overflow
    // Check for overflow with offset and then handle occuring overflows by returning overflow error
    if(UINT32_MAX - *counter_value < MIGR_LIBRARY_DATA.MIGR_COUNTERS_OFFSETS[counter_id]){
        // Overflow would occur. return overflow error
        return SGX_MIGR_ERROR_MC_OVERFLOW;
    } else {
        // No overflow -> set value to offset + counter value
        *counter_value = *counter_value + MIGR_LIBRARY_DATA.MIGR_COUNTERS_OFFSETS[counter_id];
    }

    //migrate_log("[ENCLAVE] [MLib] [INCREMENT_COUNTER] Incremented counter with ID:%i\n", *counter_id);

    return ret;
}

/* read a specified monotonic counter */
MIGRATION_STATUS sgx_read_migratable_counter(uint8_t  counter_id, uint32_t* counter_value){
    if(MIGR_LIBRARY_DATA.MIGR_FROZEN != SGX_MIGR_STATE_FROZEN_DEFAULT){
        return SGX_MIGR_ERROR_FROZEN;
    }

    if(MIGR_LIBRARY_DATA.MIGR_INIT != SGX_MIGR_STATE_INIT_DONE){
        return SGX_MIGR_ERROR_NOT_INITIALIZED;
    }

    MIGRATION_STATUS ret = sgx_read_monotonic_counter(&(MIGR_LIBRARY_DATA.MIGR_COUNTERS[counter_id]), counter_value);

    // Add offset but check for overflow
    // Check for overflow with offset and then handle occuring overflows by returning overflow error
    if(UINT32_MAX - *counter_value < MIGR_LIBRARY_DATA.MIGR_COUNTERS_OFFSETS[counter_id]){
        // Overflow would occur. return overflow error
        return SGX_MIGR_ERROR_MC_OVERFLOW;
    } else {
        // No overflow -> set value to offset + counter value
        *counter_value = *counter_value + MIGR_LIBRARY_DATA.MIGR_COUNTERS_OFFSETS[counter_id];
    }

    //migrate_log("[ENCLAVE] [MLib] [READ_COUNTER] Read counter with ID:%i\n", *counter_id);

    return ret;
}


