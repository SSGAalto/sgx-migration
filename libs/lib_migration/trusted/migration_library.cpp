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

#include <stdbool.h>
#include <stdio.h>      /* vsnprintf */
#include "string.h"

#include "sgx_trts.h" //For is_within_enclave functions

// TODO Probably remote_enclave_t should be moved to common networking
#include "la_dh.h"

#include "migration_library.h"
#include "lib_migration_t.h"  /* print_string */
#include "migration_library_internal.h"

/*
 * Global vars used by the library internals
 */

// static struct to store library data
migration_library_data MIGR_LIBRARY_DATA;

// local var to hold the pointer to sealed data
sgx_sealed_data_t *SEALED_DATA;
uint32_t SEALED_DATA_SIZE;

// vars for ME connection
remote_enclave_t ME_INFO;
uint32_t *ME_SESSION;


/*
 * Utility functions
 *
 */
/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void migrate_log(const char *fmt, ...)
{
    if(LOGGING_ENABLED){
        char buf[BUFSIZ] = {'\0'};
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(buf, BUFSIZ, fmt, ap);
        va_end(ap);
        ocall_log(buf);
    }
}

/*
 *
 * Ecalls:
 * This library provides three ECALLS:
 * ecall_migration_init: Initializes the library
 *   (Either creates a new dataset, restores one locally, or receives a migration)
 *
 * ecall_migration_start: Starts the migration to a given IP/Port.
 *   Connects to the local ME and sends the destination IP/Port and the data
 *
 * ecall_get_migration_data_size: Calculates the data size that we need
 *   for the sealed state data blob
 */

/*
	Initiates the migration library based on the init_state flag
	 - if SGX_MIGR_INIT_NEW: create new session:
	 	 -- new key
	 	 -- new array
	 	 -- directly seal that into the buffer
	 - if SGX_MIGR_INIT_RESTORE: load data from sealed buffer
	 - if SGX_MIGR_INIT_MIGRATE:
	 	 -- connect to ME
	 	 -- retrieve migration data
	 	 -- restore session
	 	 -- reseal struct
*/
MIGRATION_STATUS ecall_migration_init(void* buffer, uint32_t buffer_size,
        uint8_t init_state, const char* me_ip, const char* me_port)
{
    //migrate_log("[ENCLAVE] [MLib] [INIT] ");
    // Init library
    sgx_sealed_data_t* p_sealed_data = (sgx_sealed_data_t *) buffer;

    // Make sure migr library is empty
    memset_s(&MIGR_LIBRARY_DATA, sizeof(migration_library_data), 0, sizeof(migration_library_data));
    memset_s(&ME_INFO, sizeof(remote_enclave_t), 0, sizeof(remote_enclave_t));

    // Create the migration enclave struct
    strncpy(ME_INFO.ip, me_ip, sizeof(ME_INFO.ip));
    strncpy(ME_INFO.port, me_port, sizeof(ME_INFO.port));

    MIGRATION_STATUS ret = SGX_SUCCESS;

	migrate_log("[ENCLAVE] [MLib] [INIT] called with state %i, buffer size %i, and ip:port as %s:%s\n",
            init_state, buffer_size, me_ip, me_port);

	// Check params
	uint32_t sealed_size = sgx_calc_sealed_data_size(0,sizeof(migration_library_data));
	if(sealed_size != buffer_size){
	    migrate_log("[ENCLAVE] [MLib] [INIT] buffer size and required size do not match: given: %i != %i required\n", buffer_size, sealed_size);
		return SGX_ERROR_INVALID_PARAMETER;
	}

	// Do bounds checking on buffer: Is it strictly outside enclave?
	if(!sgx_is_outside_enclave(buffer, buffer_size)){
	    // Buffer is violating enclave boundaries: Abort
	    migrate_log("[ENCLAVE] [MLib] [INIT] Storage Buffer is violating enclave boundaries. Aborting\n");
	    return SGX_ERROR_INVALID_PARAMETER;
	}

	// Keep the pointer and size of sealed buffer
	SEALED_DATA = p_sealed_data;
	SEALED_DATA_SIZE = buffer_size;

	/*
	 * Assumes PSE session is set up already!
	 * Initialize based on our state:
	 * - New     -> create new key
	 * - Restore -> Unseal data and load
	 * - Migrate -> Contact ME and get data, then initialize that
	 */
	switch(init_state){
        case SGX_MIGR_INIT_NEW:{
            /*
             * This is a new instance
             * -> Create keys, initialize buffer
             */
            migrate_log("[ENCLAVE] [MLib] [INIT] Creating new instance...\n");
            MIGR_LIBRARY_DATA.MIGR_FROZEN = SGX_MIGR_STATE_FROZEN_DEFAULT;
            sgx_read_rand(MIGR_LIBRARY_DATA.MIGR_SEALING_KEY, 16);

            migrate_log("[ENCLAVE] [MLib] [INIT] New sealing key generated\n");

            // Now seal the current state to make it readable on restart
            ret = seal_internal_buffer();
            migrate_log("[ENCLAVE] [MLib] [INIT] Creating new instance...DONE\n");

            break;
        }
        case SGX_MIGR_INIT_RESTORE:{
            /*
             * Restore data from sealed buffer
             */
            migrate_log("[ENCLAVE] [MLib] [INIT] Restoring instance...\n");

            // Copy sealed buffer into enclave to unseal it:
            void* temp_buffer = (void*) malloc(SEALED_DATA_SIZE);
            memcpy(temp_buffer, SEALED_DATA, SEALED_DATA_SIZE);
            // unseal
            ret = sgx_unseal_data((const sgx_sealed_data_t*) temp_buffer,
                    NULL, 0, (uint8_t*)&MIGR_LIBRARY_DATA, &sealed_size);
            // And free temp buffer again
            memset_s(temp_buffer, SEALED_DATA_SIZE, 0, SEALED_DATA_SIZE);
            free(temp_buffer);


            migrate_log("[ENCLAVE] [MLib] [INIT] Restored sealing key\n");
            migrate_log("[ENCLAVE] [MLib] [INIT] Restored counters\n");

            /*
             * Check if we are in a frozen state
             */
            if( (ret == SGX_SUCCESS) &&
                (MIGR_LIBRARY_DATA.MIGR_FROZEN == SGX_MIGR_STATE_FROZEN_LOCKED) ){
                migrate_log("[ENCLAVE] [MLib] [INIT] the enclave previously shut down in the middle of the migration process, error");
            }
            break;
        }
        case SGX_MIGR_INIT_MIGRATE:{
            ret = SGX_SUCCESS;
            /*
                Restores a migrated enclave (-> Receives enclave data)
                Only works when in frozen incoming mode
                1) Local attest the ME
                2) receive migration data buffer
                3) Restore counters and key
                4) seal buffer to MIGR_LIBRARY_DATA
                5) Respond to ME with OK
                6) set Frozen to 0
             */
            migrate_log("[ENCLAVE] [MLib] [MIGRATION] Receiving Migration...\n");
            migration_data_t migration_data, response_message;
            uint32_t response_type;

            // Make sure migr data is clear
            memset_s(&migration_data, sizeof(migration_data_t), 0, sizeof(migration_data_t));
            memset_s(&response_message, sizeof(migration_data_t), 0, sizeof(migration_data_t));

            ret = ME_establish_connection();
            if(ret != SGX_SUCCESS){
                return ret;
            }

            ret = ME_exchange_message(SGX_MIGR_OPCODE_INCOMING, &migration_data,
                    NULL, &response_type, &response_message);
            if(ret != SGX_SUCCESS){
                return ret;
            }

            ret = ME_process_migration_data(response_type, &response_message);

            // Keep waiting for the migration data from the server if migration is not done
            if(ret != SGX_SUCCESS){
                while(ret != SGX_SUCCESS){
                    migrate_log("[ENCLAVE] [MLib] [INIT] Migration not ready. Waiting.\n");
                    // Abort if we have something else than outstanding migration
                    if (ret != SGX_MIGR_ERROR_MIGRATION_OUTSTANDING){
                        migrate_log("[ENCLAVE] [MLib] [INIT] Error during receive migration %x.\n", ret);
                        break;
                    }

                    // Read message after deleting the old one
                    memset_s(&response_message, sizeof(migration_data_t), 0, sizeof(migration_data_t));
                    response_type = 0;
                    ret = ME_read_message(&response_type, &response_message);
                    if(ret != SGX_SUCCESS){
                        //Error, keep retrying
                        ret = SGX_MIGR_ERROR_MIGRATION_OUTSTANDING;
                        continue;
                    }

                    // Process message
                    ret = ME_process_migration_data(response_type, &response_message);
                }

                // We are done, send okay to ME and close session.
                // ignore any errors, we are done
                ME_send_message(SGX_MIGR_OPCODE_INCOMING_DONE, &migration_data);
            }

            // close the connection
            ME_close_connection();

            migrate_log("[ENCLAVE] [MLib] [INIT] Successfully received migration data\n");

            break;
        }
        default:{
            // Unknown init_state. Throw error
            migrate_log("[ENCLAVE] [MLib] [INIT] Unknown INIT state. Aborting\n");
            ret = SGX_ERROR_INVALID_PARAMETER;
        }
	}

	/*
	 * Finally, set INIT state based on return value. We do not need to update
	 * the sealed buffer afterwards as the Init state is ignored on load
	 */
	switch(ret){
	case SGX_SUCCESS:
	    MIGR_LIBRARY_DATA.MIGR_INIT = SGX_MIGR_STATE_INIT_DONE;
	    break;
	case SGX_MIGR_ERROR_MIGRATION_OUTSTANDING:
        MIGR_LIBRARY_DATA.MIGR_INIT = SGX_MIGR_STATE_INIT_AWAITING_MIGRATION;
	    break;
	default:
	    MIGR_LIBRARY_DATA.MIGR_INIT = SGX_MIGR_STATE_INIT_FAILURE;

	}

	return ret;
}


/*
 * Assumes PSE session is set up already!
    Starts the migration process on an enclave
    1) connect to ME
    2) Set freeze to 1
    3) seal data struct to internal buffer
    4) create migration data struct
    5) send data to ME
    6) wait for OK
    7) Delete local counters

    This function sends only counters that are listed in the active counter list
*/
MIGRATION_STATUS ecall_migration_start(const char* const_dest_ip, const char* const_dest_port)
{
    MIGRATION_STATUS ret;

    // copy dest to local var
    char dest_ip[16];
    char dest_port[6];
    strncpy(dest_ip, const_dest_ip, sizeof(dest_ip));
    strncpy(dest_port, const_dest_port, sizeof(dest_port));

    migrate_log("[ENCLAVE] [MLib] [MIGRATE] Migrating to %s\n", dest_ip);

    // Check if we are already frozen to prevent multiple calls?
	if(MIGR_LIBRARY_DATA.MIGR_FROZEN == SGX_MIGR_STATE_FROZEN_LOCKED){
		// Second call. Exit.
	    migrate_log("[ENCLAVE] [MLib] [MIGRATE] We should already be frozen, migration is already running. Abort\n");
		return SGX_MIGR_ERROR_MIGRATION_IN_PROGRESS;
	}

	// Directly freeze the enclave and make sure it stays frozen
	MIGR_LIBRARY_DATA.MIGR_FROZEN = SGX_MIGR_STATE_FROZEN_LOCKED;
	seal_internal_buffer();

	// Send this data to ME. Also handles deletion of counters later
	ret = ME_send_migration_data(dest_ip, dest_port);

	migrate_log("[ENCLAVE] [MLib] [MIGRATE] Sending migration with return code: %u\n",ret);

	return ret;

}

/*
 * Calculates the data size needed by the internal library data when storing as sealed blob
 */
MIGRATION_STATUS ecall_get_migration_data_size() {
    return sgx_calc_sealed_data_size(0, sizeof(migration_library_data));
}
