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

#include "string.h" //for memset
#include "sgx_tae_service.h"
#include "sgx_key.h"

#include "marshalling.h"
#include "tla.h"

#include "migration_library_internal.h"
#include "migration_library.h"


/*
 * Utility function for testing
 */
void log_sealing_key(sgx_key_128bit_t k){
    for(int i = 0; i < 16; i++){
        migrate_log("%x", MIGR_LIBRARY_DATA.MIGR_SEALING_KEY[i]);
    }
    migrate_log("\n");
}

/*
 * Seal the internal buffer to have it available for the next restart of the enclave
 */
MIGRATION_STATUS seal_internal_buffer()
{
    MIGRATION_STATUS ret = SGX_SUCCESS;

    if(SEALED_DATA == NULL){
        return SGX_MIGR_ERROR_NOT_INITIALIZED;
    }

    uint32_t encrypt_length = sizeof(migration_library_data);

    // Allocate a buffer in the enclave for the sealing process
    sgx_sealed_data_t *temp_buffer = (sgx_sealed_data_t*)malloc(SEALED_DATA_SIZE);

    // use the temp buffer during sealing
    ret = sgx_seal_data(0, NULL, encrypt_length,
                        (uint8_t*)(&MIGR_LIBRARY_DATA), SEALED_DATA_SIZE, temp_buffer);

    if(ret == SGX_SUCCESS){
        // Copy the sealed data outside to unprotected memory
        memcpy(SEALED_DATA, temp_buffer, SEALED_DATA_SIZE);
        migrate_log("[ENCLAVE] [MLib] [SEAL] - Sealed the internal library data\n");
    } else {
        migrate_log("[ENCLAVE] [MLib] [SEAL] - ERROR Sealing internal data:%x\n", ret);
    }

    // Safely delete sealed data
    memset_s(temp_buffer, SEALED_DATA_SIZE, 0, SEALED_DATA_SIZE);
    free(temp_buffer);

    return ret;
}

/*
 * Local Attestation related functions.
 * These include the overloading functions for the local attestation:
 *  - verify_peer_enclave: Checks the peer identity if it is trustworthy
 *  - response_generator : Called by LA library to generate a response for an incoming message.
 *  - process message : Processes the actual message received by response generator.
 *                      However, as of now this library does not handle incoming messages
 *                      as it is only a client for the ME
 *  - restart_session : Handles the restart of a LA session.
 *                      It only updates the ME_SESSION variable with the new session id
 *
 */

// Function that is used to verify the identity of the other enclave
// Each enclave can have its own way of verifying the peer enclave identity
extern "C" ATTESTATION_STATUS la_verify_peer_enclave(
        sgx_dh_session_enclave_identity_t* peer_enclave_identity)
{
    if(!peer_enclave_identity)
        return SGX_ERROR_INVALID_ATTRIBUTE;

    // TODO: Properly verify the ME. This can be done by checking MRSIGNER with an expected value.
    if( peer_enclave_identity->isv_prod_id != 0 ||
        !(peer_enclave_identity->attributes.flags & SGX_FLAGS_INITTED))
        // || peer_enclave_identity->attributes.xfrm !=3 )
        // || peer_enclave_identity->mr_signer != xx
        return SGX_MIGR_ERROR_NOT_TRUSTED;
    else
        return SGX_SUCCESS;
}

// Operates on the input secret and generates the output secret
MIGRATION_STATUS process_message(uint32_t req_message_type,
        migration_data_t *incoming_migration_data, uint32_t *resp_message_type,
        migration_data_t* outgoing_migration_data)
{
    /*
     * TODO: Currently, the la_response_generator and this function are not in use by the MLib. Delete them if you do not need them.
     * Local att library forces us to implement this. However, as of now,
     * the library does not need to parse incoming messages. Thus, we always
     * return an error.
     */
    uint32_t ret = SGX_SUCCESS;

    // Process incoming messages
    switch(req_message_type){
    // ignore all messages and abort
    default:
        ret = SGX_MIGR_ERROR_WRONG_OPCODE;
    }

    return ret;
}

// Generates the response from the request message
extern "C" ATTESTATION_STATUS la_response_generator(sgx_dh_session_enclave_identity_t* identity,
                                              char* decrypted_data,
                                              char** resp_buffer,
                                              size_t* resp_length)
{
    attestation_msg_t *ms;
    migration_data_t incoming_migration_data, outgoing_migration_data;
    MIGRATION_STATUS ret;
    uint32_t resp_message_type, req_message_type;

    if(!decrypted_data || !resp_length)
        return SGX_ERROR_INVALID_ATTRIBUTE;

    ms = (attestation_msg_t *)decrypted_data;

    if( unmarshal_migration_data_message((attestation_msg_t *)decrypted_data,
            &req_message_type, &incoming_migration_data) != SGX_SUCCESS)
        return SGX_ERROR_UNEXPECTED;

    ret = process_message(req_message_type, &incoming_migration_data,
            &resp_message_type, &outgoing_migration_data);

    if(marshal_migration_data_message(resp_message_type, &outgoing_migration_data,
                resp_buffer, resp_length) != SGX_SUCCESS)
        return SGX_ERROR_UNEXPECTED;

    return SGX_SUCCESS;

}

// Restart a session. Close it and recreate
extern "C" ATTESTATION_STATUS la_restart(uint32_t *session_id)
{
    if(!session_id || !ME_SESSION){
        return SGX_ERROR_INVALID_ATTRIBUTE;
    }

    if(*session_id != *ME_SESSION)
        return SGX_ERROR_INVALID_ATTRIBUTE;

    migrate_log("[ENCLAVE] [MLib] restarting connection with ME at %s:%s\n", ME_INFO.ip, ME_INFO.port);
    la_close(*session_id);
    la_create(&ME_INFO, ME_SESSION);

    return SGX_SUCCESS;
}

/*
 * ME related functions:
 * These functions are the main part of the LA connection:
 * They activate it, close it, and send messages over the channel.
 *
 *  - ME_establish_connection : Creates a connection to the ME_IP and ME_PORT.
 *                              Session ID is stored in ME_SESSION
 *  - ME_close_connection : Closes the connection stored in ME_SESSION
 *  - ME_exchange_message : Sends a message (with encrypted and optional plaintext part)
 *                          to the LA peer and waits for a response to return to the caller.
 *  - ME_send_migration_data : Prepares the sealed data blob, sends it to ME,
 *                             and deletes counters after success
 *  - ME_receive_migration : Receives migration data from ME and restore the
 *                           internal data of this enclave.
 */
MIGRATION_STATUS ME_establish_connection()
{
    /*
     * set up connection to ME
     */
    migrate_log("[ENCLAVE] [MLib] initiating connection with ME at %s:%s\n", ME_INFO.ip, ME_INFO.port);
    if(!ME_SESSION)
        ME_SESSION = (uint32_t *) malloc(sizeof(uint32_t));

    MIGRATION_STATUS ret = la_create(&ME_INFO, ME_SESSION);
    if(ret != SGX_SUCCESS) {
        migrate_log("[ENCLAVE] [MLib] Error initializing ME: %x\n", ret);
    }

    return ret;
}

MIGRATION_STATUS ME_close_connection()
{
    migrate_log("[ENCLAVE] [MLib] closing connection with ME at %s:%s\n", ME_INFO.ip, ME_INFO.port);

    MIGRATION_STATUS ret = la_close(*ME_SESSION);
    if(ret != SGX_SUCCESS) {
        migrate_log("[ENCLAVE] [MLib] Error closing ME: %x\n", ret);
    }

    return ret;
}

MIGRATION_STATUS ME_exchange_message(uint32_t req_message_type,
        migration_data_t *outgoing_migration_data,
        remote_enclave_t *outgoing_plaintext,
        uint32_t *resp_message_type, migration_data_t* response_migration_data)
{
    MIGRATION_STATUS ret;
    size_t buffer_size, buffer_plaintext_size;
    char* buffer;
    char *buffer_plaintext;
    size_t max_out_buff_size = 2000;
    size_t out_buff_size = max_out_buff_size;
    char* out_buff = (char *)malloc(out_buff_size);
    migration_data_t response;
    uint32_t response_type;

    if(marshal_migration_data_message(req_message_type,
                outgoing_migration_data, &buffer, &buffer_size) != SGX_SUCCESS)
        return SGX_ERROR_UNEXPECTED;

    if(marshal_remote_enclave_message(req_message_type,
                outgoing_plaintext, &buffer_plaintext, &buffer_plaintext_size) != SGX_SUCCESS)
        return SGX_ERROR_UNEXPECTED;

    ret = la_exchange(ME_SESSION, buffer, buffer_size,
            (attestation_msg_t *)buffer_plaintext, buffer_plaintext_size,
            max_out_buff_size, &out_buff, &out_buff_size);

    if(ret != SGX_SUCCESS) {
        SAFE_FREE(buffer);
        SAFE_FREE(buffer_plaintext);
        SAFE_FREE(out_buff);
        return ret;
    }

    if(unmarshal_migration_data_message((attestation_msg_t *)out_buff,
                &response_type, &response) != SGX_SUCCESS) {
        SAFE_FREE(buffer);
        SAFE_FREE(buffer_plaintext);
        SAFE_FREE(out_buff);
        return SGX_ERROR_UNEXPECTED;
    }

    *resp_message_type = response_type;
    memcpy(response_migration_data, &response, sizeof(migration_data_t));
    SAFE_FREE(buffer);
    SAFE_FREE(buffer_plaintext);
    SAFE_FREE(out_buff);
    return SGX_SUCCESS;
}

MIGRATION_STATUS ME_send_message(uint32_t req_message_type, migration_data_t *outgoing_migration_data)
{
    MIGRATION_STATUS ret;
    size_t buffer_size, buffer_plaintext_size;
    char* buffer;
    char *buffer_plaintext;

    if(marshal_migration_data_message(req_message_type,
                outgoing_migration_data, &buffer, &buffer_size) != SGX_SUCCESS)
        return SGX_ERROR_UNEXPECTED;

    ret = la_send(ME_SESSION, buffer, buffer_size);

    SAFE_FREE(buffer);
    SAFE_FREE(buffer_plaintext);
    return SGX_SUCCESS;
}

MIGRATION_STATUS ME_read_message(uint32_t *resp_message_type, migration_data_t* response_migration_data){
    MIGRATION_STATUS ret;
    size_t max_out_buff_size = 2000;
    size_t out_buff_size = max_out_buff_size;
    char* out_buff = (char *)malloc(out_buff_size);
    migration_data_t response;
    uint32_t response_type;

    ret = la_receive(ME_SESSION, max_out_buff_size, &out_buff, &out_buff_size);
    if(ret != SGX_SUCCESS) {
        SAFE_FREE(out_buff);
        return ret;
    }

    if(unmarshal_migration_data_message((attestation_msg_t *)out_buff,
                &response_type, &response) != SGX_SUCCESS) {
        SAFE_FREE(out_buff);
        return SGX_ERROR_UNEXPECTED;
    }

    *resp_message_type = response_type;
    memcpy(response_migration_data, &response, sizeof(migration_data_t));
    SAFE_FREE(out_buff);
    return SGX_SUCCESS;
}

MIGRATION_STATUS ME_send_migration_data(char* dest_ip, char* dest_port)
{
    MIGRATION_STATUS ret;
    migration_data_t migration_data, response_message;
    uint32_t response_type;

    migrate_log("[ENCLAVE] [MLib] [MIGRATION] Sending Migration data to ME....\n");

    //Make sure migr data is clear
    memset_s(&migration_data, sizeof(migration_data_t), 0, sizeof(migration_data_t));
    memset_s(&response_message, sizeof(migration_data_t), 0, sizeof(migration_data_t));

    ret = ME_establish_connection();
    if(ret != SGX_SUCCESS){
        goto abort;
    }

    // Prepare the plaintext message:
    remote_enclave_t destination;
    strncpy(destination.ip, dest_ip, sizeof(destination.ip));
    strncpy(destination.port, dest_port, sizeof(destination.port));

    // now prepare the encrypted message
    // create the migration data struct by copying key and counter values
    migrate_log("[ENCLAVE] [MLib] [MIGRATION] Connection established, prepare migration data.\n");
    memcpy(&migration_data.migration_sealing_key,
           &MIGR_LIBRARY_DATA.MIGR_SEALING_KEY, sizeof(sgx_key_128bit_t));
    migrate_log("[ENCLAVE] [MLib] [MIGRATION] Migrating sealing Key:");
    log_sealing_key(MIGR_LIBRARY_DATA.MIGR_SEALING_KEY);

    // Migrate the counters
    migrate_log("[ENCLAVE] [MLib] [MIGRATION] Extracting counters:");
    for(int i=0; i<MIGR_COUNTER_AMOUNT; i++) {
        // Only try to read those counters where the active flag is set. This saves us a lot of time
        if(MIGR_LIBRARY_DATA.MIGR_COUNTERS_ACTIVE[i]) {
            ret = sgx_read_monotonic_counter(&(MIGR_LIBRARY_DATA.MIGR_COUNTERS[i]),
                    &(migration_data.counters_values[i]));

            // Check for overflow with offset and handle overflows by setting the value to max
            if(UINT32_MAX - migration_data.counters_values[i] <
                    MIGR_LIBRARY_DATA.MIGR_COUNTERS_OFFSETS[i]) {
                // Overflow would occur. set offset to max
                migration_data.counters_values[i] = UINT32_MAX;
            } else {
                // No overflow -> set value to offset + counter value
                migration_data.counters_values[i] = migration_data.counters_values[i] +
                    MIGR_LIBRARY_DATA.MIGR_COUNTERS_OFFSETS[i];
            }


            if(ret == SGX_SUCCESS){
                // Delete that counter
                ret = sgx_destroy_monotonic_counter(&(MIGR_LIBRARY_DATA.MIGR_COUNTERS[i]));
                if (ret != SGX_SUCCESS){
                    goto abort;
                }

                // Set the data separately from the stored data in case SGX fails to read one MC
                migration_data.counters_active[i] = true;

                migrate_log("%i (added with value %u),",i, migration_data.counters_values[i]);
            } else{
                migrate_log("[ENCLAVE] [MLib] [MIGRATION] ERROR RETRIEVING STORED COUNTERS: %x", ret);
                goto abort;
            }
        }
    }
    migrate_log("done\n[ENCLAVE] [MLib] [MIGRATION] Added all active counters\n");

    migrate_log("[ENCLAVE] [MLib] [MIGRATION] Sending migration data to ME.\n");
    ret = ME_exchange_message(SGX_MIGR_OPCODE_OUTGOING,
            &migration_data, &destination, &response_type, &response_message);
    if(ret != SGX_SUCCESS)
        goto abort;
        //TODO: Currently, there is no error recovery. If you need it, make sure it does not subvert any security guarantees!

    if(response_type == SGX_MIGR_OPCODE_OUTGOING_DONE){
        migrate_log("[ENCLAVE] [MLib] [MIGRATION] Migration successful.\n");
    } else {
        ret = SGX_MIGR_ERROR_WRONG_OPCODE;
        goto abort;
    }

abort:
    // close connection
    int err = ME_close_connection();

    // If we were successful previously, return the error code of ME_close_connection
    if(ret == SGX_SUCCESS) {
        migrate_log("[ENCLAVE] [MLib] [MIGRATION] Enclave data sent to ME and local counters erased.\n");
        ret = err;
    }

    return ret;
}


MIGRATION_STATUS ME_receive_migration(){

    MIGRATION_STATUS ret = SGX_SUCCESS;
    uint32_t response_type;
    uint32_t val;
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
    migration_data_t empty_migration_data, response_message;

    //Make sure migr data is clear
    memset_s(&empty_migration_data, sizeof(migration_data_t), 0, sizeof(migration_data_t));
    memset_s(&response_message, sizeof(migration_data_t), 0, sizeof(migration_data_t));

    ret = ME_establish_connection();
    if(ret != SGX_SUCCESS){
        return ret;
    }

    ret = ME_exchange_message(SGX_MIGR_OPCODE_INCOMING,
            &empty_migration_data, NULL, &response_type, &response_message);
    if(ret != SGX_SUCCESS)
        goto abort;

    switch(response_type) {
    case SGX_MIGR_OPCODE_INCOMING_DONE:

        // Null out library data in preparation of migration
        memset_s(&MIGR_LIBRARY_DATA, sizeof(migration_library_data),
                 0, sizeof(migration_library_data));

        //Unset freeze
        MIGR_LIBRARY_DATA.MIGR_FROZEN = SGX_MIGR_STATE_FROZEN_DEFAULT;

        //Copy sealing key
        memcpy(&MIGR_LIBRARY_DATA.MIGR_SEALING_KEY,
               &response_message.migration_sealing_key, sizeof(sgx_key_128bit_t));
        migrate_log("[ENCLAVE] [MLib] [MIGRATION] [RESTORATION] Restored sealing Key:");
        log_sealing_key(MIGR_LIBRARY_DATA.MIGR_SEALING_KEY);

        // And create a monotonic counter for every entry in the array
        migrate_log("[ENCLAVE] [MLib] [MIGRATION] [RESTORATION] Restoring counters:\n");
        for(int i=0; i<MIGR_COUNTER_AMOUNT; i++) {
            if(response_message.counters_active[i] == true) {
                //Only create a counter if we need one
                val = 0; // Reset val
                ret = sgx_create_monotonic_counter(&MIGR_LIBRARY_DATA.MIGR_COUNTERS[i],&val);
                MIGR_LIBRARY_DATA.MIGR_COUNTERS_ACTIVE[i] = true;
                MIGR_LIBRARY_DATA.MIGR_COUNTERS_OFFSETS[i] = response_message.counters_values[i];
                migrate_log("[ENCLAVE] [MLib] [MIGRATION] [RESTORATION] Recreating counter %i with offset %u\n", i, MIGR_LIBRARY_DATA.MIGR_COUNTERS_OFFSETS[i]);

                // Abort if error occured
                if(ret != SGX_SUCCESS){
                    goto abort;
                }
            }
        }
        migrate_log("[ENCLAVE] [MLib] [MIGRATION] [RESTORATION] Restored all counters to their previous value.\n");

        // Now seal the current state to make it readable on restart
        ret = seal_internal_buffer();

        break;

    case SGX_MIGR_OPCODE_MIGRATION_NONEXISTENT:
        // ME does not have the data yet.
        // Keep all connections open and wait for it.
        ret = SGX_MIGR_ERROR_MIGRATION_OUTSTANDING;
        return ret;

    default:
        ret = SGX_MIGR_ERROR_WRONG_OPCODE;
        goto abort;
    }


abort:
    int err = ME_close_connection();
    if(ret == SGX_SUCCESS){
        migrate_log("[ENCLAVE] [MLib] [MIGRATION] Successfully received migration.\n");
        ret = err;
    }

    return ret;
}

MIGRATION_STATUS ME_process_migration_data(uint32_t message_type, migration_data_t *message){
    MIGRATION_STATUS ret = SGX_SUCCESS;
    uint32_t val;

    switch(message_type){
    case SGX_MIGR_OPCODE_INCOMING_DONE:

        // Null out library data in preparation of migration
        memset_s(&MIGR_LIBRARY_DATA, sizeof(migration_library_data),
                 0, sizeof(migration_library_data));

        //Copy sealing key
        memcpy(&MIGR_LIBRARY_DATA.MIGR_SEALING_KEY, &(message->migration_sealing_key),
               sizeof(sgx_key_128bit_t));
        migrate_log("[ENCLAVE] [MLib] [MIGRATION] [RESTORATION] Restored sealing Key:");
        log_sealing_key(MIGR_LIBRARY_DATA.MIGR_SEALING_KEY);

        // And create a monotonic counter for every entry in the array
        migrate_log("[ENCLAVE] [MLib] [MIGRATION] [RESTORATION] Restoring counters:\n");
        for(int i=0; i<MIGR_COUNTER_AMOUNT; i++) {
            if(message->counters_active[i] == true) {
                //Only create a counter if we need one
                val = 0; // Reset val
                ret = sgx_create_monotonic_counter(&MIGR_LIBRARY_DATA.MIGR_COUNTERS[i],&val);
                MIGR_LIBRARY_DATA.MIGR_COUNTERS_ACTIVE[i] = true;
                MIGR_LIBRARY_DATA.MIGR_COUNTERS_OFFSETS[i] = message->counters_values[i];
                migrate_log("[ENCLAVE] [MLib] [MIGRATION] [RESTORATION] Recreating counter %i with offset %u\n", i, MIGR_LIBRARY_DATA.MIGR_COUNTERS_OFFSETS[i]);

                // Abort if error occured
                if(ret != SGX_SUCCESS) {
                    goto abort;
                }
            }
        }
        migrate_log("[ENCLAVE] [MLib] [MIGRATION] [RESTORATION] Restored all counters to their previous value.\n");

        //Unset freeze
        MIGR_LIBRARY_DATA.MIGR_FROZEN = SGX_MIGR_STATE_FROZEN_DEFAULT;

        // Now seal the current state to make it readable on restart
        ret = seal_internal_buffer();

        break;

    case SGX_MIGR_OPCODE_MIGRATION_NONEXISTENT:
        // ME does not have the data yet.
        // Keep all connections open and wait for it.
        ret = SGX_MIGR_ERROR_MIGRATION_OUTSTANDING;
        return ret;

    default:
        ret = SGX_MIGR_ERROR_WRONG_OPCODE;
        goto abort;
    }

abort:

    return ret;
}
