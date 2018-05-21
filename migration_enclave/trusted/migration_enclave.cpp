#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include "string.h"
#include <map>

#include "migration_enclave.h"

#include "tla.h"
#include "la_dh.h"
#include "migration_library.h"
#include "migration_enclave_t.h"  /* print_string */
#include "marshalling.h"

#include "nrt_tke.h"

// Create a class for the measurement type to make it comparable for the map
class Measurements
{
private:
    sgx_measurement_t measurements;

public:
    Measurements(sgx_measurement_t val)
        :
            measurements(val)
    {};

    bool operator<(const Measurements& other) const
    {
        // Comparator now simply compares all array fields
        for(int i = 0; i < SGX_HASH_SIZE - 1; i++){
            if(measurements.m[i] != other.measurements.m[i]){
                return measurements.m[i] < other.measurements.m[i];
            }
        }
        // If we did not return until here, return comparison of the last element
        return measurements.m[SGX_HASH_SIZE - 1] < other.measurements.m[SGX_HASH_SIZE - 1];
    }
};

std::map<Measurements, migration_data_t>g_migration_map;

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_log(buf);
}

/*
    MIGRATION ENCLAVE function
    Starts the migration process.
    ENC -> ME
    1) receive data
    2) Seal data

    ME -> ME (see ecall_send_migration_data)
    a) Remote attest ME_src
    b) Send data
    c) Wait for OK
       -> If timeout, retry
    d) On OK, delete sealed data

    3) Send ok to enclave
*/
MIGRATION_STATUS ME_migrate(sgx_measurement_t mrenclave,
        migration_data_t *incoming_migration_data,
        uint32_t *resp_message_type,
        migration_data_t* outgoing_migration_data){
    printf("[ME] [MIGRATE] Receiving migration.\n");

    // Store the data locally
    // The contact with remote ME happens outside the enclave
    // ME will be provided with the remote ME quote,
    // encrypt migration data and give it out to be sent to remote ME

    g_migration_map.insert(std::pair<Measurements,
            migration_data_t>(Measurements(mrenclave), *incoming_migration_data));

    //TODO: potentially seal data? in case ME crashes?

    *resp_message_type = SGX_MIGR_OPCODE_OUTGOING_DONE;
    outgoing_migration_data = NULL;
    printf("[ME] [MIGRATE] Size of migration map is now %u\n", g_migration_map.size());

	return SGX_SUCCESS;
}

/**
 * Incoming migration from another ME.
 * The ME already received the data from a local enclave. We must now
 * store it and send it to our local enclanve. Test if we are already connected to
 * the required enclave and if not just send back an OK after storing the data.
 */
MIGRATION_STATUS ME_migrate_incoming(
        sgx_measurement_t mrenclave,
        migration_data_t *incoming_migration_data,
        uint32_t *resp_message_type,
        migration_data_t* outgoing_migration_data)
{
    printf("[ME] [MIGRATE] Receiving migration from another ME.\n");

    // Try sending the data to local enclave session
    size_t buffer_size;
    size_t buffer_plaintext_size = 0;
    char* buffer;
    size_t max_out_buff_size = 2000;
    size_t out_buff_size = max_out_buff_size;
    char* out_buff = (char *)malloc(out_buff_size);
    migration_data_t response;
    uint32_t response_type;

    if(marshal_migration_data_message(SGX_MIGR_OPCODE_INCOMING,
                incoming_migration_data, &buffer, &buffer_size) != SGX_SUCCESS)
        return SGX_ERROR_UNEXPECTED;

    ATTESTATION_STATUS retval = la_exchange_with_eid(
            &mrenclave,
            buffer,
            buffer_size,
            NULL,
            buffer_plaintext_size,
            max_out_buff_size,
            &out_buff,
            &out_buff_size);

    uint32_t unmarshal_ret = unmarshal_migration_data_message((attestation_msg_t *)out_buff,
            &response_type, &response);

    SAFE_FREE(buffer);
    SAFE_FREE(out_buff);

    outgoing_migration_data = NULL;

    if( (retval == SGX_SUCCESS) &&
        (unmarshal_ret == SGX_SUCCESS) &&
        (response_type == SGX_MIGR_OPCODE_INCOMING_DONE ) )
    {
        // Migration successfull, wrap up by sending back migration done
        *resp_message_type = SGX_MIGR_OPCODE_ME_MIGRATION_DONE;
        printf("Passed data over to local enclave. Migration done.\n");
    } else {
        // Migration not successfull. Store buffer and send back ok
        g_migration_map.insert(std::pair<Measurements, migration_data_t>(Measurements(mrenclave),
                               *incoming_migration_data));
        *resp_message_type = SGX_MIGR_OPCODE_ME_MIGRATION_OK;

        printf("[ME] [MIGRATE] Size of migration map is now %u\n", g_migration_map.size());
    }

    return SGX_SUCCESS;
}

/*
    MIGRATION ENCLAVE function
    Enclave requested to receive migration data
    1) Check if data is there already. If not, send UNAVAILABLE message
    2) Send migration data buffer
    3) wait for OK
    4) On OK, delete data
    NOTE: This might allow for rollbacks if OK of step 3 is dropped. 
     You can solve this by deleting migration data after sending,
     or having a more sophisticated message exchange of DONE messages.
     Thus, it heavily depends on your error recovery needs and can not be generalized here 
     (In our research setup, we can simply assume that we always abort on errors).
*/
MIGRATION_STATUS ME_migrate_restore(sgx_measurement_t mrenclave,
        migration_data_t *incoming_migration_data,
        uint32_t *resp_message_type,
        migration_data_t* outgoing_migration_data)
{
    printf("[ME] [MIGRATE] [RESTORE] called\n");
    migration_data_t *data;

    // Retreive the session information for the corresponding source enclave id
    std::map<Measurements, migration_data_t>::iterator it =
        g_migration_map.find(Measurements(mrenclave));
    if(it != g_migration_map.end())
    {
        data = &it->second;
        memcpy(outgoing_migration_data, data, sizeof(migration_data_t));
        *resp_message_type = SGX_MIGR_OPCODE_INCOMING_DONE;
        g_migration_map.erase(it);
        printf("[ME] [MIGRATE] [RESTORE] Found data and sending it to peer.\n");
    }
    else
    {
        *resp_message_type = SGX_MIGR_OPCODE_MIGRATION_NONEXISTENT;
        outgoing_migration_data = NULL;
    }

    printf("[ME] [MIGRATE] [RESTORE]: size of map is now %u\n", g_migration_map.size());

    return SGX_SUCCESS;
}

// Function that is used to verify the trust of the other enclave
// Each enclave can have its own way verifying the peer enclave identity
extern "C" ATTESTATION_STATUS la_verify_peer_enclave(
        sgx_dh_session_enclave_identity_t* peer_enclave_identity)
{
    //As of now, the migration enclave does not care who it is migrating, everyone is welcome
    if(!peer_enclave_identity)
    {
        return SGX_ERROR_INVALID_ATTRIBUTE;
    }
    else
    {
        return SGX_SUCCESS;
    }
}

//Operates on the input secret and generates the output secret
void process_message(sgx_dh_session_enclave_identity_t* identity,
        uint32_t req_message_type,
        migration_data_t *incoming_migration_data,
        uint32_t *resp_message_type,
        migration_data_t* outgoing_migration_data)
{
    uint32_t ret = SGX_SUCCESS;
    migration_data_t out_data;
    uint32_t out_type;

    //Process incoming messages
    switch(req_message_type) {
    case SGX_MIGR_OPCODE_OUTGOING: // enclave migrates its own data
        ret = ME_migrate(identity->mr_enclave,
                incoming_migration_data, resp_message_type, outgoing_migration_data);
        break;
    case SGX_MIGR_OPCODE_INCOMING: // enclave retrieves data
        ret = ME_migrate_restore(identity->mr_enclave,
                incoming_migration_data, resp_message_type, outgoing_migration_data);
        break;
    case SGX_MIGR_OPCODE_TEST:
        out_type = req_message_type;
        *resp_message_type = out_type;
        memcpy(outgoing_migration_data, incoming_migration_data, sizeof(migration_data_t));

        printf("[ME] TEST OPCODE received. Printing:\n");
        printf("Type: %u; ", req_message_type);
        printf("Data: Active:%X Counter:%u Key:%u ; ", outgoing_migration_data->counters_active[0], outgoing_migration_data->counters_values[0], outgoing_migration_data->migration_sealing_key[0]);
        printf("Bouncing message back to peer\n");

        break;

    default:
        printf("[ME] Unknown message type %x", req_message_type);
        break;
    }

}

// Generates the response from the request message
extern "C" ATTESTATION_STATUS la_response_generator(sgx_dh_session_enclave_identity_t* identity,
                                              char* decrypted_data,
                                              char** resp_buffer,
                                              size_t* resp_length)
{
    attestation_msg_t *ms;
    migration_data_t incoming_migration_data, outgoing_migration_data;
    uint32_t resp_message_type, req_message_type;

    if(!decrypted_data || !resp_length)
    {
        return SGX_ERROR_INVALID_ATTRIBUTE;
    }
    ms = (attestation_msg_t *)decrypted_data;

    if(unmarshal_migration_data_message((attestation_msg_t *)decrypted_data,
                &req_message_type, &incoming_migration_data) != SGX_SUCCESS)
        return SGX_ERROR_UNEXPECTED;

    process_message(identity, req_message_type, &incoming_migration_data,
            &resp_message_type, &outgoing_migration_data);

    if(marshal_migration_data_message(resp_message_type, &outgoing_migration_data,
                resp_buffer, resp_length) != SGX_SUCCESS)
        return SGX_ERROR_UNEXPECTED;

    return SGX_SUCCESS;

}

// Restart a session. In the migration enclave, we do nothing
extern "C" ATTESTATION_STATUS la_restart(uint32_t *session_id)
{
    // do nothing

    return SGX_SUCCESS;
}

// Remote Attestation
int ecall_enclave_init_ra( int b_pse, nrt_ra_context_t *p_context )
{
    sgx_status_t ret;
    if( b_pse ) {
        int busy_retry = 2;
        do {
            ret = sgx_create_pse_session();
        } while( ret == SGX_ERROR_BUSY && busy_retry-- );

        if( ret != SGX_SUCCESS )
            return ret;
    }
    ret = nrt_ra_init( b_pse, p_context );
    if( b_pse ) {
        sgx_close_pse_session();
    }
    return ret;
}

int ecall_enclave_close_ra( nrt_ra_context_t context )
{
    sgx_status_t ret;
    ret = nrt_ra_close( context );
    return ret;
}

int ecall_get_migration_data(nrt_ra_context_t context,
                             uint32_t quote_len, uint8_t *quote,
                             uint32_t max_len, uint8_t *result, uint32_t *res_len)
{

// Actual data sent over to ME
// typedef struct _migration_data {
//     uint32_t counters_values[MIGR_COUNTER_AMOUNT];
//     bool counters_active[MIGR_COUNTER_AMOUNT];
//     sgx_key_128bit_t migration_sealing_key;
// } migration_data_t;

    migration_data_t *data;

    if( g_migration_map.empty() ) {
        return SGX_ERROR_UNEXPECTED;
    }

    if( sizeof(migration_data_t) > max_len ) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    std::map<Measurements, migration_data_t>::iterator it = g_migration_map.begin();

    const Measurements *mrenclave = &it->first;
    data = &it->second;

    memcpy(result, data, sizeof(migration_data_t));
    *res_len = sizeof(migration_data_t);

    return SGX_SUCCESS;
}
