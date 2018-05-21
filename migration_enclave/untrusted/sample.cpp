#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <pwd.h>
#include <libgen.h>
#include <stdlib.h>

# define MAX_PATH FILENAME_MAX


#include <sgx_urts.h>
#include "sample.h"

#include "network_types.h"
#include "TcpServer.h"
#include "la_dh.h"
#include <iostream>
#include <string>
#include <signal.h>

#include <boost/program_options.hpp>
#include <string>
#include <vector>
#include <algorithm>
#include <iterator>
#include <iostream>

#include "migration_library.h"
#include "migration_enclave_u.h"

#include "ra.h"
#include "nrt_ra.h"

using namespace network;
using boost::asio::ip::tcp;
using namespace boost::program_options;


/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

/* Global IO service to handle all ME communications */
boost::asio::io_service g_io_service;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

std::map<std::string, ra_socket_t*> g_ra_sockets;

/*
 * Let it be here for the time being
 * Returns a string representation of remote_enclave_t
 * ip:port
 */
std::string remote_enclave_to_string( remote_enclave_t enclave ) {
    char res[24];
    std::string std_res;
    std_res.assign( enclave.ip );
    std_res.append( ":" );
    std_res.append( enclave.port );
    return std_res;
}

/* Initialize the enclave:
 *   Step 1: retrive the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    /* Step 1: retrive the launch token saved by last transaction */

    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }
    printf("token_path: %s\n", token_path);
    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }

    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */

    ret = sgx_create_enclave(MIGRATION_ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);

    if (ret != SGX_SUCCESS) {
        printf("Error creating enclave %u\n", ret);
        if (fp != NULL) fclose(fp);

        return -1;
    }

    /* Step 3: save the launch token if it is updated */

    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);

    return 0;
}


static int handle_remote_message(network::TcpConnection *conn, message_t *msg);
static int handle_nested_local_message(message_t *msg, size_t max_size,
        secure_message_t *resp_data, size_t resp_data_size) {
    uint32_t ret, ret_val;
    ra_socket_t *ra_socket;
    network::TcpConnection::ptr conn;
    int status;

    // Process the unencrypted part first:
    // Handle the unencrypted part as a migration message:
    attestation_msg_t *plaintext_msg = (attestation_msg_t *) msg->data_plaintext;
    remote_enclave_t *destination;
    std::string dest;

    // Process it based on its type
    switch(plaintext_msg->msg_type){
    case SGX_MIGR_OPCODE_OUTGOING:
        destination = (remote_enclave_t *) plaintext_msg->inparam_buff;
        printf("[ME] [LA] Handling nested message outgoing migration.\n");

        ra_socket = (ra_socket_t*) malloc( sizeof(ra_socket_t) );
        memset(ra_socket, 0, sizeof(ra_socket_t));
        ra_send_quote_to( global_eid, *destination, ra_socket, &g_io_service );

        std::cout << "[ME] [LA] Setting up remote attestation to " <<
               ra_socket->conn->to_string() << std::endl;

        g_ra_sockets[ ra_socket->conn->to_string() ] = ra_socket;
        ra_socket->conn->receive_msg( handle_remote_message );

        break;
    default:
        printf("[ME] [LA] Unknown nested message type %x.\n", plaintext_msg->msg_type);
        return SGX_MIGR_ERROR_WRONG_OPCODE;
        break;
    }

    ret = la_ecall_generate_response(
            global_eid,
            &ret_val,
            msg->session_id,
            (secure_message_t *) msg->data_encrypted,
            msg->size_encrypted,
            max_size,
            resp_data,
            resp_data_size);

    if(ret != SGX_SUCCESS || ret_val != SGX_SUCCESS){
        printf("[ME] [LA] Error handling ecall of nested message: %X and %X of nested message type %x\n", ret, ret_val, plaintext_msg->msg_type);
        return ret;
    }

    return SGX_SUCCESS;
}

static int handle_local_message(network::TcpConnection *conn, message_t *msg){
    int ret = SGX_SUCCESS;
    bool response_required = true;
    bool error = false;
    uint32_t ret_val;
    message_t response;

    // For message handling
    // FIXME: max size is fixed right now.
    // This is NOT optimal, but it is the easiest way.
    size_t max_size = 2000;
    size_t resp_data_size = max_size;
    secure_message_t *resp_data = 0;

    switch(msg->type){
    case NETWORK_DH_REQUEST:
        // Prepare dh msg 1 and id pointers
        sgx_dh_msg1_t dh1;
        uint32_t id;
        ret = la_ecall_session_request(global_eid, &ret_val, &dh1, &id);
        if(ret != SGX_SUCCESS || ret_val != SGX_SUCCESS){
            response.type = NETWORK_ERROR_UNKNOWN_ERROR;
            goto abort;
        }

        //set message data
        response.size_encrypted = sizeof(sgx_dh_msg1_t);
        response.size_plaintext = 0;
        response.type = NETWORK_DH_MESSAGE_1;
        response.session_id = id;
        response.data_encrypted = &dh1;
        printf("[ME] [LA] Sent DH1 message to peer.\n");
        break;

    case NETWORK_DH_MESSAGE_2:
        //Prepare dh3 message
        sgx_dh_msg3_t dh3;
        if(msg->size_encrypted != sizeof(sgx_dh_msg2_t)){
            return SGX_ERROR_NETWORK_FAILURE;
        }

        ret = la_ecall_exchange_report(global_eid, &ret_val, (sgx_dh_msg2_t *)msg->data_encrypted, &dh3, msg->session_id);

        if(ret != SGX_SUCCESS || ret_val != SGX_SUCCESS){
            response.type = NETWORK_ERROR_UNKNOWN_ERROR;
            goto abort;
        }

        //set message data
        response.size_encrypted = sizeof(sgx_dh_msg3_t);
        response.size_plaintext = 0;
        response.type = NETWORK_DH_MESSAGE_3;
        response.session_id = msg->session_id;
        response.data_encrypted = &dh3;
        printf("[ME] [LA] Received DH Message 2 and sent message 3 to peer. DH session initialized.\n");
        break;

    case NETWORK_MESSAGE:
        resp_data = (secure_message_t *) malloc(resp_data_size);

        printf("[ME] [LMESS] Received message, processing now.\n");

        ret = la_ecall_generate_response(global_eid, &ret_val, msg->session_id, (secure_message_t *) msg->data_encrypted, msg->size_encrypted, max_size, resp_data, resp_data_size);
        if(ret != SGX_SUCCESS || ret_val != SGX_SUCCESS){
            printf("Error handling message: %X and %X\n", ret, ret_val);
            response.type = NETWORK_ERROR_UNKNOWN_ERROR;
            goto abort;
        }
        response.size_encrypted = sizeof(secure_message_t) + resp_data->message_aes_gcm_data.payload_size;
        response.size_plaintext = 0;
        response.type = NETWORK_MESSAGE_RESPONSE;
        response.session_id = msg->session_id;
        response.data_encrypted = resp_data;

        printf("[ME] [LMESS] Received encrypted message from peer and sent answer.\n");
        break;

    case NETWORK_NESTED_MESSAGE:
        resp_data = (secure_message_t *) malloc(resp_data_size);

        printf("[ME] [LMESS] Received nested message, processing now.\n");

        ret = handle_nested_local_message(msg, max_size, resp_data, resp_data_size);

        if(ret != SGX_SUCCESS){
            printf("Error handling nested message: %X\n", ret);
            response.type = NETWORK_ERROR_UNKNOWN_ERROR;
            goto abort;
        }
        response.size_encrypted = sizeof(secure_message_t) + resp_data->message_aes_gcm_data.payload_size;
        response.size_plaintext = 0;
        response.type = NETWORK_MESSAGE_RESPONSE;
        response.session_id = msg->session_id;
        response.data_encrypted = resp_data;

        printf("[ME] [LMESS] Received encrypted message from peer and sent answer.\n");
        break;


    case NETWORK_SHUTDOWN:
        response_required = false;
        ret = la_ecall_end_session(global_eid, &ret_val, msg->session_id);
        if(ret != SGX_SUCCESS || ret_val != SGX_SUCCESS){
            printf("Error closing connection\n");
            response.type = NETWORK_ERROR_UNKNOWN_ERROR;
            goto abort;
        }
        printf("Gracefully shut down the connection.\n");
        break;

    case NETWORK_RA_MESSAGE_QUOTE:
        printf("[ME] [LOCAL] Quote arrived over local attestation: %X\n", msg->type);
        response_required = false;
        ret = la_ecall_end_session(global_eid, &ret_val, msg->session_id);
        if(ret != SGX_SUCCESS || ret_val != SGX_SUCCESS){
            printf("Error closing connection\n");
            response.type = NETWORK_ERROR_UNKNOWN_ERROR;
            goto abort;
        }
        printf("Gracefully shut down the connection.\n");
        break;

    default:
        printf("[ME] [LOCAL] Unknown incoming message: %X\n", msg->type);
        response.type = NETWORK_ERROR_UNKNOWN_TYPE;
        goto abort;
    }

abort:
    if(error){
        response.size_encrypted = 0;
        response.size_plaintext = 0;
        response.session_id = msg->session_id;
        response.data_encrypted = NULL;
    }

    if(response_required){
        conn->send_message(&response);
    }

    SAFE_FREE(resp_data);
    return ret;
}

static int handle_remote_message(network::TcpConnection *conn, message_t *msg) {
    nrt_ra_request_header_t* ra_msg;
    nrt_ra_msg_quote_t* quote_msg;
    quote_t* quote;
    ra_socket_t *ra_socket;
    int status;

    int max_len = sizeof(migration_data_t);
    uint32_t res_len = 0;
    uint8_t *migration_data_msg;


    switch(msg->type){
    case NETWORK_RA_MESSAGE_QUOTE:
        /*
         * The message that is sent to the receiving enclave.
         * It needs to generate the quote in return and then wait for migration data
         */

        ra_msg = (nrt_ra_request_header_t*) msg->data_plaintext;
        if( ra_msg->type != TYPE_NRT_RA_MSG_QUOTE ) {
            printf("[ME] [REMOTE] Incoming quote message does not contain a quote.");
            break;
        }

        quote_msg = (nrt_ra_msg_quote_t*)((uint8_t*)ra_msg +
                                          sizeof(nrt_ra_request_header_t));
        quote = (quote_t*)quote_msg->quote;
        ra_verify_quote(quote);

        ra_socket = (ra_socket_t*) malloc( sizeof(ra_socket_t) );
        memset(ra_socket, 0, sizeof(ra_socket_t));
        ra_socket->conn = network::TcpConnection::ptr(conn);

        /* We need to store ra_socket for subsequent migration data handling */
        g_ra_sockets[ conn->to_string() ] = ra_socket;

        ra_send_quote( global_eid, ra_socket );

        break;

    case NETWORK_RA_MESSAGE_QUOTE_RESPONSE:
        /*
         * The remote ME replied with its quote.
         * Ready to send the migration data.
         */

        ra_msg = (nrt_ra_request_header_t*) msg->data_plaintext;
        if( ra_msg->type != TYPE_NRT_RA_MSG_QUOTE ) {
            printf("[ME] [REMOTE] Incoming response quote message does not contain a quote.");
            break;
        }

        quote_msg = (nrt_ra_msg_quote_t*)((uint8_t*)ra_msg +
                                          sizeof(nrt_ra_request_header_t));
        quote = (quote_t*)quote_msg->quote;
        ra_verify_quote(quote);

        ra_socket = g_ra_sockets[ conn->to_string() ];

        migration_data_msg = (uint8_t*)malloc( sizeof(migration_data_t) );
        ecall_get_migration_data(global_eid, &status, ra_socket->context,
                                 sizeof(quote_t), (uint8_t*)quote,
                                 max_len, migration_data_msg, &res_len);

        ra_send_migration_data( ra_socket, migration_data_msg, res_len );
        free(migration_data_msg);

        printf("[ME] [REMOTE] Closing the remote attestation context.\n");

        ecall_enclave_close_ra(global_eid, &status,
                               g_ra_sockets[ conn->to_string() ]->context );

        free(g_ra_sockets[ conn->to_string() ]);
        g_ra_sockets.erase( conn->to_string() );

        conn->socket().close();

        break;

    default:
        printf("[ME] [REMOTE] Unknown incoming message: %X\n", msg->type);
    }
    return -1;
}

void shutdown_migration_enclave(int s){
    sgx_destroy_enclave(global_eid);

    std::cout << "Enclave properly shut down."  << std::endl;
    exit(1);
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    variables_map vm;
    int lport, rport;

    try{
        options_description desc{"Options"};
        desc.add_options()
          ("help,h", "Help screen")
          ("me_lport,lp", value<int>(&lport)->default_value(1300), "Port for local enclaves")
          ("me_rport,rp", value<int>(&rport)->default_value(1301), "Port for remote enclaves");

        store(parse_command_line(argc, argv, desc), vm);
        notify(vm);

        if (vm.count("help")){
          std::cout << desc << '\n';
          return 0;
        }
      }
      catch (const error &ex){
        std::cerr << ex.what() << '\n';
        return -1;
    }
    int ret;

    /* Changing dir to where the executable is.*/
    char absolutePath [MAX_PATH];
    char *ptr = NULL;

    ptr = realpath(dirname(argv[0]),absolutePath);

    if( chdir(absolutePath) != 0)
    		abort();

    /* Initialize the enclave */
    if(initialize_enclave() < 0){

        return -1; 
    }
 
    ret = SGX_ERROR_UNEXPECTED;
    int ecall_return = 0;

    struct sigaction sigIntHandler;

    sigIntHandler.sa_handler = shutdown_migration_enclave;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;

    sigaction(SIGINT, &sigIntHandler, NULL);


    try
    {
        std::function<int(network::TcpConnection *conn, message_t *msg)> lcb(handle_local_message);
        std::function<int(network::TcpConnection *conn, message_t *msg)> rcb(handle_remote_message);
        network::TcpServer lserver(g_io_service, lport, lcb);
        network::TcpServer rserver(g_io_service, rport, rcb);
        g_io_service.run();
    }
    catch (std::exception& e)
    {
        std::cerr << e.what() << std::endl;
    }

    return ecall_return;
}
