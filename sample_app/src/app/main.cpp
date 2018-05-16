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

#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include <unistd.h>
#include <pwd.h>
#include <libgen.h>

#define MAX_PATH FILENAME_MAX
#define PSE_RETRIES 3

#include <sgx_urts.h>
#include "migration_library.h"
#include "enclave_u.h"

#include <boost/program_options.hpp>
#include <algorithm>

#include <numeric>
#include <chrono>
#include <iostream>
#include <sstream>
#include <vector>
#include <iterator>
#include <fstream>

#include <fcntl.h>

#include "sgx_tseal.h"   // For seal defines
#include "sgx_error.h"   /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */

# define TOKEN_FILENAME          "enclave.token"
# define SAMPLE_ENCLAVE_FILENAME "enclave.signed.so"

using namespace boost::program_options;

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

// Launch token globally known to be able to reuse it
sgx_launch_token_t g_token = {0};
bool g_token_init = false;
char g_token_path[MAX_PATH] = {'\0'};


//Required size for init buffer
uint32_t g_required_size;

//Required size for test seal buffer and its mac/seal size
uint32_t g_test_length_mac, g_test_length_enc, g_test_length_sealed_blob;

/* Initialize the enclave:
 *   Step 1: retrive the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    FILE *fp;

    if(!g_token_init){
        //First iteration: Retrieve launch token and path:
        /* Step 1: retrive the launch token saved by last transaction */

        /* try to get the token saved in $HOME */
        const char *home_dir = getpwuid(getuid())->pw_dir;
        if (home_dir != NULL &&
            (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
            /* compose the token path */
            strncpy(g_token_path, home_dir, strlen(home_dir));
            strncat(g_token_path, "/", strlen("/"));
            strncat(g_token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
        } else {
            /* if token path is too long or $HOME is NULL */
            strncpy(g_token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
        }

        fp = fopen(g_token_path, "rb");
        if (fp == NULL && (fp = fopen(g_token_path, "wb")) == NULL) {
            printf("Warning: Failed to create/open the launch token file \"%s\".\n", g_token_path);
        }
        printf("g_token_path: %s\n", g_token_path);
        if (fp != NULL) {
            /* read the token from saved file */
            size_t read_num = fread(g_token, 1, sizeof(sgx_launch_token_t), fp);
            if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
                /* if token is invalid, clear the buffer */
                memset(&g_token, 0x0, sizeof(sgx_launch_token_t));
                printf("Warning: Invalid launch token read from \"%s\".\n", g_token_path);
            }
            fclose(fp);
        }

        g_token_init = true;
    }

    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */

    ret = sgx_create_enclave(SAMPLE_ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &g_token, &updated, &global_eid, NULL);

    if (ret != SGX_SUCCESS) {
        printf("Error creating enclave: %x\nAborting", ret);
        if (fp != NULL) fclose(fp);

        return -1;
    }

    /* Step 3: save the launch token if it is updated */

    if (updated == false) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        return 0;
    }

    /* reopen the file with write capablity */
    fp = fopen(g_token_path, "wb");
    if (fp == NULL) return 0;
    size_t write_num = fwrite(g_token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", g_token_path);
    fclose(fp);

    return 0;
}

void establish_pse_session(){
    // Init pse session (dumb way but we assume it will return true at some point)
    bool b_retval = false;
    int counter = 0;
    while(!b_retval){
        if(counter >= PSE_RETRIES){
            abort();
        } else {
            ecall_init_session(global_eid, &b_retval);
            counter++;
        }
    }
}

void close_pse_session(){
    // destroy pse session (dumb way but we assume it will return true at some point)
    bool b_retval = false;
    int counter = 0;
    while(!b_retval){
        if(counter >= PSE_RETRIES){
            abort();
        } else {
            ecall_destroy_session(global_eid, &b_retval);
            counter++;
        }
    }
}

void start_enclave(){
    // Initialize the enclave
    if(initialize_enclave() < 0){
        abort();
    }

    establish_pse_session();
    //printf("Started enclave\n");
}

void shutdown_enclave(){
    close_pse_session();

    sgx_destroy_enclave(global_eid);
    //printf("Stopped enclave\n");
}

void restart_enclave(){
    close_pse_session();

    sgx_destroy_enclave(global_eid);
    // Initialize the enclave
    if(initialize_enclave() < 0){
        abort();
    }

    establish_pse_session();
    //printf("Restarted enclave\n");
}

void test_two_hop_migration(const char* me_ip, const char* me_port, const char* dest_ip, const char* dest_port){
    uint32_t return_value;
    void * buff = (void*) malloc(g_required_size);
    bool b_retval;

    //Setting up test environment for counter tests
    int numtests = 2;
    uint8_t ids[numtests];
    uint32_t vals[numtests] = {2, 0};

    start_enclave();

    //Init new library data
    ecall_migration_init(global_eid, &return_value, buff, g_required_size, SGX_MIGR_INIT_NEW, me_ip, me_port);
    printf("Init returned: %x\n", return_value);

    //ecall_test_seal_unseal(global_eid);

    for(int i = 0; i < numtests; i++){
        ecall_test_create_counter(global_eid, &ids[i], vals[i]);
    }
    //printf("Test create counters function returned: %i\n", init_return);

    ecall_migration_start(global_eid, &return_value, dest_ip, dest_port);
    printf("Migrate returned: %x\n", return_value);

    shutdown_enclave();

    /*
     * Second iteration of enclave
     */
    printf("Rebuilding enclave to test migration functionality...\n");
    start_enclave();

    ecall_migration_init(global_eid, &return_value, buff, g_required_size, SGX_MIGR_INIT_MIGRATE, me_ip, me_port);
    printf("Init returned: %x\n", return_value);

    bool result;
    printf("Testing counters\n");
    for(int i = 0; i < numtests; i++){
        ecall_test_counter(global_eid, &result, ids[i], vals[i]);
        if(!result){
            printf("####### ERROR testing counter %i\n", ids[i]);
        }
    }
    printf("Keep migrating to test two hop migration...\n");
    ecall_migration_start(global_eid, &return_value, dest_ip, dest_port);
    printf("Migrate returned: %x\n", return_value);

    shutdown_enclave();


    /*
     * Third iteration of enclave
     */
    start_enclave();

    ecall_migration_init(global_eid, &return_value, buff, g_required_size, SGX_MIGR_INIT_MIGRATE, me_ip, me_port);
    printf("Init returned: %x\n", return_value);

    printf("Testing and then deleting counters\n");
    for(int i = 0; i < numtests; i++){
        ecall_test_counter(global_eid, &result, ids[i], vals[i]);
        if(!result){
            printf("####### ERROR testing counter %i\n", ids[i]);
        }
        ecall_delete_counter(global_eid, &result, ids[i]);
        if(!result){
            printf("####### ERROR deleting counter %i\n", ids[i]);
        }
    }

    shutdown_enclave();

    //Cleanup
    free(buff);
}

void test_waiting_migration(const char* me_ip, const char* me_port){
    uint32_t return_value;
    void * buff = (void*) malloc(g_required_size);

    start_enclave();

    //Init new library data
    printf("\n\n\nTESTING RECEIVE MIGRATION. IF YOU DID NOT SEND MIGRATION DATA ALREADY, THIS WILL NEVER TERMINATE!\n\n\n");
    ecall_migration_init(global_eid, &return_value, buff, g_required_size,
                         SGX_MIGR_INIT_MIGRATE, me_ip, me_port);
    printf("Init returned: %x\n", return_value);

    shutdown_enclave();

    //Cleanup
    free(buff);
}

void test_send_migration(const char* me_ip, const char* me_port, const char* dest_ip, const char* dest_port){
    uint32_t return_value;
    void * buff = (void*) malloc(g_required_size);
    bool b_retval;

    // Setting up test environment for counter tests
    int numtests = 2;
    uint8_t ids[numtests];
    uint32_t vals[numtests] = {2, 0};

    start_enclave();

    // Init new library data
    // TODO port/ip
    ecall_migration_init(global_eid, &return_value, buff, g_required_size,
                         SGX_MIGR_INIT_NEW, me_ip, me_port);
    printf("Init returned: %x\n", return_value);

    //ecall_test_seal_unseal(global_eid);

    for(int i = 0; i < numtests; i++){
        ecall_test_create_counter(global_eid, &ids[i], vals[i]);
    }
    //printf("Test create counters function returned: %i\n", init_return);

    ecall_migration_start(global_eid, &return_value, dest_ip, dest_port);
    printf("Migrate returned: %x\n", return_value);

    shutdown_enclave();
}

void run_migration_measurements(int iterations, const char* me_ip, const char* me_port, const char* dest_ip, const char* dest_port){
    void * buff = (void*) malloc(g_required_size);
    uint32_t return_value, sgx_return;
    bool b_retval;
    uint8_t counter_id;
    uint32_t counter_val;
    std::chrono::duration<double> diff;

    std::vector<std::vector<double> > measurements;
    measurements.reserve(iterations);

    std::cout << "Performance measurements for migration - destination IP:Port is:" << dest_ip << ":" << dest_port << std::endl;
    std::cout << "Starting measurements:" << std::endl;
    for(int i = 1; i <= iterations; i++){
        std::cout << "Iteration " << i << " of " << iterations << std::endl;
        std::vector<double> single_line;
        single_line.reserve(2);

        start_enclave();

        // Init new library data
        ecall_migration_init(global_eid, &return_value, buff, g_required_size,
                             SGX_MIGR_INIT_NEW, me_ip, me_port);
       
        //Measure outgoing migration
        auto start = std::chrono::high_resolution_clock::now();
        ecall_migration_start(global_eid, &return_value, dest_ip, dest_port);
        auto end = std::chrono::high_resolution_clock::now();
        diff = end - start;
        single_line.push_back(diff.count());
        
        //Restart enclave to test incoming functions
        restart_enclave();

        //Test receive migration
        start = std::chrono::high_resolution_clock::now();
        ecall_migration_init(global_eid, &return_value, buff, g_required_size,
            SGX_MIGR_INIT_MIGRATE, me_ip, me_port);
        end = std::chrono::high_resolution_clock::now();
        diff = end - start;
        single_line.push_back(diff.count());

        shutdown_enclave();

    }

    std::cout << "Finished migration measurements" << std::endl;

    //Log the measurements to a file
    char filename[255];
    struct tm* tm;
    time_t now;
    now = time(0); // get current time
    tm = localtime(&now); // get structure
    //Folder/Filename:
    sprintf(filename, "measurements/migration_%04d-%02d-%02d_%02d-%02d-%02d", tm->tm_year+1900, tm->tm_mon+1,
        tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec );
    //open stream to new file
    std::ofstream out_stream(filename);
    //log a header
    out_stream << "migrate_out,migrate_in\n";
    // log the data
    for (const std::vector<double> e : measurements){
        for(const double &d : e){
            out_stream << d << ",";
        }
        out_stream << "\n";
    }
    out_stream.close();
}

void run_performance_measurements(int iterations, const char* me_ip, const char* me_port){
    uint32_t return_value, sgx_return;
    void * buff = (void*) malloc(g_required_size);
    bool b_retval;
    uint8_t counter_id;
    uint32_t counter_val;
    std::chrono::duration<double> diff;

    //Prepare source buffers
    uint8_t *reference_buff_mac = (uint8_t *) malloc(g_test_length_mac);
    uint8_t *reference_buff_enc = (uint8_t *) malloc(g_test_length_enc);
    int fd = open("/dev/urandom", O_RDONLY);
    //Prepare test buffers
    void *test_buff_sealed = (void *) malloc(g_test_length_sealed_blob);
    uint8_t *test_buff_mac = (uint8_t *) malloc(g_test_length_mac);
    uint8_t *test_buff_enc = (uint8_t *) malloc(g_test_length_enc);

    std::cout << "Setting up performance done. Prepared random buffers of size "
            << g_test_length_mac << ";" << g_test_length_enc << " for MAC;ENC length" << std::endl;



    std::vector<std::vector<double> > measurements;
    measurements.reserve(iterations);

    std::cout << "Starting measurements:" << std::endl;
    for(int i = 1; i <= iterations; i++){
        std::cout << "Iteration " << i << " of " << iterations << std::endl;
        std::vector<double> single_line;
        single_line.reserve(6);

        //Start enclave
        start_enclave();

        //null out buffers and fill reference buffers
        read(fd, reference_buff_mac, g_test_length_mac);
        read(fd, reference_buff_enc, g_test_length_enc);
        memset(test_buff_enc,0,g_test_length_enc);
        memset(test_buff_mac,0,g_test_length_mac);


        //Init a new data blob
        auto start = std::chrono::high_resolution_clock::now();
        ecall_migration_init(global_eid, &return_value, buff, g_required_size, SGX_MIGR_INIT_NEW, me_ip, me_port);
        auto end = std::chrono::high_resolution_clock::now();
        diff = end - start;
        single_line.push_back(diff.count());

        restart_enclave();

        //Init with reload data blob
        start = std::chrono::high_resolution_clock::now();
        ecall_migration_init(global_eid, &return_value, buff, g_required_size, SGX_MIGR_INIT_RESTORE, me_ip, me_port);
        end = std::chrono::high_resolution_clock::now();
        diff = end - start;
        single_line.push_back(diff.count());

        //Create new counter
        start = std::chrono::high_resolution_clock::now();
        ecall_create_counter(global_eid, &counter_id);
        end = std::chrono::high_resolution_clock::now();
        diff = end - start;
        single_line.push_back(diff.count());

        //Increase counter
        start = std::chrono::high_resolution_clock::now();
        ecall_increase_counter(global_eid, &counter_val, counter_id);
        end = std::chrono::high_resolution_clock::now();
        diff = end - start;
        single_line.push_back(diff.count());

        //Read counter
        start = std::chrono::high_resolution_clock::now();
        ecall_read_counter(global_eid, &counter_val, counter_id);
        end = std::chrono::high_resolution_clock::now();
        diff = end - start;
        single_line.push_back(diff.count());

        //Destroy counter
        start = std::chrono::high_resolution_clock::now();
        ecall_fast_destroy_counter(global_eid, counter_id);
        end = std::chrono::high_resolution_clock::now();
        diff = end - start;
        single_line.push_back(diff.count());

        //Test seal
        start = std::chrono::high_resolution_clock::now();
        sgx_return = ecall_seal(global_eid, &return_value, g_test_length_mac, reference_buff_mac, g_test_length_enc, reference_buff_enc, g_test_length_sealed_blob, test_buff_sealed);
        end = std::chrono::high_resolution_clock::now();
        diff = end - start;
        single_line.push_back(diff.count());

        //Test unseal
        start = std::chrono::high_resolution_clock::now();
        sgx_return = ecall_unseal(global_eid, &return_value, test_buff_sealed, g_test_length_sealed_blob, test_buff_mac, g_test_length_mac, test_buff_enc, g_test_length_enc);
        end = std::chrono::high_resolution_clock::now();
        diff = end - start;
        single_line.push_back(diff.count());

        if(memcmp(test_buff_mac, reference_buff_mac, g_test_length_mac) != 0 ||
           memcmp(test_buff_enc, reference_buff_enc, g_test_length_enc) != 0){
            printf("Buffers not equal!");
            abort();
        }

        shutdown_enclave();

        measurements.push_back(single_line);
    }
    std::cout << "Finished measurements" << std::endl;

    //Log the measurements to a file
    char filename[255];
    struct tm* tm;
    time_t now;
    now = time(0); // get current time
    tm = localtime(&now); // get structure
    //Folder/Filename:
    sprintf(filename, "measurements/%04d-%02d-%02d_%02d-%02d-%02d", tm->tm_year+1900, tm->tm_mon+1,
        tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec );
    //open stream to new file
    std::ofstream out_stream(filename);
    //log a header
    out_stream << "init_new,init_restore,counter_create,counter_increase,counter_read,counter_destroy,seal,unseal\n";
    // log the data
    for (const std::vector<double> e : measurements){
        for(const double &d : e){
            out_stream << d << ",";
        }
        out_stream << "\n";
    }
    out_stream.close();

}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    variables_map vm;
    std::string me_ip, me_port, dest_ip, dest_port;
    int num_tests;

    try{
        options_description desc{"Options"};
        desc.add_options()
          ("help,h", "Help screen")
          ("me_ip", value<std::string>(&me_ip)->default_value("127.0.0.1"), "IP address of local Migration Enclave")
          ("me_port", value<std::string>(&me_port)->default_value("1300"), "Port of local Migration Enclave")
          ("dest_ip", value<std::string>(&dest_ip)->default_value("127.0.0.1"), "IP address of destination for migration")
          ("dest_port", value<std::string>(&dest_port)->default_value("1300"), "Port of destination for migration")
          ("test,t", "Test a full self-enclosed two-hop migration")
          ("send,s", "Send a migration to ME")
          ("receive,r", "Receive a migration from ME")
          ("measurements,m", value<int>(&num_tests), "Run performance measurements")
          ("migration,g", value<int>(&num_tests), "Run migration measurements")
          ("mac_data", value<uint32_t>(&g_test_length_mac)->default_value(100000), "MAC size used for testing sealing")
          ("enc_data", value<uint32_t>(&g_test_length_enc)->default_value(100000), "ENC size used for testing sealing");


        store(parse_command_line(argc, argv, desc), vm);
        notify(vm);

        if (vm.count("help") || argc == 1){
          std::cout << desc << '\n';
          return 0;
        }
      }
      catch (const error &ex){
        std::cerr << ex.what() << '\n';
        return -1;
    }

    const char* me_ip_char = me_ip.c_str();
    const char* me_port_char = me_port.c_str();
    const char* dest_ip_char = dest_ip.c_str();
    const char* dest_port_char = dest_port.c_str();

    // Setup: Changing dir to where the executable is.
    char absolutePath [MAX_PATH];
    char *ptr = NULL;

    ptr = realpath(dirname(argv[0]),absolutePath);

    if( chdir(absolutePath) != 0)
    		abort();

    /*
     * Start enclave to read out required migration size
     */
    start_enclave();

    // Read required g_required_size
    ecall_get_migration_data_size(global_eid, &g_required_size);
    if(g_required_size == UINT32_MAX){
        printf("ERROR reading sealed data g_required_size\n");
    }

    // Read required size for our test seal buffer
    ecall_get_required_size(global_eid, &g_test_length_sealed_blob, g_test_length_mac, g_test_length_enc);
    if(g_test_length_sealed_blob == UINT32_MAX){
        printf("ERROR reading sealed data g_test_length_sealed_blob\n");
    }

    printf("Setting up environment done\n");
    shutdown_enclave();

    if(vm.count("test")){
        printf("Testing a full self-enclosed two hop migration:\n");
        test_two_hop_migration(me_ip_char, me_port_char, dest_ip_char, dest_port_char);
    }

    if(vm.count("send")){
        printf("Sending an outgoing migration.\n");
        test_send_migration(me_ip_char, me_port_char, dest_ip_char, dest_port_char);
    }

    if(vm.count("receive")){
        printf("Receiving (and possibly waiting for) an incoming migration.\n");
        test_waiting_migration(me_ip_char, me_port_char);
    }

    if(vm.count("measurements")){
        printf("Performance measurements:\n");
        auto start = std::chrono::high_resolution_clock::now();
        run_performance_measurements(num_tests, me_ip_char, me_port_char);
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> diff = end - start;
        printf("Measurements done after %lf seconds\n", diff.count());
    }

    if(vm.count("migration")){
        printf("Migration measurements:\n");
        auto start = std::chrono::high_resolution_clock::now();
        run_migration_measurements(num_tests, me_ip_char, me_port_char, dest_ip_char, dest_port_char);
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> diff = end - start;
        printf("Migration measurements done after %lf seconds\n", diff.count());
    }
    
    return 0;
}
