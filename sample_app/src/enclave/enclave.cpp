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

#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <string.h>

#include "sgx_tae_service.h"
#include "sgx_tseal.h"

#include "enclave.h"
#include "enclave_t.h"  /* print_string */

#include "migration_library.h"

bool ecall_init_session(){
    sgx_status_t ret = sgx_create_pse_session();
    if(ret == SGX_SUCCESS){
        return true;
    }
    return false;
}

bool ecall_destroy_session(){
    sgx_status_t ret = sgx_close_pse_session();
    if(ret == SGX_SUCCESS){
        return true;
    }
    return false;
}

void ecall_test_seal_unseal(){
    migrate_log("[TEST] [SEAL UNSEAL]\n");
    int ret;
    int secretValue = 1337;
    uint32_t sealed_data_size = sgx_calc_sealed_data_size(0, sizeof(int));
    void* sealed_data = malloc(sealed_data_size);

    ret = sgx_seal_migratable_data(0, NULL,sizeof(int),(uint8_t*)&secretValue,
            sealed_data_size, (sgx_sealed_data_t*)sealed_data);

    migrate_log("Sealed blob with ret code %x\n", ret);

    int unsealed_value;
    uint32_t unsealed_size = sizeof(int);
    ret = sgx_unseal_migratable_data((sgx_sealed_data_t*) sealed_data, NULL, 0, (uint8_t*)&unsealed_value, &unsealed_size);
    migrate_log("Unsealed blob with ret code %x\n", ret);
    migrate_log("Sealed value was %u and unsealed was %u\n", secretValue, unsealed_value);
    if(secretValue == unsealed_value){
        migrate_log("[TEST] [SEAL UNSEAL] SUCCESSFULL\n");
    } else {
        migrate_log("[TEST] [SEAL UNSEAL] ERROR\n");
    }
}

uint32_t ecall_seal(
                uint32_t additional_MACtext_length,
                uint8_t *p_additional_MACtext,
                uint32_t text2encrypt_length,
                uint8_t *p_text2encrypt,
                uint32_t sealed_data_size,
                void *p_sealed_data){
    void *sealed_data = (void *) malloc(sealed_data_size);
    uint32_t ret = sgx_seal_migratable_data(additional_MACtext_length, p_additional_MACtext, text2encrypt_length, p_text2encrypt, sealed_data_size, (sgx_sealed_data_t*) sealed_data);
    memcpy(p_sealed_data, sealed_data, sealed_data_size);

    return ret;
}

uint32_t ecall_unseal(
                void *p_sealed_data,
                uint32_t sealed_data_size,
                uint8_t *p_additional_MACtext,
                uint32_t additional_MACtext_length,
                uint8_t *p_decrypted_text,
                uint32_t decrypted_text_length){

    uint32_t p_additional_MACtext_length = additional_MACtext_length;
    uint32_t p_decrypted_text_length = decrypted_text_length;
    uint8_t *mac_data = (uint8_t *) malloc(additional_MACtext_length);
    uint8_t *enc_data = (uint8_t *) malloc(decrypted_text_length);
    uint32_t ret = sgx_unseal_migratable_data(
            (sgx_sealed_data_t*) p_sealed_data,
            mac_data,
            &p_additional_MACtext_length,
            enc_data,
            &p_decrypted_text_length);

    //Check if sizes match
    if(additional_MACtext_length != p_additional_MACtext_length || decrypted_text_length != p_decrypted_text_length){
        migrate_log("ERROR sealing data: Mismatch in Sizes: %u != %u and/or %u != %u\n", additional_MACtext_length, p_additional_MACtext_length, decrypted_text_length, p_decrypted_text_length);
        return SGX_ERROR_INVALID_ATTRIBUTE;
    }
    memcpy(p_additional_MACtext, mac_data, p_additional_MACtext_length);
    memcpy(p_decrypted_text, enc_data, p_decrypted_text_length);

    return ret;
}

uint32_t ecall_get_required_size(uint32_t add_mac_txt_size, uint32_t txt_encrypt_size){
    return sgx_calc_sealed_data_size(add_mac_txt_size, txt_encrypt_size);
}

uint8_t ecall_test_create_counter(uint32_t test_value)
{
  migrate_log("[TEST CREATE COUNTER]\n");

  //Test counters:
  int ret;
  uint8_t id=0;
  uint32_t val=0;
  ret = sgx_create_migratable_counter(&id, &val);
  migrate_log("Counter created: Return code %x, ID:%u with value %u\n", ret, id, val);

  migrate_log("Increasing counter %u to %u\n", id, test_value);
  for(int i = 0; i < test_value; i++){
      ret = sgx_increment_migratable_counter(id, &val);
      if(val%10 == 0){
          migrate_log("Current value: %u. %u to go.\n", val, test_value - val);
      }
  }
  migrate_log("done\n");

  ret = sgx_read_migratable_counter(id, &val);
  migrate_log("Counter read: Return code %x, ID:%u has value %u\n", ret, id, val);


  return id;
}

uint8_t ecall_create_counter(){
    uint8_t id=0;
    uint32_t val;
    sgx_create_migratable_counter(&id, &val);
    return id;
}

uint32_t ecall_increase_counter(uint8_t id){
    uint32_t val;
    sgx_increment_migratable_counter(id, &val);
    return val;
}

uint32_t ecall_read_counter(uint8_t id){
    uint32_t val;
    sgx_read_migratable_counter(id, &val);
    return val;
}

void ecall_fast_destroy_counter(uint8_t id){
    sgx_destroy_migratable_counter(id);
}

bool ecall_test_counter(uint8_t id, uint32_t expected_value){
    migrate_log("[TEST COUNTER] ");
    bool retval = false;

    //Test counters:
    int ret;
    uint32_t val=0;
    ret = sgx_read_migratable_counter(id, &val);
    if(ret == SGX_SUCCESS){
        if(val == expected_value){
            migrate_log("Counter %i has expected value %u\n", id, val);
            retval = true;
        } else {
            migrate_log("ERROR: Counter %i does NOT have expected value %u but instead has %u\n", id, expected_value, val);
        }
    } else {
        migrate_log("Read counter failed with %x\n", ret);
    }

    return retval;
}

bool ecall_delete_counter(uint8_t id){

    bool retval = false;

    int ret = sgx_destroy_migratable_counter(id);

    if(ret == SGX_SUCCESS){
        migrate_log("[DELETE COUNTER SUCCESS]\n");
        retval = true;
    } else {
        migrate_log("Error deleting counter %i with error code %x\n", id, ret);
    }

    return retval;
}

