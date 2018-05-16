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
    Migratable seal functions
*/
#include "sgx_tseal.h"   // For seal defines
#include "sgx_tcrypto.h" // For de-,encryption
#include "sgx_trts.h"    // For is_within_enclave functions
#include "string.h"

#include "migration_library.h"
#include "migration_library_internal.h"

/*
 * Migratable seal
 * This function is a modified version of sgx_seal_data in tSeal.cpp.
 * Due to a predefined key being used (MIGR_LIBRARY_DATA.MIGR_SEALING_KEY),
 * the function has been scrapped of all the code required for EGETKEY operation.
 * NOTE: sealed_data.key_request is unspecified with this function. Is that a problem?
 */
MIGRATION_STATUS sgx_seal_migratable_data(const uint32_t additional_MACtext_length,
        const uint8_t *p_additional_MACtext,
        const uint32_t text2encrypt_length,
        const uint8_t *p_text2encrypt,
        const uint32_t sealed_data_size,
        sgx_sealed_data_t *p_sealed_data){

    // Abort if we dont have a key yet
    if(MIGR_LIBRARY_DATA.MIGR_INIT != SGX_MIGR_STATE_INIT_DONE)
        return SGX_MIGR_ERROR_NOT_INITIALIZED;

    sgx_status_t err = SGX_ERROR_UNEXPECTED;
    uint8_t payload_iv[SGX_SEAL_IV_SIZE];
    memset(&payload_iv, 0, sizeof(payload_iv));

    uint32_t sealedDataSize = sgx_calc_sealed_data_size(additional_MACtext_length,text2encrypt_length);
    // Check for overflow
    if (sealedDataSize == UINT32_MAX)
        return SGX_ERROR_INVALID_PARAMETER;

    //
    // Check parameters
    //

    if ((additional_MACtext_length > 0) && (p_additional_MACtext == NULL))
        return SGX_ERROR_INVALID_PARAMETER;
    if ( (text2encrypt_length == 0) ||
         (p_text2encrypt == NULL)   ||
         (!sgx_is_within_enclave(p_text2encrypt,text2encrypt_length)) )
        return SGX_ERROR_INVALID_PARAMETER;
    // Ensure sealed data blob is within an enclave during the sealing process
    if ( (p_sealed_data == NULL) ||
         (!sgx_is_within_enclave(p_sealed_data,sealed_data_size)) )
        return SGX_ERROR_INVALID_PARAMETER;
    // Ensure aad data does not cross enclave boundary
    if ( (additional_MACtext_length > 0) &&
         (!sgx_is_within_enclave(p_additional_MACtext, additional_MACtext_length ||
          sgx_is_outside_enclave(p_additional_MACtext, additional_MACtext_length))) )
        return SGX_ERROR_INVALID_PARAMETER;
    if (sealedDataSize != sealed_data_size)
        return SGX_ERROR_INVALID_PARAMETER;

    memset(p_sealed_data, 0, sealedDataSize);

    // Encrypt the content with the random seal key and the static payload_iv
    err = sgx_rijndael128GCM_encrypt(&(MIGR_LIBRARY_DATA.MIGR_SEALING_KEY),
            p_text2encrypt, text2encrypt_length,
            reinterpret_cast<uint8_t *>(&(p_sealed_data->aes_data.payload)), payload_iv,
            SGX_SEAL_IV_SIZE, p_additional_MACtext, additional_MACtext_length,
            &(p_sealed_data->aes_data.payload_tag));

    if (err == SGX_SUCCESS)
    {
        // Copy additional MAC text
        uint8_t* p_aad = NULL;
        if (additional_MACtext_length > 0)
        {
            p_aad = &(p_sealed_data->aes_data.payload[text2encrypt_length]);
            memcpy(p_aad, p_additional_MACtext, additional_MACtext_length);
        }

        // populate the plain_text_offset, payload_size in the data_blob
        p_sealed_data->plain_text_offset = text2encrypt_length;
        p_sealed_data->aes_data.payload_size = additional_MACtext_length + text2encrypt_length;
    }

    //migrate_log("[ENCLAVE] [MLib] [SEAL_DATA] Sealed migratable data with Mac size %u and ciphertext size %u\n", additional_MACtext_length, text2encrypt_length);

    return err;
}

/*
 * Migratable unseal
 * This function is a modified version of sgx_unseal_data in tSeal.cpp.
 * Due to a predefined key being used (MIGR_LIBRARY_DATA.MIGR_SEALING_KEY),
 * the function has been scrapped of all the code required for EGETKEY operation.
 * NOTE: sealed_data.key_request is unspecified with this function. Is that a problem?
 */
MIGRATION_STATUS sgx_unseal_migratable_data(const sgx_sealed_data_t *p_sealed_data,
        uint8_t *p_additional_MACtext,
        uint32_t *p_additional_MACtext_length,
        uint8_t *p_decrypted_text,
        uint32_t *p_decrypted_text_length){

    // Abort if we dont have a key yet
    if(MIGR_LIBRARY_DATA.MIGR_INIT != SGX_MIGR_STATE_INIT_DONE)
        return SGX_MIGR_ERROR_NOT_INITIALIZED;

    sgx_status_t err = SGX_ERROR_UNEXPECTED;
    // Ensure the the sgx_sealed_data_t members are all inside enclave before using them.
    if( (p_sealed_data == NULL) ||
        !sgx_is_within_enclave(p_sealed_data, sizeof(sgx_sealed_data_t)) )
        return SGX_ERROR_INVALID_PARAMETER;

    uint32_t encrypt_text_length = sgx_get_encrypt_txt_len(p_sealed_data);
    if(encrypt_text_length == UINT32_MAX)
        return SGX_ERROR_MAC_MISMATCH; // Return error indicating the blob is corrupted

    uint32_t add_text_length = sgx_get_add_mac_txt_len(p_sealed_data);
    if(add_text_length == UINT32_MAX)
        return SGX_ERROR_MAC_MISMATCH; // Return error indicating the blob is corrupted

    uint32_t sealedDataSize = sgx_calc_sealed_data_size(add_text_length, encrypt_text_length);
    if (sealedDataSize == UINT32_MAX)
    {
        return SGX_ERROR_MAC_MISMATCH; // Return error indicating the blob is corrupted
    }

    //
    // Check parameters
    //
    // Ensure sealed data blob is within an enclave during the unsealing process
    if (!sgx_is_within_enclave(p_sealed_data, sealedDataSize))
        return SGX_ERROR_INVALID_PARAMETER;
    if ( (add_text_length > 0) &&
         ((p_additional_MACtext == NULL) ||
          (p_additional_MACtext_length == NULL)) )
        return SGX_ERROR_INVALID_PARAMETER;

    if ( (encrypt_text_length < 1) ||
         (p_decrypted_text == NULL) ||
         (p_decrypted_text_length == NULL) )
        return SGX_ERROR_INVALID_PARAMETER;

    if ( !sgx_is_within_enclave(p_decrypted_text,encrypt_text_length) )
        return SGX_ERROR_INVALID_PARAMETER;

    if ( !sgx_is_within_enclave(p_decrypted_text_length, sizeof(p_decrypted_text_length)) )
        return SGX_ERROR_INVALID_PARAMETER;
    //
    // Ensure aad data does not cross enclave boundary
    if ( (add_text_length > 0) &&
         (!sgx_is_within_enclave(p_additional_MACtext, add_text_length) ||
          sgx_is_outside_enclave(p_additional_MACtext, add_text_length)) )
        return SGX_ERROR_INVALID_PARAMETER;

    if ((*p_decrypted_text_length) < encrypt_text_length)
        return SGX_ERROR_INVALID_PARAMETER;

    uint32_t additional_MACtext_length =
        (NULL != p_additional_MACtext_length) ? *p_additional_MACtext_length : 0;

    if (additional_MACtext_length < add_text_length)
        return SGX_ERROR_INVALID_PARAMETER;

    // unseal code
    uint8_t payload_iv[SGX_SEAL_IV_SIZE];
    memset(&payload_iv, 0, SGX_SEAL_IV_SIZE);

    memset(p_decrypted_text, 0, encrypt_text_length);

    if (additional_MACtext_length > 0)
        memset(p_additional_MACtext, 0, additional_MACtext_length);

    err = sgx_rijndael128GCM_decrypt(&(MIGR_LIBRARY_DATA.MIGR_SEALING_KEY),
            const_cast<uint8_t *>(p_sealed_data->aes_data.payload),
            encrypt_text_length, p_decrypted_text, &payload_iv[0], SGX_SEAL_IV_SIZE,
            const_cast<uint8_t *>(&(p_sealed_data->aes_data.payload[encrypt_text_length])),
            additional_MACtext_length,
            const_cast<sgx_aes_gcm_128bit_tag_t *>(&p_sealed_data->aes_data.payload_tag));

    if (err != SGX_SUCCESS)
        return err;

    if (additional_MACtext_length > 0)
        memcpy(p_additional_MACtext,
               &(p_sealed_data->aes_data.payload[encrypt_text_length]), additional_MACtext_length);

    if (err == SGX_SUCCESS)
    {
        *p_decrypted_text_length = encrypt_text_length;
        if(p_additional_MACtext_length != NULL)
            *p_additional_MACtext_length = add_text_length;
    }

    //migrate_log("[ENCLAVE] [MLib] [UNSEAL_DATA] Unsealed migratable data with Mac size %u and cleartext size %u\n", additional_MACtext_length, encrypt_text_length);

    return err;
}
