/*
 * Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

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

#include "marshalling.h"
#include "sgx_eid.h"
#include "stdlib.h"
#include "string.h"

#include "la_dh.h"
#include "sgx_error.h"
#include "tla.h"

/*
 * Migration data type
 */
ATTESTATION_STATUS marshal_migration_data_message(uint32_t msg_type,
        migration_data_t *p_data, char** marshalled_buff, size_t* marshalled_buff_len)
{
    attestation_msg_t *ms;
    size_t param_len, ms_len;
    char *temp_buff;
    if(!marshalled_buff_len)
        return SGX_ERROR_INVALID_PARAMETER;

    if(p_data){
        param_len = sizeof(migration_data_t);
        temp_buff = (char*)malloc(param_len);
        if(!temp_buff)
            return SGX_ATT_ERROR_MALLOC_ERROR;
        memcpy(temp_buff, p_data, sizeof(migration_data_t)); //can be optimized
    } else {
        param_len = 0;
        temp_buff = NULL;
    }
    ms_len = sizeof(attestation_msg_t) + param_len;
    ms = (attestation_msg_t *)malloc(ms_len);
    if(!ms)
    {
        SAFE_FREE(temp_buff);
        return SGX_ATT_ERROR_MALLOC_ERROR;
    }
    ms->msg_type = msg_type;
    ms->inparam_buff_len = (uint32_t)param_len;
    if(param_len > 0){
        memcpy(&ms->inparam_buff, temp_buff, param_len);
    }
    *marshalled_buff = (char*)ms;
    *marshalled_buff_len = ms_len;
    SAFE_FREE(temp_buff);
    return SGX_SUCCESS;
}

ATTESTATION_STATUS unmarshal_migration_data_message(attestation_msg_t* ms,
        uint32_t *msg_type, migration_data_t *p_data)
{
    if(!p_data || !ms)
        return SGX_ERROR_INVALID_PARAMETER;

    if(ms->inparam_buff_len == (sizeof(migration_data_t))){
        // fill buffer only if size matches. Otherwise ignore
        memcpy(p_data, ms->inparam_buff, ms->inparam_buff_len);
    } else {
        return SGX_ERROR_NETWORK_FAILURE;
    }

    *msg_type = ms->msg_type;
    return SGX_SUCCESS;
}

/*
 * Remote enclave type
 */
ATTESTATION_STATUS marshal_remote_enclave_message(uint32_t msg_type,
        remote_enclave_t *p_data, char** marshalled_buff, size_t* marshalled_buff_len)
{
    attestation_msg_t *ms;
    size_t param_len, ms_len;
    char *temp_buff;
    if(!marshalled_buff_len)
        return SGX_ERROR_INVALID_PARAMETER;

    if(p_data){
        param_len = sizeof(remote_enclave_t);
        temp_buff = (char*)malloc(param_len);
        if(!temp_buff)
            return SGX_ATT_ERROR_MALLOC_ERROR;
        memcpy(temp_buff, p_data, sizeof(remote_enclave_t)); //can be optimized
    } else {
        param_len = 0;
        temp_buff = NULL;
    }
    ms_len = sizeof(attestation_msg_t) + param_len;
    ms = (attestation_msg_t *)malloc(ms_len);
    if(!ms)
    {
        SAFE_FREE(temp_buff);
        return SGX_ATT_ERROR_MALLOC_ERROR;
    }
    ms->msg_type = msg_type;
    ms->inparam_buff_len = (uint32_t)param_len;
    if(param_len > 0){
        memcpy(&ms->inparam_buff, temp_buff, param_len);
    }
    *marshalled_buff = (char*)ms;
    *marshalled_buff_len = ms_len;
    SAFE_FREE(temp_buff);
    return SGX_SUCCESS;
}

ATTESTATION_STATUS unmarshal_remote_enclave_message(attestation_msg_t* ms,
        uint32_t *msg_type, remote_enclave_t *p_data)
{
    if(!p_data || !ms)
        return SGX_ERROR_INVALID_PARAMETER;

    if(ms->inparam_buff_len == (sizeof(remote_enclave_t))){
        // fill buffer only if size matches. Otherwise ignore
        memcpy(p_data, ms->inparam_buff, ms->inparam_buff_len);
    } else {
        return SGX_ERROR_NETWORK_FAILURE;
    }

    *msg_type = ms->msg_type;
    return SGX_SUCCESS;
}
