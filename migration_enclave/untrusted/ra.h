/*
 * ra.h
 *
 * Created on: Aug 31, 2017
 */

#ifndef _MIGRATION_APP_RA_H
#define _MIGRATION_APP_RA_H

#include "sgx_urts.h"
#include "nrt_key_exchange.h"

// TODO Probably remote_enclave_t should be moved to RA,
// or common networking

#include "la_dh.h"
#include "TcpConnection.h"
 
#define ISVSVN_SIZE         2
#define PSDA_SVN_SIZE       4
#define GID_SIZE            4
#define PSVN_SIZE           18

#define HASH_SIZE    32  // SHA256
#define MAC_SIZE     16  // Message Authentication Code
                         // - 16 bytes

#define REPORT_DATA_SIZE         64

typedef uint8_t             measurement_t[HASH_SIZE];
typedef uint8_t             mac_t[MAC_SIZE];
typedef uint8_t             report_data_t[REPORT_DATA_SIZE];
typedef uint16_t            prod_id_t;

#define CPUSVN_SIZE  16

typedef uint8_t             cpu_svn_t[CPUSVN_SIZE];
typedef uint16_t            isv_svn_t;

typedef struct attributes_t
{
    uint64_t                flags;
    uint64_t                xfrm;
} attributes_t;

typedef struct report_body_t {
    cpu_svn_t        cpu_svn;        // (  0) Security Version of the CPU
    uint8_t          reserved1[32];  // ( 16)
    attributes_t     attributes;     // ( 48) Any special Capabilities
                                     //       the Enclave possess
    measurement_t    mr_enclave;     // ( 64) The value of the enclave's
                                     //       ENCLAVE measurement
    uint8_t          reserved2[32];  // ( 96)
    measurement_t    mr_signer;      // (128) The value of the enclave's
                                     //       SIGNER measurement
    uint8_t          reserved3[32];  // (160)
    measurement_t    mr_reserved1;   // (192)
    measurement_t    mr_reserved2;   // (224)
    prod_id_t        isv_prod_id;    // (256) Product ID of the Enclave
    isv_svn_t        isv_svn;        // (258) Security Version of the
                                     //       Enclave
    uint8_t          reserved4[60];  // (260)
    report_data_t    report_data;    // (320) Data provided by the user
} report_body_t;

#pragma pack(push, 1)

typedef uint8_t epid_group_id_t[4];

typedef struct basename_t
{
    uint8_t                 name[32];
} basename_t;

typedef struct quote_nonce_t
{
    uint8_t                 rand[16];
} quote_nonce_t;

#define QUOTE_UNLINKABLE_SIGNATURE 0
#define QUOTE_LINKABLE_SIGNATURE   1

typedef struct quote_t {
    uint16_t         version;        // 0
    uint16_t         sign_type;      // 2
    epid_group_id_t  epid_group_id;  // 4
    isv_svn_t        qe_svn;         // 8
    uint8_t          reserved[6];    // 10
    basename_t       basename;       // 16
    report_body_t    report_body;    // 48
    uint32_t         signature_len;  // 432
    uint8_t          signature[];    // 436
} quote_t;

#pragma pack(pop)

typedef struct _ra_socket_t {
    nrt_ra_context_t context;
    network::TcpConnection::ptr conn;
} ra_socket_t;

int ra_send_quote_to( sgx_enclave_id_t eid, remote_enclave_t destination,
                   ra_socket_t *ra_socket, boost::asio::io_service* ios );

int ra_send_quote( sgx_enclave_id_t eid, ra_socket_t *ra_socket);

int ra_send_migration_data( ra_socket_t* ra_socket, uint8_t *migration_data, int data_len );

int ra_verify_quote( quote_t* quote );

#endif
