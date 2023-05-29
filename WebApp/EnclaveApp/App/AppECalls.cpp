#include "sgx_urts.h"
#include "Enclave_u.h"
#include <string>
#include <fstream>

sgx_enclave_id_t global_eid = 0;

void ecall_hello() {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = ecall_hello_world(global_eid);
    if (ret != SGX_SUCCESS)
        abort();
}

void ecall_init() {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = ecall_init_TrustGlass(global_eid);
    if (ret != SGX_SUCCESS)
        abort();
}

void ecall_send_input(std::string in) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = ecall_receive_input(global_eid, in.c_str());
    if (ret != SGX_SUCCESS)
        abort();
}

void ecall_send_key() {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    //TODO: Remove hardcoded key

    std::ifstream teeKey("EC_TEEPrivKey.pem");
    std::string teeKeyContent( (std::istreambuf_iterator<char>(teeKey) ),
                         (std::istreambuf_iterator<char>()       ) );

    ret = ecall_receive_key_pair(global_eid, teeKeyContent.c_str());
    if (ret != SGX_SUCCESS)
        abort();

    std::ifstream glassKey("EC_GlassPubKey.pem");
    std::string glassKeyContent( (std::istreambuf_iterator<char>(glassKey) ),
             (std::istreambuf_iterator<char>()       ) );
    ret = ecall_receive_peer_key(global_eid, glassKeyContent.c_str());
    if (ret != SGX_SUCCESS)
        abort();

    // LTK Section
    std::ifstream sharedLTKey("sharedLTKeyB64.txt");
    if (sharedLTKey.good()) {
        std::string sharedLTKeyContent( (std::istreambuf_iterator<char>(sharedLTKey) ),
                (std::istreambuf_iterator<char>()       ) );
        ret = ecall_receive_long_term_shared_key(global_eid, sharedLTKeyContent.c_str());
        if (ret != SGX_SUCCESS)
            abort();
    }
}

void ecall_handshake() {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = ecall_setup(global_eid);
    if (ret != SGX_SUCCESS)
        abort();
}

void ecall_pin_auth() {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = ecall_pin_login(global_eid);
    if (ret != SGX_SUCCESS)
        abort();
}