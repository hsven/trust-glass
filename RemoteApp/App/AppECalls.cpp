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


}

void ecall_handshake_phase1() {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = ecall_initial_enclave_setup(global_eid);
    if (ret != SGX_SUCCESS)
        abort();
}

void ecall_handshake_phase2(std::string in) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = ecall_finish_setup(global_eid, in.c_str());
    if (ret != SGX_SUCCESS)
        abort();
}