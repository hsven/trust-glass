#include "sgx_urts.h"
#include "Enclave_u.h"
#include <string>

sgx_enclave_id_t global_eid = 0;

void ecall_hello() {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = ecall_hello_world(global_eid);
    if (ret != SGX_SUCCESS)
        abort();
}

void ecall_send_input(std::string in) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    // char* response = new char[4096];

    ret = ecall_receive_input(global_eid, in.c_str());
    if (ret != SGX_SUCCESS)
        abort();

    // return response;
}

void ecall_send_key() {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    //TODO: Remove hardcoded key
    std::string tempKey = "n8lD7d1jI96cLSxjP4UI7ywGRW0PXKZHAx6dZJGMUCQ=";

    // std::string message = rsaEncrypt(rsaEncrypt(tempKey, ""), "");

    // ret = ecall_receive_shared_key(global_eid, tempKey.c_str());
    // if (ret != SGX_SUCCESS)
    //     abort();
}

void ecall_handshake() {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = ecall_setup_enclave(global_eid);
    if (ret != SGX_SUCCESS)
        abort();
}