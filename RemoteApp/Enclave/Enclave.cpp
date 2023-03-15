/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
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

#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string>

EC_KEY *keyPair = NULL;
EC_POINT *peerPoint = NULL;

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_debug_print(buf);
    // ocall_print_string(buf);
    // ocall_print_qr_code(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

/* 
 * prepare_response: 
 *   Creates an adequate response according to the input command.
 */
std::string prepare_response(std::string in) {
    std::string response = "response_";
    return response + in;
}



void ecall_hello_world(void)
{
    const char* hello = "HelloWorld!\n";
    printf("%s", hello);
}

void ecall_receive_input(const char* in) {
    //Decrypt message

    //Generate Response Message
    ResponseMessage* response = new ResponseMessage();

    //Prepare Response
    response->message = prepare_response(in);

    //Create freshness token
    response->freshnessToken = "";

    //Sign message
    response->digitalSignature = sign_message(response->message);

    
    //Prints for DEBUG purposes
    printf("Message: %s\n", response->message.c_str());
    printf("Signature: %s\n", response->digitalSignature.c_str());
    printf("Fresh Token: %s\n", response->freshnessToken.c_str());


    // *out = response->generate_final();
    // ocall_print_qr_code(response->generate_final());
    char* finalMsg = response->generate_final();
    ocall_send_response(finalMsg, strlen(finalMsg));

    // return res;
}

// void ecall_receive_shared_key(const char* in) {
//     printf("%s", in);
// }

void ecall_setup_enclave_phase1(void) {
    //Prepare keys
    const char* hello = "TEST!";
    printf("%s\n", hello);

    EC_GROUP *ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if(!generate_ec_key_pair(&keyPair)) {
        printf("%s\n", "Error generating keypair");
        return;
    }
    

    EC_POINT const* pub = EC_KEY_get0_public_key(keyPair);
    if(!pub)
    {
        EC_KEY_free(keyPair);
        return;
    }
    BN_CTX *ctx;
    ctx = BN_CTX_new();
    const unsigned char* result = NULL;
    result = (const unsigned char*) EC_POINT_point2hex(ecgroup, pub, POINT_CONVERSION_UNCOMPRESSED, ctx);
    printf("POINT: %s\n", result);
    const char* b64PubKey = convert_to_base64(result, strlen((char*) result));
    printf("KEY: %s\n", b64PubKey);

    //Generate Response Message
    ResponseMessage* response = new ResponseMessage();
    response->header = "HANDSHAKE";

    //Prepare Response
    response->message = b64PubKey;

    //Create freshness token
    response->freshnessToken = "";

    //Sign message
    response->digitalSignature = "";

    char* finalMsg = response->generate_final();
    ocall_send_response(finalMsg, strlen(finalMsg));
}

void ecall_setup_enclave_phase2(const char* encodedPeerKey) {
    //For some reason the string enters with an extra, unwanted, character
    printf("KEY: %s\n", encodedPeerKey);
    unsigned char* decodedPeerKey = decode_from_base64(encodedPeerKey, strlen(encodedPeerKey));
    printf("DECODED KEY: %s\n", decodedPeerKey);
    peerPoint = extract_ec_point((char*) decodedPeerKey);
    if (!peerPoint) {
        printf("%s\n", "Failed to create the EC_POINT for the peer key");
    }
    size_t secretLen;
    unsigned char* secretKey = derive_shared_key(keyPair, peerPoint, &secretLen);

    printf("SECRET KEY: %s\nLEN: %d", convert_to_base64(secretKey, secretLen), secretLen);
}