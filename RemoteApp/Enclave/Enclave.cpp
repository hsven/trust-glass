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
unsigned char* secretKey = NULL;

RSA* longTermKeyPair = NULL;
RSA* longTermPeerKey = NULL;

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

ResponseMessage* create_response(std::string headerMsg, std::string mainMsg, bool withSecure) {
    //Generate Response Message
    ResponseMessage* response = new ResponseMessage();
    response->header = headerMsg;

    //Prepare Response
    response->message = mainMsg;

    //If message requires security properties
    if (withSecure) {
        //Encrypt response
        //TODO: Message size should not be hardcoded
        unsigned char encryptedMessage[256];
        int msgLen = aes_encryption((unsigned char*) mainMsg.data(), mainMsg.length(), secretKey, encryptedMessage);
        response->message = base64_encode(encryptedMessage, msgLen);

        //Create freshness token
        response->freshnessToken = "";

        //Sign message
        response->digitalSignature = sign_message(mainMsg, longTermKeyPair);
    }

    return response;
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
    response->digitalSignature = sign_message(response->message, longTermKeyPair);

    
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

void ecall_receive_key_pair(const char* in) {
    printf("%s", in);

    BIO* bo = BIO_new(BIO_s_mem());
    BIO_write(bo, in, strlen(in));
    
    if (PEM_read_bio_RSAPrivateKey(bo, &longTermKeyPair, NULL, NULL) == NULL){
        printf("PEM_read_bio_RSAPrivateKey Error: %ld\n",  ERR_get_error());
        return;
    }

    BIO_free(bo);
}

void ecall_receive_peer_key(const char* in) {
    printf("%s", in);

    BIO* bo = BIO_new(BIO_s_mem());
    BIO_write(bo, in, strlen(in));
    
    if (PEM_read_bio_RSA_PUBKEY(bo, &longTermPeerKey, NULL, NULL) == NULL){
        printf("PEM_read_RSA_PUBKEY Error: %ld\n",  ERR_get_error());
        return;
    }

    BIO_free(bo);
}

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
    const char* b64PubKey = base64_encode(result, strlen((char*) result));
    printf("KEY: %s\n", b64PubKey);

    //Generate Response Message
    ResponseMessage* response = create_response("HANDSHAKE", b64PubKey, false);
    char* finalMsg = response->generate_final();
    ocall_send_response(finalMsg, strlen(finalMsg));
}

void ecall_setup_enclave_phase2(const char* encodedPeerKey) {
    //For some reason the string enters with an extra, unwanted, character
    printf("KEY: %s\n", encodedPeerKey);
    unsigned char* decodedPeerKey = base64_decode(encodedPeerKey, strlen(encodedPeerKey));
    printf("DECODED KEY: %s\n", decodedPeerKey);
    peerPoint = extract_ec_point((char*) decodedPeerKey);
    if (!peerPoint) {
        printf("%s\n", "Failed to create the EC_POINT for the peer key");
    }
    size_t secretLen;
    secretKey = derive_shared_key(keyPair, peerPoint, &secretLen);
    secretKey[secretLen] = '\0';

    printf("SECRET KEY: %s\nKey Length: %d\nRegistered Length: %d\n\n", base64_encode(secretKey, secretLen), secretLen, strlen((const char*) secretKey));

    //Generate Response Message
    ResponseMessage* response = create_response("", "Welcome!", true);
    char* finalMsg = response->generate_final();
    ocall_send_response(finalMsg, strlen(finalMsg));
}