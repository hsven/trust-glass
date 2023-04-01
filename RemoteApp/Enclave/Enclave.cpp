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
#include <algorithm>
#include <map>
#include <random>

#include "TrustedLibrary/ResponseManager.cpp"

EC_KEY *keyPair = NULL;
EC_POINT *peerPoint = NULL;
unsigned char* secretKey = NULL;

EC_KEY* longTermKeyPair = NULL;
EVP_PKEY* longTermKeyPair_pkey =  EVP_PKEY_new();

EC_KEY* longTermPeerKey = NULL;
EVP_PKEY* longTermPeerKey_pkey =  EVP_PKEY_new();

int messageCounter = 0;
ResponseManager resManager = ResponseManager();


/**
 * Creates an alphanumeric string of specified length.
 * Taken from https://stackoverflow.com/questions/440133/how-do-i-create-a-random-alpha-numeric-string-in-c
*/
std::string generate_random_string(const int len) {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    std::string tmp_s;
    tmp_s.reserve(len);


    for (int i = 0; i < len; ++i) {
        char n[12];
        sgx_read_rand(reinterpret_cast<unsigned char*>(&n),
                        sizeof(n));

        tmp_s += alphanum[(*(char*)n) % (sizeof(alphanum) - 1)];
    }
    
    return tmp_s;
}

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 *   Note that the fmt section should end with a new line
 *   
 *   Example: printf("%s", "test\n");
 *            printf("%s\n", "test");
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


ResponseMessage* create_response(std::string headerMsg, std::string mainMsg, bool withSecure) {
    //Generate Response Message
    ResponseMessage* response = new ResponseMessage();
    MessageContent* content = new MessageContent();
    content->header = headerMsg;
    content->message = mainMsg;
    content->freshnessToken = messageCounter;
    std::string contentString = content->generate_final();

    //Prepare Response    
    response->content = base64_encode((unsigned char*) contentString.data(), contentString.length());

    //If message requires security properties
    if (withSecure) {
        //Encrypt response
        //TODO: Message size should not be hardcoded
        unsigned char encryptedMessage[contentString.length() + 256];
        int msgLen = aes_encryption((unsigned char*) contentString.data(), contentString.length(), secretKey, encryptedMessage);
        response->content = base64_encode(encryptedMessage, msgLen);

        //Sign message
        response->digitalSignature = sign_message(contentString.c_str(), longTermKeyPair_pkey);
    }

    //Prints for DEBUG purposes
    printf("%s\n", "From the original creator!");
    printf("Message: %s\n", response->content.c_str());
    printf("Signature: %s\n", response->digitalSignature.c_str());
    printf("Freshess: %d\n", messageCounter);

    messageCounter++;
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
    ResponseMessage* response = create_response("MSG", resManager.prepare_response(in), true);

    char* finalMsg = response->generate_final();
    ocall_send_response(finalMsg, strlen(finalMsg));
}

void ecall_receive_key_pair(const char* in) {
    printf("Peer Key: %s\n", in);

    BIO* bo = BIO_new(BIO_s_mem());
    BIO_write(bo, in, strlen(in));

    if (PEM_read_bio_PrivateKey(bo, &longTermKeyPair_pkey, NULL, NULL) == NULL) {
        printf("PEM_read_bio_PrivateKey: %ld\n",  ERR_get_error());
        BIO_free(bo);
        EVP_PKEY_free(longTermKeyPair_pkey);
        return;
    }

    BIO_free(bo);
}

void ecall_receive_peer_key(const char* in) {
    printf("Peer Key: %s\n", in);

    BIO* bo = BIO_new(BIO_s_mem());
    BIO_write(bo, in, strlen(in));

    if (PEM_read_bio_PUBKEY(bo, &longTermPeerKey_pkey, NULL, NULL) == NULL) {
        printf("PEM_read_bio_PUBKEY: %ld\n",  ERR_get_error());
        BIO_free(bo);
        EVP_PKEY_free(longTermPeerKey_pkey);
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
    char* result = NULL;
    result = EC_POINT_point2hex(ecgroup, pub, POINT_CONVERSION_UNCOMPRESSED, ctx);
    printf("POINT: %s\n", result);
    const char* b64PubKey = base64_encode((const unsigned char*) result, strlen(result));
    printf("KEY: %s\n", b64PubKey);

    BN_CTX_free(ctx);
    OPENSSL_free(result);

    //Generate Response Message
    ResponseMessage* response = create_response("HANDSHAKE", b64PubKey, false);
    char* finalMsg = response->generate_final();
    ocall_send_response(finalMsg, strlen(finalMsg));
}

void ecall_setup_enclave_phase2(const char* encodedPeerKey) {
    //For some reason the string enters with an extra, unwanted, character
    printf("KEY: %s\n", encodedPeerKey);
    unsigned char* decodedPeerKey = NULL;

    int len = base64_decode_len(encodedPeerKey, strlen(encodedPeerKey), &decodedPeerKey);
    std::string hexStr = std::string(OPENSSL_buf2hexstr(decodedPeerKey, len));
    hexStr.erase(std::remove(hexStr.begin(), hexStr.end(), ':'), hexStr.end());
    printf("%s\n", hexStr.data());

    peerPoint = extract_ec_point(hexStr.data());
    if (!peerPoint) {
        printf("%s\n", "Failed to create the EC_POINT for the peer key");
    }
    size_t secretLen;
    secretKey = derive_shared_key(keyPair, peerPoint, &secretLen);
    secretKey[secretLen] = '\0';

    printf("SECRET KEY: %s\nKey Length: %ld\nRegistered Length: %ld\n\n", base64_encode(secretKey, secretLen), secretLen, strlen((const char*) secretKey));

    //Generate Response Message

    resManager.userMenu.clear();
    std::string opt1 = generate_random_string(4);

    std::string opt2 = "abcd";
    do {
        opt2 = generate_random_string(4);
    } while (opt1.compare(opt2) == 0);
    std::string opt3 = "abcd";
    do {
        opt3 = generate_random_string(4);
    } while (opt1.compare(opt3) == 0 && opt2.compare(opt3) == 0);

    resManager.userMenu = {
        {opt1, MenuOptions::EXAMPLE_1},
        {opt2, MenuOptions::EXAMPLE_2},
        {opt3, MenuOptions::EXAMPLE_5},
    };

    std::string resStr = "Welcome!\nType:\n- \'" + opt1 + "\' to enter Menu 1.\n- \'" + opt2 + "\' to enter Menu 2.\n- \'" + opt3 + "\' to enter echo mode.";
    ResponseMessage* response = create_response("MSG", resStr, true);
    char* finalMsg = response->generate_final();
    ocall_send_response(finalMsg, strlen(finalMsg));
}

