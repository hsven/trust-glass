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

#include "TrustedLibrary/ResponseManager.cpp"

TrustGlass* trustGlass = NULL;
ResponseManager resManager = ResponseManager();

int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_debug_print(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

void send_response(std::string header, std::string content, std::string map, bool signWithSessionKeys) {
    ResponseMessage* response = trustGlass->create_response(header, content, map, signWithSessionKeys);
    char* finalMsg = response->generate_final();
    ocall_send_response(finalMsg, strlen(finalMsg));
}

void generate_welcome_message() {
    std::string resStr = resManager.generate_home_message();
    send_response("MSG", "Welcome!\n" + resStr, "null", true);
}


void ecall_hello_world(void)
{
    const char* hello = "HelloWorld!\n";
    printf("%s", hello);
}

void ecall_init_TrustGlass() {
    trustGlass = new TrustGlass();
    resManager.set_TrustGlass(trustGlass);
}


void ecall_receive_key_pair(const char* in) {
    printf("Key Pair:\n%s\n", in);
    trustGlass->set_key_pair(in);
}


void ecall_receive_peer_key(const char* in) {
    printf("Peer Key:\n%s\n", in);
    trustGlass->set_peer_key(in);
}

void ecall_receive_long_term_shared_key(const char* in) {
    printf("LT Key: %s\n", in);
    trustGlass->set_long_term_shared_key(in);
}

void ecall_pin_login() {

    std::map<char, char>* keyboard = trustGlass->create_random_keyboard("0123456789");
    std::string keyboardOut = trustGlass->map_to_string(keyboard);

    trustGlass->currentState = TrustGlassStates::IN_AUTH;
    send_response("HANDSHAKE", "Please insert your PIN following the defined number mapping", keyboardOut, true);
}

void ecall_request_otp_challenge() {
    std::string otp = trustGlass->create_otp_value();
    trustGlass->currentState = TrustGlassStates::IN_OTP;
    send_response("OTP", otp, "null", true);
}

void ecall_verify_otp_reponse(const char* in) {
    printf("%s\n", in);
    if (trustGlass->verify_otp_entry(in))
        ecall_pin_login();
    else
        send_response("ERROR", "OTP ERROR - Response did not match challenge", "null", false);
}



void ecall_auth(const char* input) {
    const char* result = trustGlass->decipher_randomized_string(input).c_str();
    printf("Decipher Result: %s\n", result);
    // TODO: Don't hardcode passwords
    if (!strcmp(result, "1234"))
        generate_welcome_message();
    else 
        send_response("ERROR", "AUTH ERROR - Wrong Password", "null", false);
}

void ecall_setup() {
    const char* response = trustGlass->create_session();

    printf("Encoded LTK: %s\n", trustGlass->longTermSharedKey);
    printf("Encoded NONCE: %s\n", response);
    printf("Encoded session key: %s\n", base64_encode(trustGlass->sessionKey, 32));
    send_response("HANDSHAKE", response, "null", false);
}

void ecall_receive_input(const char* in) {
    if (trustGlass->currentState == TrustGlassStates::IN_OTP) {
        ecall_verify_otp_reponse(in);
        return;
    }
    if (trustGlass->currentState == TrustGlassStates::IN_AUTH) {
        ecall_auth(in);
        return;
    }
    std::string map = "null";
    std::string content = resManager.prepare_response(in, &map);
    send_response("MSG", content, map, true);
}
