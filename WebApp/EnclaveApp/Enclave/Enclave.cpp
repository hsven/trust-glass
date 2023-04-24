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
    // ocall_print_string(buf);
    // ocall_print_qr_code(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

void send_response(std::string header, std::string content, bool isSecure) {
    ResponseMessage* response = trustGlass->create_response(header, content, isSecure);
    char* finalMsg = response->generate_final();
    ocall_send_response(finalMsg, strlen(finalMsg));
}

void generate_welcome_message() {
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
    
    send_response("MSG", resStr, true);
}


void ecall_hello_world(void)
{
    const char* hello = "HelloWorld!\n";
    printf("%s", hello);
}

void ecall_init_TrustGlass() {
    trustGlass = new TrustGlass();
}


void ecall_receive_key_pair(const char* in) {
    printf("Key Pair:\n%s\n", in);
    trustGlass->set_key_pair(in);
}


void ecall_receive_peer_key(const char* in) {
    printf("Peer Key:\n%s\n", in);
    trustGlass->set_peer_key(in);
}

void ecall_receive_otp_key(const char * in) {
    printf("%s\n", in);
    trustGlass->set_otp_key(in);
}

void ecall_request_otp_challenge() {
    // trustGlass->create_otp_value();
    char* otp = trustGlass->create_otp_value().data();
    printf("%s\n", otp);
    send_response("OTP", otp, true);
}

void ecall_verify_otp_reponse(const char* in) {
    printf("%s\n", in);
    if (trustGlass->verify_otp_entry(in))
        generate_welcome_message();
        // send_response("OTP", "OTP Success", true);
    else
        send_response("ERROR", "OTP ERROR - Response did not match challenge", true);
}

void ecall_start_setup() {
    const char* pubKey = trustGlass->retrieve_public_EC_session_key().c_str();
    printf("%s\n", pubKey);
    // if(pubKey.empty()) {
    //     send_response("ERROR", "Setup: Failed to retrieve public EC key", false);
    //     return;
    // }

    send_response("HANDSHAKE", pubKey, false);
}

void ecall_finish_setup(const char* encodedPeerKey) {
    if(!trustGlass->derive_secret_key(encodedPeerKey)) {
        send_response("ERROR", "Setup: Faied to process the received key", false);
        return;
    }
    // generate_welcome_message();
}

void ecall_receive_input(const char* in) {
    send_response("MSG", resManager.prepare_response(in), true);
}
