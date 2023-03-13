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


#include <stdio.h>
// #include <string>
#include <assert.h>
#include <iostream>
# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"
#include "AppOCalls.cpp"
#include "AppECalls.cpp"

#include "UntrustedLibrary/Server.h"
/* Global EID shared by multiple threads */
// sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
    {
        SGX_ERROR_MEMORY_MAP_FAILURE,
        "Failed to reserve memory for the enclave.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    return 0;
}

// std::string rsaEncrypt(std::string message, std::string key) {

// }


/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    // exit(0);


    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }
 
    /* Utilize edger8r attributes */
    // edger8r_array_attributes();
    // edger8r_pointer_attributes();
    // edger8r_type_attributes();
    // edger8r_function_attributes();
    
    // /* Utilize trusted libraries */
    // ecall_libc_functions();
    // ecall_libcxx_functions();
    // ecall_thread_functions();

    // ecall_hello();

    ecall_send_key();

    std::string x = "Hello World!\n";
    // generate_QR_code(x);
    // ecall_send_input(x);
    
    // while (x.compare("") != 0) {
    //     std::cout << "\nInput string (Empty to exit): ";
    //     std::getline(std::cin, x);
    
    //     ecall_send_input(x);
    // }

    // ecall_sum();
    std::cout << "\n";
    /* Destroy the enclave */


    SSL_CTX *ssl_ctx = NULL;
    // SSL *ssl = NULL;
    int server_skt = -1;
    int client_skt = -1;
    bool is_server_running = true;
    char rxbuf[128];
    size_t rxcap = sizeof(rxbuf);
    int rxlen;
    struct sockaddr_in addr;
    unsigned int addr_len = sizeof(addr);
    server_loop(&ssl_ctx, &server_skt);

    while (is_server_running) {
        /* Wait for TCP connection from client */
        client_skt = accept(server_skt, (struct sockaddr*) &addr,
                &addr_len);
        if (client_skt < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        printf("Client TCP connection accepted\n");

        /* Create server SSL structure using newly accepted client socket */
        ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, client_skt);
        printf("YOO\n");

        /* Wait for SSL connection from the client */
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            is_server_running = false;
        } else {

            printf("Client SSL connection accepted\n\n");

            ecall_handshake();

            /* Echo loop */
            while (true) {
                /* Get message from client; will fail if client closes connection */
                if ((rxlen = SSL_read(ssl, rxbuf, rxcap)) <= 0) {
                    if (rxlen == 0) {
                        printf("Client closed connection\n");
                    }
                    ERR_print_errors_fp(stderr);
                    break;
                }
                /* Insure null terminated input */
                rxbuf[rxlen] = 0;
                /* Look for kill switch */
                if (strcmp(rxbuf, "kill\n") == 0) {
                    /* Terminate...with extreme prejudice */
                    printf("Server received 'kill' command\n");
                    is_server_running = false;
                    break;
                }
                /* Show received message */
                // printf("Received: %s", rxbuf);

                // char* response = new char[4098];
                ecall_send_input(std::string(rxbuf));
                // char destination[strlen(response) + 1];
                // strcpy(destination, response);
                // TODO:: Seems like utilizing the string in any capacity causes a seg fault, idk why
                /* Echo it back */
                // printf("THE RESPONSEW: %s", response);
                // if (SSL_write(ssl, "OK", strlen("OK")) <= 0) {
                //     ERR_print_errors_fp(stderr);
                // }

                // delete response;
            }
        }
        if (is_server_running) {
            /* Cleanup for next client */
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_skt);
        }
    }


    sgx_destroy_enclave(global_eid);
    
    printf("Info: SampleEnclave successfully returned.\n");

    // printf("Enter a character before exit ...\n");
    // getchar();
    return 0;
}