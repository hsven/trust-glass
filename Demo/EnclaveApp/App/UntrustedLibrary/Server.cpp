/*
 *  Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License").  You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 */


#include "Server.h"

int create_socket()
{
    int s;
    int optval = 1;
    struct sockaddr_in addr;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(server_port);
    addr.sin_addr.s_addr = INADDR_ANY;

    /* Reuse the address; good for quick restarts */
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval))
            < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return s;
}

SSL_CTX* create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_server_context(SSL_CTX *ctx)
{
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_chain_file(ctx, "cert.pem") <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}


void usage()
{
    printf("Usage: sslecho s\n");
    printf("       --or--\n");
    printf("       sslecho c ip\n");
    printf("       c=client, s=server, ip=dotted ip of server\n");
    exit(1);
}

int create_server(SSL_CTX **ssl_ctx, int* server_skt)
{
    *ssl_ctx = NULL;

    *server_skt = -1;

    /* Splash */
    printf("\nsslecho : Simple Echo Client/Server (OpenSSL 3.0.1-dev) : %s : %s\n\n", __DATE__,
    __TIME__);

    /* Create context used by both client and server */
    *ssl_ctx = create_context();

    printf("We are the server on port: %d\n\n", server_port);

    /* Configure server context with appropriate key files */
    configure_server_context(*ssl_ctx);

    /* Create server socket; will bind with server port and listen */
    *server_skt = create_socket();

    return 0;
}
