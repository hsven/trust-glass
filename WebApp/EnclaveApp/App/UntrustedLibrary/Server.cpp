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

int server_loop(SSL_CTX **ssl_ctx, int* server_skt)
{
    // SSL_CTX *ssl_ctx = NULL;
    *ssl_ctx = NULL;
    // SSL *ssl = NULL;

    *server_skt = -1;
    // int client_skt = -1;

    // char rxbuf[128];
    // size_t rxcap = sizeof(rxbuf);
    // int rxlen;

    // struct sockaddr_in addr;
    // unsigned int addr_len = sizeof(addr);

    /* Splash */
    printf("\nsslecho : Simple Echo Client/Server (OpenSSL 3.0.1-dev) : %s : %s\n\n", __DATE__,
    __TIME__);

    /* Need to know if client or server */
    // if (argc < 2) {
    //     usage();
    //     /* NOTREACHED */
    // }
    // isServer = (argv[1][0] == 's') ? true : false;
    /* If client get remote server address (could be 127.0.0.1) */
    // if (!isServer) {
    //     if (argc != 3) {
    //         usage();
    //         /* NOTREACHED */
    //     }
    //     rem_server_ip = argv[2];
    // }

    /* Create context used by both client and server */
    *ssl_ctx = create_context();

    printf("We are the server on port: %d\n\n", server_port);

    /* Configure server context with appropriate key files */
    configure_server_context(*ssl_ctx);

    /* Create server socket; will bind with server port and listen */
    *server_skt = create_socket();

    /*
        * Loop to accept clients.
        * Need to implement timeouts on TCP & SSL connect/read functions
        * before we can catch a CTRL-C and kill the server.
        */
    // while (server_running) {
    //     /* Wait for TCP connection from client */
    //     client_skt = accept(server_skt, (struct sockaddr*) &addr,
    //             &addr_len);
    //     if (client_skt < 0) {
    //         perror("Unable to accept");
    //         exit(EXIT_FAILURE);
    //     }

    //     printf("Client TCP connection accepted\n");

    //     /* Create server SSL structure using newly accepted client socket */
    //     ssl = SSL_new(ssl_ctx);
    //     SSL_set_fd(ssl, client_skt);

    //     /* Wait for SSL connection from the client */
    //     if (SSL_accept(ssl) <= 0) {
    //         ERR_print_errors_fp(stderr);
    //         server_running = false;
    //     } else {

    //         printf("Client SSL connection accepted\n\n");

    //         /* Echo loop */
    //         while (true) {
    //             /* Get message from client; will fail if client closes connection */
    //             if ((rxlen = SSL_read(ssl, rxbuf, rxcap)) <= 0) {
    //                 if (rxlen == 0) {
    //                     printf("Client closed connection\n");
    //                 }
    //                 ERR_print_errors_fp(stderr);
    //                 break;
    //             }
    //             /* Insure null terminated input */
    //             rxbuf[rxlen] = 0;
    //             /* Look for kill switch */
    //             if (strcmp(rxbuf, "kill\n") == 0) {
    //                 /* Terminate...with extreme prejudice */
    //                 printf("Server received 'kill' command\n");
    //                 server_running = false;
    //                 break;
    //             }
    //             /* Show received message */
    //             printf("Received: %s", rxbuf);
    //             /* Echo it back */
    //             if (SSL_write(ssl, rxbuf, rxlen) <= 0) {
    //                 ERR_print_errors_fp(stderr);
    //             }
    //         }
    //     }
    //     if (server_running) {
    //         /* Cleanup for next client */
    //         SSL_shutdown(ssl);
    //         SSL_free(ssl);
    //         close(client_skt);
    //     }
    // }
    // printf("Server exiting...\n");

    return 0;
}
