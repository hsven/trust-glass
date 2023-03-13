/*
 *  Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License").  You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "qrcodegen.hpp"

static const int server_port = 4433;


// typedef unsigned char   bool;
#define true            1
#define false           0

static std::string receive_message(SSL *ssl);
static void display_message(std::string response);
static void toSvgFile(std::string dest, const qrcodegen::QrCode &qr, int border);
static std::string toSvgString(const qrcodegen::QrCode &qr, int border);
static void printQr(const qrcodegen::QrCode &qr);

/*
 * This flag won't be useful until both accept/read (TCP & SSL) methods
 * can be called with a timeout. TBD.
 */
static volatile bool    server_running = true;

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

    return s;
}

SSL_CTX* create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method();

    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// void configure_server_context(SSL_CTX *ctx)
// {
//     /* Set the key and cert */
//     if (SSL_CTX_use_certificate_chain_file(ctx, "cert.pem") <= 0) {
//         ERR_print_errors_fp(stderr);
//         exit(EXIT_FAILURE);
//     }

//     if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
//         ERR_print_errors_fp(stderr);
//         exit(EXIT_FAILURE);
//     }
// }

void configure_client_context(SSL_CTX *ctx)
{
    /*
     * Configure the client to abort the handshake if certificate verification
     * fails
     */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    /*
     * In a real application you would probably just use the default system certificate trust store and call:
     *     SSL_CTX_set_default_verify_paths(ctx);
     * In this demo though we are using a self-signed certificate, so the client must trust it directly.
     */
    if (!SSL_CTX_load_verify_locations(ctx, "cert.pem", NULL)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void usage()
{
    printf("Usage: ./client <IP>\n");
    printf("       <IP>=dotted ip of server\n");
    exit(1);
}

int main(int argc, char **argv)
{
    // bool isServer;
    int result;

    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;

    int server_skt = -1;
    int client_skt = -1;

    /* used by getline relying on realloc, can't be statically allocated */
    char *txbuf = NULL;
    size_t txcap = 0;
    int txlen;

    char *rem_server_ip = NULL;

    struct sockaddr_in addr;
    unsigned int addr_len = sizeof(addr);
    std::string response = std::string("");

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
    if (argc != 2) {
        usage();
        /* NOTREACHED */
    }
    rem_server_ip = argv[1];

    /* Create context used by both client and server */
    ssl_ctx = create_context();


    printf("We are the client\n\n");

    /* Configure client context so we verify the server correctly */
    configure_client_context(ssl_ctx);

    /* Create "bare" socket */
    client_skt = create_socket();
    /* Set up connect address */
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, rem_server_ip, &addr.sin_addr.s_addr);
    addr.sin_port = htons(server_port);
    /* Do TCP connect with server */
    if (connect(client_skt, (struct sockaddr*) &addr, sizeof(addr)) != 0) {
        perror("Unable to TCP connect to server");
        goto exit;
    } else {
        printf("TCP connection to server successful\n");
    }

    /* Create client SSL structure using dedicated client socket */
    ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, client_skt);
    /* Set hostname for SNI */
    // SSL_set_tlsext_host_name(ssl, rem_server_ip);
    /* Configure server hostname check */
    // SSL_set1_host(ssl, rem_server_ip);

    /* Now do SSL connect with server */
    if (SSL_connect(ssl) == 1) {

        printf("SSL connection to server successful\n\n");

        /* Initial handshake */
        printf("Received: \n");
        response = receive_message(ssl);
        display_message(response);

        /* Loop to send input from keyboard */
        while (true) {
            /* Get a line of input */
            txlen = getline(&txbuf, &txcap, stdin);
            /* Exit loop on error */
            if (txlen < 0 || txbuf == NULL) {
                break;
            }
            /* Exit loop if just a carriage return */
            if (txbuf[0] == '\n') {
                break;
            }
            /* Send it to the server */
            if ((result = SSL_write(ssl, txbuf, txlen)) <= 0) {
                printf("Server closed connection\n");
                ERR_print_errors_fp(stderr);
                break;
            }

            /* Wait for the echo */
            printf("Received: \n");
            response = receive_message(ssl);

            display_message(response);
            printf("--End--\n");

        }
        printf("Client exiting...\n");
    } else {

        printf("SSL connection to server failed\n\n");

        ERR_print_errors_fp(stderr);
    }


    exit:
    /* Close up */
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    SSL_CTX_free(ssl_ctx);

    if (client_skt != -1)
        close(client_skt);
    if (server_skt != -1)
        close(server_skt);

    if (txbuf != NULL && txcap > 0)
        free(txbuf);

    printf("sslecho exiting\n");

    return 0;
}



/*---- Utilities ----*/
static std::string receive_message(SSL *ssl) {
    std::string response = "";
    char rxbuf[128];
    size_t rxcap = sizeof(rxbuf);
    int rxlen;

    // printf("Received: \n");
    do {
        rxlen = SSL_read(ssl, rxbuf, rxcap);

        if (rxlen <= 0) {
            printf("Server closed connection\n");
            ERR_print_errors_fp(stderr);
            break;
        } else {
            /* Show it */
            rxbuf[rxlen] = 0;
            response.append(rxbuf);
        }
    } while(strstr(rxbuf, "END") == NULL);

    //Remove the END sufix from the response
    return response.substr(0, response.length() - 3);
}

static void display_message(std::string response) {
    qrcodegen::QrCode::Ecc errCorLvl = qrcodegen::QrCode::Ecc::LOW;  // Error correction level
    // Make and print the QR Code symbol
    qrcodegen::QrCode qr = qrcodegen::QrCode::encodeText(response.c_str(), errCorLvl);
    printQr(qr);
    toSvgFile("../qrCode.svg", qr, 1);
}

static void toSvgFile(std::string dest, const qrcodegen::QrCode &qr, int border) {
    std::string svgString = toSvgString(qr, border);
    std::ofstream file;
    file.open(dest);
    file << svgString;
    file.close();

}

// Returns a string of SVG code for an image depicting the given QR Code, with the given number
// of border modules. The string always uses Unix newlines (\n), regardless of the platform.
static std::string toSvgString(const qrcodegen::QrCode &qr, int border) {
	if (border < 0)
		throw std::domain_error("Border must be non-negative");
	if (border > INT_MAX / 2 || border * 2 > INT_MAX - qr.getSize())
		throw std::overflow_error("Border too large");
	
	std::ostringstream sb;
	sb << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
	sb << "<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">\n";
	sb << "<svg xmlns=\"http://www.w3.org/2000/svg\" version=\"1.1\" viewBox=\"0 0 ";
	sb << (qr.getSize() + border * 2) << " " << (qr.getSize() + border * 2) << "\" stroke=\"none\">\n";
	sb << "\t<rect width=\"100%\" height=\"100%\" fill=\"#FFFFFF\"/>\n";
	sb << "\t<path d=\"";
	for (int y = 0; y < qr.getSize(); y++) {
		for (int x = 0; x < qr.getSize(); x++) {
			if (qr.getModule(x, y)) {
				if (x != 0 || y != 0)
					sb << " ";
				sb << "M" << (x + border) << "," << (y + border) << "h1v1h-1z";
			}
		}
	}
	sb << "\" fill=\"#000000\"/>\n";
	sb << "</svg>\n";
	return sb.str();
}


// Prints the given QrCode object to the console.
static void printQr(const qrcodegen::QrCode &qr) {
	int border = 4;
	for (int y = -border; y < qr.getSize() + border; y++) {
		for (int x = -border; x < qr.getSize() + border; x++) {
			std::cout << (qr.getModule(x, y) ? "##" : "  ");
		}
		std::cout << std::endl;
	}
	std::cout << std::endl;
}