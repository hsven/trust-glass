#pragma once

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

static const int server_port = 4433;

#define true            1
#define false           0
/*
 * This flag won't be useful until both accept/read (TCP & SSL) methods
 * can be called with a timeout. TBD.
 */
static volatile bool    server_running = true;


int create_socket();
SSL_CTX* create_context();
void configure_server_context(SSL_CTX *ctx);
void usage();
int server_loop();