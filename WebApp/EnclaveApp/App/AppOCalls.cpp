#include <iostream>

#include <openssl/ssl.h>
#include <openssl/err.h>

SSL* ssl = NULL;

/* OCall functions */
void ocall_debug_print(const char *str) {
    printf("%s", str);
}

void ocall_send_response(const char *message, size_t len) {
	if (SSL_write(ssl, message, len) <= 0) {
		ERR_print_errors_fp(stderr);
	}
	// An END is appended to conclusively mark the end of a message
	if (SSL_write(ssl, "END", strlen("END")) <= 0) {
		ERR_print_errors_fp(stderr);
	}
}