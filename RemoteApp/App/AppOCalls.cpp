// #include "App.h"
#include <iostream>
#include "UntrustedLibrary/qrcodegen.hpp"

#include <openssl/ssl.h>
#include <openssl/err.h>

SSL* ssl = NULL;

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
	if (SSL_write(ssl, str, strlen(str)) <= 0) {
		ERR_print_errors_fp(stderr);
	}
	if (SSL_write(ssl, "END", strlen("END")) <= 0) {
		ERR_print_errors_fp(stderr);
	}
}

void printQr(const qrcodegen::QrCode &qr) {
	int border = 4;
	std::string response = "";
	for (int y = -border; y < qr.getSize() + border; y++) {
		for (int x = -border; x < qr.getSize() + border; x++) {
			response.append((qr.getModule(x, y) ? "##" : "  "));
			std::cout << (qr.getModule(x, y) ? "##" : "  ");
		}
		response.append("\n");
		std::cout << std::endl;
	}
	response.append("\n");	
	std::cout << std::endl;

	// if (SSL_write(ssl, response.data(), response.length()) <= 0) {
	// 	ERR_print_errors_fp(stderr);
	// }
	// if (SSL_write(ssl, "END", strlen("END")) <= 0) {
	// 	ERR_print_errors_fp(stderr);
	// }
}


void ocall_print_qr_code(const char  *message) {
	const qrcodegen::QrCode::Ecc errCorLvl = qrcodegen::QrCode::Ecc::LOW;  // Error correction level
	
	// Make and print the QR Code symbol
	const qrcodegen::QrCode qr = qrcodegen::QrCode::encodeText(message, errCorLvl);
	
	printQr(qr);
	// std::cout << qrcodegen::toSvgString(qr, 4) << std::endl;
}

void ocall_send_response(const char *message, size_t len) {
	if (SSL_write(ssl, message, len) <= 0) {
		ERR_print_errors_fp(stderr);
	}
	if (SSL_write(ssl, "END", strlen("END")) <= 0) {
		ERR_print_errors_fp(stderr);
	}
}