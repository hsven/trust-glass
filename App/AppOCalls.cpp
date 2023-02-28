// #include "App.h"
#include <iostream>
#include "UntrustedLibrary/qrcodegen.hpp"

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}

void printQr(const qrcodegen::QrCode &qr) {
	int border = 4;
	for (int y = -border; y < qr.getSize() + border; y++) {
		for (int x = -border; x < qr.getSize() + border; x++) {
			std::cout << (qr.getModule(x, y) ? "##" : "  ");
		}
		std::cout << std::endl;
	}
	std::cout << std::endl;
}


void ocall_print_qr_code(const char  *message) {
	const qrcodegen::QrCode::Ecc errCorLvl = qrcodegen::QrCode::Ecc::LOW;  // Error correction level
	
	// Make and print the QR Code symbol
	const qrcodegen::QrCode qr = qrcodegen::QrCode::encodeText(message, errCorLvl);
	printQr(qr);
	// std::cout << qrcodegen::toSvgString(qr, 4) << std::endl;
}