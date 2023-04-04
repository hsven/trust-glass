#include "Utils.h"

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