#include <string.h>
#include <algorithm>
#include <random>
#include <map>
#include <stdarg.h>
#include "TrustGlass_t.h"

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 *   Note that the fmt section should end with a new line
 *   
 *   Example: printf("%s", "test\n");
 *            printf("%s\n", "test");
 */
int printf(const char* fmt, ...);