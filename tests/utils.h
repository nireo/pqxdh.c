#ifndef __TEST_UTIL__
#define __TEST_UTIL__

#include <stdio.h>

#define mu_assert(msg, test) \
    do {                     \
        if (!(test))         \
            return msg;      \
    } while (0)
#define mu_run_test(test)         \
    do {                          \
        const char* msg = test(); \
        tests_run++;              \
        if (msg)                  \
            return msg;           \
    } while (0)

static int tests_run;

#endif
