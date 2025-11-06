#include "pqxdh/pqxdh.h"
#include "utils.h"

static const char* test_init(void)
{
    pqxdh_state s = { 0 };
    int ret = init_pqxdh_state(&s);

    mu_assert("init key failed", ret == 0);
    return 0;
}

static const char* all_tests(void)
{
    mu_run_test(test_init);
    return 0;
}

int main(void)
{
    tests_run = 0;
    const char* result = all_tests();
    if (result) {
        printf("FAIL: %s\n", result);
        return 1;
    }
    printf("OK (%d tests)\n", tests_run);
    return 0;
}
