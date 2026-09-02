#include "WhoSudodPAMInvocationPolicy.h"

#include <assert.h>
#include <stddef.h>

static bool
allows(int count, const char *const arguments[])
{
    return whosudod_pam_invocation_allows_password_input(count, arguments);
}

int
main(void)
{
    const char *const ordinary[] = { "sudo", "ls", "-l" };
    const char *const noninteractive[] = { "sudo", "-n", "ls" };
    const char *const clustered[] = { "sudo", "-knv", "ls" };
    const char *const stdin_mode[] = { "sudo", "-S", "ls" };
    const char *const askpass[] = { "sudo", "--askpass", "ls" };
    const char *const long_noninteractive[] = {
        "sudo", "--non-interactive", "ls",
    };
    const char *const abbreviated_noninteractive[] = {
        "sudo", "--non-i", "ls",
    };
    const char *const abbreviated_stdin[] = { "sudo", "--st", "ls" };
    const char *const user_named_n[] = { "sudo", "-un", "ls" };
    const char *const prompt_contains_n[] = {
        "sudo", "-p", "-n is text", "ls",
    };
    const char *const user_then_noninteractive[] = {
        "sudo", "--user", "root", "-n", "ls",
    };
    const char *const assignment_then_noninteractive[] = {
        "sudo", "NAME=value", "-n", "ls",
    };
    const char *const after_separator[] = { "sudo", "--", "-n" };

    assert(allows(3, ordinary));
    assert(!allows(3, noninteractive));
    assert(!allows(3, clustered));
    assert(!allows(3, stdin_mode));
    assert(!allows(3, askpass));
    assert(!allows(3, long_noninteractive));
    assert(!allows(3, abbreviated_noninteractive));
    assert(!allows(3, abbreviated_stdin));
    assert(allows(3, user_named_n));
    assert(allows(4, prompt_contains_n));
    assert(!allows(5, user_then_noninteractive));
    assert(!allows(4, assignment_then_noninteractive));
    assert(allows(3, after_separator));
    assert(!allows(0, NULL));
    return 0;
}
