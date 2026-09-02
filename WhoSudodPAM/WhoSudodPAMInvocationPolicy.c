#include "WhoSudodPAMInvocationPolicy.h"

#include <stddef.h>
#include <string.h>

static bool
is_environment_assignment(const char *argument)
{
    const char *equals;
    const char *cursor;

    if (argument == NULL) {
        return false;
    }
    equals = strchr(argument, '=');
    if (equals == NULL || equals == argument) {
        return false;
    }
    for (cursor = argument; cursor < equals; cursor++) {
        unsigned char value = (unsigned char)*cursor;
        if (!((value >= 'a' && value <= 'z') ||
                (value >= 'A' && value <= 'Z') ||
                value == '_' ||
                (cursor != argument && value >= '0' && value <= '9'))) {
            return false;
        }
    }
    return true;
}

static bool
is_prefix_of_long_option(const char *candidate, size_t candidate_length,
    const char *option)
{
    size_t option_length = strlen(option);

    return candidate_length >= 3 && candidate_length <= option_length &&
        memcmp(candidate, option, candidate_length) == 0;
}

static bool
long_option_consumes_argument(const char *option, size_t option_length)
{
    static const char *const consuming_options[] = {
        "--chdir",
        "--close-from",
        "--command-timeout",
        "--group",
        "--host",
        "--other-user",
        "--prompt",
        "--role",
        "--chroot",
        "--type",
        "--user",
    };
    size_t index;

    for (index = 0;
         index < sizeof(consuming_options) / sizeof(consuming_options[0]);
         index++) {
        if (is_prefix_of_long_option(option, option_length,
                consuming_options[index])) {
            return true;
        }
    }
    return false;
}

static bool
short_option_consumes_argument(char option)
{
    return strchr("CDghpRTUu", option) != NULL;
}

bool
whosudod_pam_invocation_allows_password_input(int argument_count,
    const char *const arguments[])
{
    int index;

    if (argument_count < 1 || arguments == NULL || arguments[0] == NULL) {
        return false;
    }

    for (index = 1; index < argument_count; index++) {
        const char *argument = arguments[index];

        if (argument == NULL) {
            return false;
        }
        if (strcmp(argument, "--") == 0) {
            return true;
        }
        if (argument[0] != '-' || argument[1] == '\0') {
            if (is_environment_assignment(argument)) {
                continue;
            }
            return true;
        }

        if (argument[1] == '-') {
            const char *equals = strchr(argument, '=');
            size_t option_length = equals != NULL
                ? (size_t)(equals - argument)
                : strlen(argument);

            if (is_prefix_of_long_option(argument, option_length,
                    "--non-interactive") ||
                is_prefix_of_long_option(argument, option_length,
                    "--stdin") ||
                is_prefix_of_long_option(argument, option_length,
                    "--askpass")) {
                return false;
            }
            if (equals == NULL &&
                long_option_consumes_argument(argument, option_length)) {
                if (++index >= argument_count || arguments[index] == NULL) {
                    return false;
                }
            }
            continue;
        }

        {
            size_t option_index;
            for (option_index = 1; argument[option_index] != '\0';
                 option_index++) {
                char option = argument[option_index];

                if (option == 'n' || option == 'S' || option == 'A') {
                    return false;
                }
                if (short_option_consumes_argument(option)) {
                    if (argument[option_index + 1] == '\0') {
                        if (++index >= argument_count ||
                            arguments[index] == NULL) {
                            return false;
                        }
                    }
                    break;
                }
            }
        }
    }
    return true;
}
