#ifndef WHO_SUDOD_PAM_INVOCATION_POLICY_H
#define WHO_SUDOD_PAM_INVOCATION_POLICY_H

#include <stdbool.h>

/* Returns false for sudo modes that must not accept an interactive password. */
bool whosudod_pam_invocation_allows_password_input(
    int argument_count,
    const char *const arguments[]
);

#endif /* WHO_SUDOD_PAM_INVOCATION_POLICY_H */
