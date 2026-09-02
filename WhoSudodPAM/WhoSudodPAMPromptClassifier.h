#ifndef WHO_SUDOD_PAM_PROMPT_CLASSIFIER_H
#define WHO_SUDOD_PAM_PROMPT_CLASSIFIER_H

#include <stdbool.h>
#include <security/pam_appl.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Returns true only for OpenPAM's single default account-password prompt. */
bool whosudod_pam_is_account_password_conversation(
    int message_count,
    const struct pam_message **messages
);

#ifdef __cplusplus
}
#endif

#endif /* WHO_SUDOD_PAM_PROMPT_CLASSIFIER_H */
