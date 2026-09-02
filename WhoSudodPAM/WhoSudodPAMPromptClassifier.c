#include "WhoSudodPAMPromptClassifier.h"

#include <security/pam_constants.h>
#include <stddef.h>
#include <string.h>

static bool
is_bounded_string(const char *value)
{
    return value != NULL && strnlen(value, PAM_MAX_MSG_SIZE + 1U) <= PAM_MAX_MSG_SIZE;
}

bool
whosudod_pam_is_account_password_conversation(
    int message_count,
    const struct pam_message **messages
)
{
    const struct pam_message *message;

    if (message_count != 1 || messages == NULL || messages[0] == NULL) {
        return false;
    }

    message = messages[0];
    if (message->msg_style != PAM_PROMPT_ECHO_OFF ||
        !is_bounded_string(message->msg)) {
        return false;
    }

    /* These are OpenPAM's account-password default and its spaced form. */
    return strcmp(message->msg, "Password:") == 0 ||
        strcmp(message->msg, "Password: ") == 0;
}
