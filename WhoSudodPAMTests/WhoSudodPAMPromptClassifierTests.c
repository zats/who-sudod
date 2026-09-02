#include "WhoSudodPAMPromptClassifier.h"

#include <assert.h>
#include <security/pam_constants.h>

static const struct pam_message *
one_message(const struct pam_message *message,
    const struct pam_message **messages)
{
    messages[0] = message;
    return message;
}

int
main(void)
{
    const struct pam_message *messages[2] = { NULL, NULL };
    struct pam_message password = {
        .msg_style = PAM_PROMPT_ECHO_OFF,
        .msg = "Password:",
    };
    struct pam_message password_with_space = {
        .msg_style = PAM_PROMPT_ECHO_OFF,
        .msg = "Password: ",
    };
    struct pam_message pin = {
        .msg_style = PAM_PROMPT_ECHO_OFF,
        .msg = "YubiKey PIN:",
    };
    struct pam_message visible = {
        .msg_style = PAM_PROMPT_ECHO_ON,
        .msg = "Password:",
    };
    struct pam_message information = {
        .msg_style = PAM_TEXT_INFO,
        .msg = "Insert your security key.",
    };

    one_message(&password, messages);
    assert(whosudod_pam_is_account_password_conversation(1, messages));

    one_message(&password_with_space, messages);
    assert(whosudod_pam_is_account_password_conversation(1, messages));

    one_message(&pin, messages);
    assert(!whosudod_pam_is_account_password_conversation(1, messages));

    one_message(&visible, messages);
    assert(!whosudod_pam_is_account_password_conversation(1, messages));

    messages[0] = &information;
    messages[1] = &password;
    assert(!whosudod_pam_is_account_password_conversation(2, messages));
    assert(!whosudod_pam_is_account_password_conversation(0, messages));
    assert(!whosudod_pam_is_account_password_conversation(1, NULL));

    messages[0] = NULL;
    assert(!whosudod_pam_is_account_password_conversation(1, messages));
    return 0;
}
