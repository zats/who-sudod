#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <util.h>

#include "../WhoSudodPAM/WhoSudodPAM.c"

static int
test_conversation(
    int message_count,
    const struct pam_message **messages,
    struct pam_response **responses,
    void *application_data
)
{
    (void)message_count;
    (void)messages;
    (void)responses;
    (void)application_data;
    return PAM_CONV_ERR;
}

static void
test_strict_module_arguments(void)
{
    const char *offer[] = { WHOSUDOD_PAM_OFFER_ARGUMENT };
    const char *restore[] = { WHOSUDOD_PAM_RESTORE_ARGUMENT };
    const char *unknown[] = { "offer" };
    const char *extra[] = {
        WHOSUDOD_PAM_OFFER_ARGUMENT,
        "extra",
    };

    assert(whosudod_pam_parse_mode(1, offer) ==
        WHOSUDOD_PAM_MODE_OFFER);
    assert(whosudod_pam_parse_mode(1, restore) ==
        WHOSUDOD_PAM_MODE_RESTORE);
    assert(whosudod_pam_parse_mode(1, unknown) ==
        WHOSUDOD_PAM_MODE_INVALID);
    assert(whosudod_pam_parse_mode(2, extra) ==
        WHOSUDOD_PAM_MODE_INVALID);
    assert(whosudod_pam_parse_mode(0, NULL) ==
        WHOSUDOD_PAM_MODE_INVALID);
}

static void
test_fragmented_and_coalesced_frames(void)
{
    const uint8_t request_id[WHOSUDOD_PAM_REQUEST_ID_SIZE] = {
        0, 1, 2, 3, 4, 5, 6, 7,
        8, 9, 10, 11, 12, 13, 14, 15,
    };
    const uint8_t password[] = { 's', 'e', 'c', 'r', 'e', 't' };
    uint8_t ready_frame[WHOSUDOD_PAM_FRAME_HEADER_SIZE];
    uint8_t password_frame[
        WHOSUDOD_PAM_FRAME_HEADER_SIZE + sizeof(password)
    ];
    struct whosudod_pam_frame_reader reader;
    struct whosudod_pam_frame_view view;
    size_t index;

    memset(&reader, 0, sizeof(reader));
    memset(ready_frame, 0, sizeof(ready_frame));
    memset(password_frame, 0, sizeof(password_frame));
    whosudod_pam_encode_header(
        ready_frame,
        WHOSUDOD_PAM_MESSAGE_READY,
        request_id,
        0U
    );
    whosudod_pam_encode_header(
        password_frame,
        WHOSUDOD_PAM_MESSAGE_PASSWORD,
        request_id,
        (uint32_t)sizeof(password)
    );
    memcpy(
        password_frame + WHOSUDOD_PAM_FRAME_HEADER_SIZE,
        password,
        sizeof(password)
    );

    memcpy(reader.bytes, ready_frame, 9U);
    reader.used = 9U;
    assert(whosudod_pam_reader_peek(
        &reader,
        request_id,
        &view
    ) == WHOSUDOD_PAM_FRAME_INCOMPLETE);

    memcpy(
        reader.bytes + reader.used,
        ready_frame + reader.used,
        sizeof(ready_frame) - reader.used
    );
    reader.used = sizeof(ready_frame);
    memcpy(
        reader.bytes + reader.used,
        password_frame,
        sizeof(password_frame)
    );
    reader.used += sizeof(password_frame);

    assert(whosudod_pam_reader_peek(
        &reader,
        request_id,
        &view
    ) == WHOSUDOD_PAM_FRAME_COMPLETE);
    assert(view.message_type == WHOSUDOD_PAM_MESSAGE_READY);
    assert(view.payload_length == 0U);
    whosudod_pam_reader_consume(&reader, view.frame_length);

    assert(whosudod_pam_reader_peek(
        &reader,
        request_id,
        &view
    ) == WHOSUDOD_PAM_FRAME_COMPLETE);
    assert(view.message_type == WHOSUDOD_PAM_MESSAGE_PASSWORD);
    assert(view.payload_length == sizeof(password));
    assert(memcmp(view.payload, password, sizeof(password)) == 0);
    whosudod_pam_reader_consume(&reader, view.frame_length);

    assert(reader.used == 0U);
    for (index = 0U; index < sizeof(reader.bytes); index += 1U) {
        assert(reader.bytes[index] == 0U);
    }
}

static void
test_invalid_frames(void)
{
    const uint8_t request_id[WHOSUDOD_PAM_REQUEST_ID_SIZE] = { 0 };
    uint8_t other_request_id[WHOSUDOD_PAM_REQUEST_ID_SIZE] = { 0 };
    struct whosudod_pam_frame_reader reader;
    struct whosudod_pam_frame_view view;

    memset(&reader, 0, sizeof(reader));
    other_request_id[0] = 1U;
    whosudod_pam_encode_header(
        reader.bytes,
        WHOSUDOD_PAM_MESSAGE_PASSWORD,
        other_request_id,
        1U
    );
    reader.bytes[WHOSUDOD_PAM_FRAME_HEADER_SIZE] = 'x';
    reader.used = WHOSUDOD_PAM_FRAME_HEADER_SIZE + 1U;
    assert(whosudod_pam_reader_peek(
        &reader,
        request_id,
        &view
    ) == WHOSUDOD_PAM_FRAME_INVALID);

    memset(&reader, 0, sizeof(reader));
    whosudod_pam_encode_header(
        reader.bytes,
        WHOSUDOD_PAM_MESSAGE_PASSWORD,
        request_id,
        WHOSUDOD_PAM_MAX_PASSWORD_SIZE + 1U
    );
    reader.used = WHOSUDOD_PAM_FRAME_HEADER_SIZE;
    assert(whosudod_pam_reader_peek(
        &reader,
        request_id,
        &view
    ) == WHOSUDOD_PAM_FRAME_INVALID);
}

static void
test_non_sudo_callback_is_rejected(void)
{
    struct pam_conv conversation = {
        .conv = test_conversation,
        .appdata_ptr = NULL,
    };

    assert(!whosudod_pam_callback_is_stock_sudo(&conversation));
}

static void
add_extended_acl(const char *path)
{
    int status = 0;
    pid_t child = fork();
    pid_t waited;

    assert(child >= 0);
    if (child == 0) {
        execl(
            "/bin/chmod",
            "chmod",
            "+a",
            "group:everyone allow read",
            path,
            NULL
        );
        _exit(127);
    }

    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    assert(waited == child);
    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) == 0);
}

static void
test_extended_acl_policy(void)
{
    char path[] = "/private/tmp/whosudod-pam-acl-test.XXXXXX";
    int descriptor = mkstemp(path);

    assert(descriptor >= 0);
    assert(close(descriptor) == 0);
    assert(whosudod_pam_path_has_no_extended_acl(path));

    add_extended_acl(path);
    assert(!whosudod_pam_path_has_no_extended_acl(path));

    assert(unlink(path) == 0);
}

static void
test_real_controlling_terminal(void)
{
    int master = -1;
    int other_master = -1;
    int other_slave = -1;
    int status = 0;
    char terminal_path[PATH_MAX];
    char other_path[PATH_MAX];
    pid_t child;
    pid_t waited;

    assert(openpty(&other_master, &other_slave, other_path, NULL, NULL) == 0);
    child = forkpty(&master, terminal_path, NULL, NULL);
    assert(child >= 0);
    if (child == 0) {
        struct pam_conv conversation = {
            .conv = test_conversation,
            .appdata_ptr = NULL,
        };
        pam_handle_t *pamh = NULL;
        struct whosudod_pam_terminal terminal;

        alarm(5);
        assert(pam_start("sudo", "whosudod-test", &conversation, &pamh) == PAM_SUCCESS);
        assert(pam_set_item(pamh, PAM_TTY, terminal_path) == PAM_SUCCESS);
        assert(whosudod_pam_terminal_open(pamh, &terminal));
        whosudod_pam_terminal_close(&terminal);

        assert(pam_set_item(pamh, PAM_TTY, other_path) == PAM_SUCCESS);
        assert(!whosudod_pam_terminal_open(pamh, &terminal));
        assert(pam_set_item(pamh, PAM_TTY, "/dev/null") == PAM_SUCCESS);
        assert(!whosudod_pam_terminal_open(pamh, &terminal));
        assert(pam_end(pamh, PAM_SUCCESS) == PAM_SUCCESS);
        _exit(0);
    }

    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    assert(waited == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    close(master);
    close(other_master);
    close(other_slave);
}

int
main(void)
{
    test_strict_module_arguments();
    test_fragmented_and_coalesced_frames();
    test_invalid_frames();
    test_non_sudo_callback_is_rejected();
    test_extended_acl_policy();
    test_real_controlling_terminal();
    puts("WhoSudod PAM module support tests passed");
    return 0;
}
