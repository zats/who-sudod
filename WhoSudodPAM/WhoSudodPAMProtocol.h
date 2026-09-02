#ifndef WHO_SUDOD_PAM_PROTOCOL_H
#define WHO_SUDOD_PAM_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WHOSUDOD_PAM_PROTOCOL_MAGIC UINT32_C(0x5753504d)
#define WHOSUDOD_PAM_PROTOCOL_VERSION UINT16_C(1)

#define WHOSUDOD_PAM_SOCKET_PATH_FORMAT \
    "/private/tmp/com.zats.WhoSudo.pam.%u.sock"
#define WHOSUDOD_PAM_INSTALLED_MODULE_PATH \
    "/Library/Security/WhoSudod/pam_whosudod.so"
#define WHOSUDOD_PAM_TERMINAL_READER_PATH \
    "/Library/Security/WhoSudod/whosudod-pam-terminal-reader"
#define WHOSUDOD_PAM_OFFER_ARGUMENT "whosudod_offer_v1"
#define WHOSUDOD_PAM_RESTORE_ARGUMENT "whosudod_restore_v1"

#define WHOSUDOD_PAM_REQUEST_ID_SIZE 16U
#define WHOSUDOD_PAM_FRAME_HEADER_SIZE 28U
#define WHOSUDOD_PAM_BEGIN_PREFIX_SIZE 16U
#define WHOSUDOD_PAM_MAX_FRAME_PAYLOAD 4096U
#define WHOSUDOD_PAM_MAX_USERNAME_SIZE 256U
#define WHOSUDOD_PAM_MAX_TTY_SIZE 256U
#define WHOSUDOD_PAM_MAX_PROMPT_SIZE 1024U

/* PAM_MAX_RESP_SIZE is 512. A response must leave room for its NUL byte. */
#define WHOSUDOD_PAM_MAX_PASSWORD_SIZE 511U

enum whosudod_pam_message_type {
    WHOSUDOD_PAM_MESSAGE_BEGIN = 1,
    WHOSUDOD_PAM_MESSAGE_PASSWORD = 2,
    WHOSUDOD_PAM_MESSAGE_CANCEL = 3,
    WHOSUDOD_PAM_MESSAGE_END = 4,
    WHOSUDOD_PAM_MESSAGE_READY = 5,

    /* Private module-to-terminal-reader messages. */
    WHOSUDOD_PAM_MESSAGE_TERMINAL_START = 10,
    WHOSUDOD_PAM_MESSAGE_TERMINAL_READY = 11,
    WHOSUDOD_PAM_MESSAGE_TERMINAL_FAILURE = 12,
};

/*
 * All integer fields use network byte order. Strings are UTF-8 byte spans
 * without a trailing NUL byte.
 *
 * Each frame starts with this 28-byte wire layout:
 *
 *   u32 magic
 *   u16 version
 *   u16 message type
 *   u32 payload length
 *   u8  request ID[16]
 *
 * BEGIN has this 16-byte payload prefix, followed in order by username,
 * terminal path, and prompt bytes:
 *
 *   u32 sudo process ID
 *   u32 invoking user ID
 *   u16 username length
 *   u16 terminal path length
 *   u16 prompt length
 *   u16 reserved (must be zero)
 *
 * PASSWORD contains 1...511 app password bytes. READY, CANCEL, and END have
 * no payload. A terminal-reader PASSWORD can have an empty payload so PAM can
 * reject an empty password normally.
 *
 * The app sends READY only after it accepts the request and can present its
 * password field. Until READY arrives, the module does not change the terminal
 * and can call sudo's original conversation unchanged.
 *
 * Every response must repeat the BEGIN request ID. A disconnect or CANCEL
 * only removes the app input option; it does not cancel sudo's terminal input.
 */

static inline int
whosudod_pam_socket_path(uid_t uid, char *buffer, size_t capacity)
{
    int length;

    if (buffer == NULL || capacity == 0) {
        return -1;
    }
    length = snprintf(buffer, capacity, WHOSUDOD_PAM_SOCKET_PATH_FORMAT,
        (unsigned int)uid);
    if (length < 0 || (size_t)length >= capacity) {
        buffer[0] = '\0';
        return -1;
    }
    return length;
}

#ifdef __cplusplus
}
#endif

#endif /* WHO_SUDOD_PAM_PROTOCOL_H */
