#define _DARWIN_C_SOURCE

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <limits.h>
#include <mach/message.h>
#include <poll.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/acl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "WhoSudodPAMInvocationPolicy.h"
#include "WhoSudodPAMPromptClassifier.h"
#include "WhoSudodPAMProtocol.h"

#define WHOSUDOD_PAM_STATE_KEY "com.zats.WhoSudo.pam.state"
#define WHOSUDOD_PAM_ASKPASS_DATA_KEY "askpass-enabled"
#define WHOSUDOD_PAM_INSTALL_DIRECTORY "/Library/Security/WhoSudod"
#define WHOSUDOD_PAM_APP_SIGNING_REQUIREMENT \
    "anchor apple generic and identifier \"com.zats.WhoSudo\" and " \
    "certificate leaf[subject.OU] = \"5KE88HWMKJ\""
#define WHOSUDOD_PAM_HELPER_SIGNING_REQUIREMENT \
    "anchor apple generic and identifier \"com.zats.WhoSudo.PAMTerminalReader\" and " \
    "certificate leaf[subject.OU] = \"5KE88HWMKJ\""
#define WHOSUDOD_PAM_CONNECT_TIMEOUT_MILLISECONDS 100
#define WHOSUDOD_PAM_WRITE_TIMEOUT_MILLISECONDS 100
#define WHOSUDOD_PAM_READY_TIMEOUT_MILLISECONDS 1000
#define WHOSUDOD_PAM_CHILD_GRACE_MILLISECONDS 500
#define WHOSUDOD_PAM_PROCESS_ARGUMENT_LIMIT (1024U * 1024U)
#define WHOSUDOD_PAM_CONTROL_DESCRIPTOR 3
#define WHOSUDOD_PAM_READER_CAPACITY \
    ((WHOSUDOD_PAM_FRAME_HEADER_SIZE * 2U) + WHOSUDOD_PAM_MAX_PASSWORD_SIZE)

extern char **environ;

enum whosudod_pam_mode {
    WHOSUDOD_PAM_MODE_INVALID = 0,
    WHOSUDOD_PAM_MODE_OFFER,
    WHOSUDOD_PAM_MODE_RESTORE,
};

enum whosudod_pam_frame_status {
    WHOSUDOD_PAM_FRAME_INCOMPLETE = 0,
    WHOSUDOD_PAM_FRAME_COMPLETE,
    WHOSUDOD_PAM_FRAME_INVALID,
};

enum whosudod_pam_race_result {
    WHOSUDOD_PAM_RACE_PENDING = 0,
    WHOSUDOD_PAM_RACE_FAILURE,
    WHOSUDOD_PAM_RACE_APP_PASSWORD,
    WHOSUDOD_PAM_RACE_HELPER_PASSWORD,
};

enum whosudod_pam_child_wait_result {
    WHOSUDOD_PAM_CHILD_REAPED = 0,
    WHOSUDOD_PAM_CHILD_TIMED_OUT,
    WHOSUDOD_PAM_CHILD_WAIT_ERROR,
};

struct whosudod_pam_state {
    pam_handle_t *pamh;
    struct pam_conv original;
    struct pam_conv replacement;
    bool armed;
};

struct whosudod_pam_terminal {
    int descriptor;
    struct termios original;
    pid_t process_group;
};

struct whosudod_pam_frame_reader {
    uint8_t bytes[WHOSUDOD_PAM_READER_CAPACITY];
    size_t used;
    bool closed;
};

struct whosudod_pam_frame_view {
    uint16_t message_type;
    const uint8_t *payload;
    uint32_t payload_length;
    size_t frame_length;
};

struct whosudod_pam_process_arguments {
    char *buffer;
    size_t buffer_size;
    char **arguments;
    int count;
};

struct whosudod_pam_race_outcome {
    enum whosudod_pam_race_result result;
    uint8_t password[WHOSUDOD_PAM_MAX_PASSWORD_SIZE];
    size_t password_length;
};

struct whosudod_pam_pending_password {
    uint8_t bytes[WHOSUDOD_PAM_MAX_PASSWORD_SIZE];
    size_t length;
    bool available;
};

static int whosudod_pam_conversation(
    int message_count,
    const struct pam_message **messages,
    struct pam_response **responses,
    void *application_data
);

static uint16_t
whosudod_pam_decode_u16(const uint8_t *bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8U) |
        (uint16_t)bytes[1]);
}

static uint32_t
whosudod_pam_decode_u32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24U) |
        ((uint32_t)bytes[1] << 16U) |
        ((uint32_t)bytes[2] << 8U) |
        (uint32_t)bytes[3];
}

static void
whosudod_pam_encode_u16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t)(value >> 8U);
    bytes[1] = (uint8_t)value;
}

static void
whosudod_pam_encode_u32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)(value >> 24U);
    bytes[1] = (uint8_t)(value >> 16U);
    bytes[2] = (uint8_t)(value >> 8U);
    bytes[3] = (uint8_t)value;
}

static void
whosudod_pam_encode_header(
    uint8_t header[WHOSUDOD_PAM_FRAME_HEADER_SIZE],
    uint16_t message_type,
    const uint8_t request_id[WHOSUDOD_PAM_REQUEST_ID_SIZE],
    uint32_t payload_length
)
{
    whosudod_pam_encode_u32(header, WHOSUDOD_PAM_PROTOCOL_MAGIC);
    whosudod_pam_encode_u16(
        header + 4,
        WHOSUDOD_PAM_PROTOCOL_VERSION
    );
    whosudod_pam_encode_u16(header + 6, message_type);
    whosudod_pam_encode_u32(header + 8, payload_length);
    memcpy(header + 12, request_id, WHOSUDOD_PAM_REQUEST_ID_SIZE);
}

static void
whosudod_pam_secure_zero(void *bytes, size_t length)
{
    volatile uint8_t *cursor = bytes;

    while (length > 0U) {
        *cursor = 0U;
        cursor += 1;
        length -= 1U;
    }
}

static void
whosudod_pam_close(int *descriptor)
{
    if (descriptor == NULL || *descriptor < 0) {
        return;
    }

    while (close(*descriptor) != 0 && errno == EINTR) {
    }
    *descriptor = -1;
}

static bool
whosudod_pam_add_milliseconds(
    struct timespec *deadline,
    unsigned int milliseconds
)
{
    if (deadline == NULL ||
        clock_gettime(CLOCK_MONOTONIC, deadline) != 0) {
        return false;
    }

    deadline->tv_sec += (time_t)(milliseconds / 1000U);
    deadline->tv_nsec +=
        (long)((milliseconds % 1000U) * 1000000U);
    if (deadline->tv_nsec >= 1000000000L) {
        deadline->tv_sec += 1;
        deadline->tv_nsec -= 1000000000L;
    }
    return true;
}

static int
whosudod_pam_remaining_milliseconds(const struct timespec *deadline)
{
    struct timespec now;
    time_t seconds;
    long nanoseconds;
    int64_t milliseconds;

    if (deadline == NULL ||
        clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }

    seconds = deadline->tv_sec - now.tv_sec;
    nanoseconds = deadline->tv_nsec - now.tv_nsec;
    if (nanoseconds < 0L) {
        seconds -= 1;
        nanoseconds += 1000000000L;
    }
    if (seconds < 0 || (seconds == 0 && nanoseconds <= 0L)) {
        return 0;
    }

    milliseconds =
        ((int64_t)seconds * 1000LL) +
        ((int64_t)nanoseconds + 999999LL) / 1000000LL;
    if (milliseconds > INT_MAX) {
        return INT_MAX;
    }
    return (int)milliseconds;
}

static bool
whosudod_pam_poll_descriptor(
    int descriptor,
    short events,
    const struct timespec *deadline,
    short *returned_events
)
{
    struct pollfd poll_descriptor;

    if (returned_events != NULL) {
        *returned_events = 0;
    }

    poll_descriptor.fd = descriptor;
    poll_descriptor.events = events;
    poll_descriptor.revents = 0;

    for (;;) {
        int timeout = whosudod_pam_remaining_milliseconds(deadline);
        int result;

        if (timeout <= 0) {
            return false;
        }

        result = poll(&poll_descriptor, 1, timeout);
        if (result > 0) {
            if (returned_events != NULL) {
                *returned_events = poll_descriptor.revents;
            }
            return true;
        }
        if (result == 0) {
            return false;
        }
        if (errno != EINTR) {
            return false;
        }
    }
}

static bool
whosudod_pam_set_descriptor_flags(int descriptor, int command, int flag)
{
    int current;

    do {
        current = fcntl(descriptor, command);
    } while (current < 0 && errno == EINTR);
    if (current < 0) {
        return false;
    }

    do {
        current = fcntl(
            descriptor,
            command == F_GETFD ? F_SETFD : F_SETFL,
            current | flag
        );
    } while (current < 0 && errno == EINTR);
    return current == 0;
}

static bool
whosudod_pam_configure_socket(int descriptor)
{
    int enabled = 1;

    return setsockopt(
        descriptor,
        SOL_SOCKET,
        SO_NOSIGPIPE,
        &enabled,
        sizeof(enabled)
    ) == 0 &&
        whosudod_pam_set_descriptor_flags(descriptor, F_GETFD, FD_CLOEXEC) &&
        whosudod_pam_set_descriptor_flags(descriptor, F_GETFL, O_NONBLOCK);
}

static bool
whosudod_pam_send_all(
    int descriptor,
    const void *bytes,
    size_t length
)
{
    const uint8_t *cursor = bytes;
    size_t remaining = length;
    struct timespec deadline;

    if (!whosudod_pam_add_milliseconds(
            &deadline,
            WHOSUDOD_PAM_WRITE_TIMEOUT_MILLISECONDS)) {
        return false;
    }

    while (remaining > 0U) {
        ssize_t written = send(
            descriptor,
            cursor,
            remaining,
            MSG_NOSIGNAL
        );

        if (written > 0) {
            cursor += (size_t)written;
            remaining -= (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written < 0 &&
            (errno == EAGAIN || errno == EWOULDBLOCK)) {
            short returned_events = 0;

            if (!whosudod_pam_poll_descriptor(
                    descriptor,
                    POLLOUT,
                    &deadline,
                    &returned_events) ||
                (returned_events &
                    (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                return false;
            }
            continue;
        }
        return false;
    }
    return true;
}

static bool
whosudod_pam_send_frame(
    int descriptor,
    uint16_t message_type,
    const uint8_t request_id[WHOSUDOD_PAM_REQUEST_ID_SIZE],
    const void *payload,
    uint32_t payload_length
)
{
    uint8_t frame[
        WHOSUDOD_PAM_FRAME_HEADER_SIZE +
        WHOSUDOD_PAM_MAX_FRAME_PAYLOAD
    ];
    size_t frame_length;
    bool result;

    if (request_id == NULL ||
        payload_length > WHOSUDOD_PAM_MAX_FRAME_PAYLOAD ||
        (payload_length > 0U && payload == NULL)) {
        return false;
    }

    whosudod_pam_encode_header(
        frame,
        message_type,
        request_id,
        payload_length
    );
    if (payload_length > 0U) {
        memcpy(
            frame + WHOSUDOD_PAM_FRAME_HEADER_SIZE,
            payload,
            payload_length
        );
    }
    frame_length =
        WHOSUDOD_PAM_FRAME_HEADER_SIZE + (size_t)payload_length;
    result = whosudod_pam_send_all(descriptor, frame, frame_length);
    whosudod_pam_secure_zero(frame, sizeof(frame));
    return result;
}

static void
whosudod_pam_reader_clear(struct whosudod_pam_frame_reader *reader)
{
    if (reader == NULL) {
        return;
    }
    whosudod_pam_secure_zero(reader->bytes, sizeof(reader->bytes));
    reader->used = 0U;
    reader->closed = false;
}

static enum whosudod_pam_frame_status
whosudod_pam_reader_peek(
    const struct whosudod_pam_frame_reader *reader,
    const uint8_t request_id[WHOSUDOD_PAM_REQUEST_ID_SIZE],
    struct whosudod_pam_frame_view *view
)
{
    uint32_t payload_length;
    size_t frame_length;

    if (reader == NULL || request_id == NULL || view == NULL) {
        return WHOSUDOD_PAM_FRAME_INVALID;
    }
    if (reader->used < WHOSUDOD_PAM_FRAME_HEADER_SIZE) {
        return WHOSUDOD_PAM_FRAME_INCOMPLETE;
    }
    if (whosudod_pam_decode_u32(reader->bytes) !=
            WHOSUDOD_PAM_PROTOCOL_MAGIC ||
        whosudod_pam_decode_u16(reader->bytes + 4) !=
            WHOSUDOD_PAM_PROTOCOL_VERSION ||
        memcmp(
            reader->bytes + 12,
            request_id,
            WHOSUDOD_PAM_REQUEST_ID_SIZE
        ) != 0) {
        return WHOSUDOD_PAM_FRAME_INVALID;
    }

    payload_length = whosudod_pam_decode_u32(reader->bytes + 8);
    if (payload_length > WHOSUDOD_PAM_MAX_PASSWORD_SIZE) {
        return WHOSUDOD_PAM_FRAME_INVALID;
    }

    frame_length =
        WHOSUDOD_PAM_FRAME_HEADER_SIZE + (size_t)payload_length;
    if (frame_length > sizeof(reader->bytes)) {
        return WHOSUDOD_PAM_FRAME_INVALID;
    }
    if (reader->used < frame_length) {
        return WHOSUDOD_PAM_FRAME_INCOMPLETE;
    }

    view->message_type = whosudod_pam_decode_u16(reader->bytes + 6);
    view->payload = reader->bytes + WHOSUDOD_PAM_FRAME_HEADER_SIZE;
    view->payload_length = payload_length;
    view->frame_length = frame_length;
    return WHOSUDOD_PAM_FRAME_COMPLETE;
}

static void
whosudod_pam_reader_consume(
    struct whosudod_pam_frame_reader *reader,
    size_t frame_length
)
{
    size_t remaining;

    if (reader == NULL || frame_length > reader->used) {
        return;
    }

    whosudod_pam_secure_zero(reader->bytes, frame_length);
    remaining = reader->used - frame_length;
    if (remaining > 0U) {
        memmove(reader->bytes, reader->bytes + frame_length, remaining);
    }
    whosudod_pam_secure_zero(
        reader->bytes + remaining,
        sizeof(reader->bytes) - remaining
    );
    reader->used = remaining;
}

static bool
whosudod_pam_reader_receive(
    int descriptor,
    struct whosudod_pam_frame_reader *reader
)
{
    if (reader == NULL) {
        return false;
    }

    while (!reader->closed && reader->used < sizeof(reader->bytes)) {
        ssize_t received = recv(
            descriptor,
            reader->bytes + reader->used,
            sizeof(reader->bytes) - reader->used,
            MSG_DONTWAIT
        );

        if (received > 0) {
            reader->used += (size_t)received;
            continue;
        }
        if (received == 0) {
            reader->closed = true;
            return true;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return true;
        }
        return false;
    }
    return true;
}

static enum whosudod_pam_mode
whosudod_pam_parse_mode(int argument_count, const char **arguments)
{
    if (argument_count != 1 || arguments == NULL ||
        arguments[0] == NULL) {
        return WHOSUDOD_PAM_MODE_INVALID;
    }
    if (strcmp(arguments[0], WHOSUDOD_PAM_OFFER_ARGUMENT) == 0) {
        return WHOSUDOD_PAM_MODE_OFFER;
    }
    if (strcmp(arguments[0], WHOSUDOD_PAM_RESTORE_ARGUMENT) == 0) {
        return WHOSUDOD_PAM_MODE_RESTORE;
    }
    return WHOSUDOD_PAM_MODE_INVALID;
}

static void
whosudod_pam_process_arguments_clear(
    struct whosudod_pam_process_arguments *process_arguments
)
{
    if (process_arguments == NULL) {
        return;
    }

    if (process_arguments->buffer != NULL) {
        whosudod_pam_secure_zero(
            process_arguments->buffer,
            process_arguments->buffer_size
        );
        free(process_arguments->buffer);
    }
    if (process_arguments->arguments != NULL) {
        whosudod_pam_secure_zero(
            process_arguments->arguments,
            ((size_t)process_arguments->count + 1U) *
                sizeof(*process_arguments->arguments)
        );
        free(process_arguments->arguments);
    }
    memset(process_arguments, 0, sizeof(*process_arguments));
}

static bool
whosudod_pam_load_process_arguments(
    struct whosudod_pam_process_arguments *process_arguments
)
{
    int argument_maximum = 0;
    size_t argument_maximum_size = sizeof(argument_maximum);
    int maximum_mib[2] = { CTL_KERN, KERN_ARGMAX };
    int arguments_mib[3] = {
        CTL_KERN,
        KERN_PROCARGS2,
        (int)getpid(),
    };
    size_t data_size;
    const char *cursor;
    const char *end;
    const char *terminator;
    int argument_count;
    int index;

    if (process_arguments == NULL) {
        return false;
    }
    memset(process_arguments, 0, sizeof(*process_arguments));

    if (sysctl(
            maximum_mib,
            2,
            &argument_maximum,
            &argument_maximum_size,
            NULL,
            0) != 0 ||
        argument_maximum <= 0 ||
        (size_t)argument_maximum >
            WHOSUDOD_PAM_PROCESS_ARGUMENT_LIMIT) {
        return false;
    }

    process_arguments->buffer = calloc(1U, (size_t)argument_maximum);
    if (process_arguments->buffer == NULL) {
        return false;
    }
    process_arguments->buffer_size = (size_t)argument_maximum;
    data_size = process_arguments->buffer_size;

    if (sysctl(
            arguments_mib,
            3,
            process_arguments->buffer,
            &data_size,
            NULL,
            0) != 0 ||
        data_size < sizeof(argument_count)) {
        whosudod_pam_process_arguments_clear(process_arguments);
        return false;
    }

    memcpy(
        &argument_count,
        process_arguments->buffer,
        sizeof(argument_count)
    );
    if (argument_count < 1 || argument_count > 4096) {
        whosudod_pam_process_arguments_clear(process_arguments);
        return false;
    }

    process_arguments->arguments = calloc(
        (size_t)argument_count + 1U,
        sizeof(*process_arguments->arguments)
    );
    if (process_arguments->arguments == NULL) {
        whosudod_pam_process_arguments_clear(process_arguments);
        return false;
    }
    process_arguments->count = argument_count;

    cursor = process_arguments->buffer + sizeof(argument_count);
    end = process_arguments->buffer + data_size;
    terminator = memchr(cursor, '\0', (size_t)(end - cursor));
    if (terminator == NULL) {
        whosudod_pam_process_arguments_clear(process_arguments);
        return false;
    }
    cursor = terminator + 1;
    while (cursor < end && *cursor == '\0') {
        cursor += 1;
    }

    for (index = 0; index < argument_count; index += 1) {
        if (cursor >= end || *cursor == '\0') {
            whosudod_pam_process_arguments_clear(process_arguments);
            return false;
        }
        process_arguments->arguments[index] = (char *)cursor;
        terminator = memchr(cursor, '\0', (size_t)(end - cursor));
        if (terminator == NULL) {
            whosudod_pam_process_arguments_clear(process_arguments);
            return false;
        }
        cursor = terminator + 1;
    }
    process_arguments->arguments[argument_count] = NULL;
    return true;
}

static bool
whosudod_pam_is_sudo_process(void)
{
    char path[PROC_PIDPATHINFO_MAXSIZE];
    int length;

    if (getuid() == 0 || geteuid() != 0) {
        return false;
    }

    memset(path, 0, sizeof(path));
    length = proc_pidpath(getpid(), path, (uint32_t)sizeof(path));
    return length > 0 && (size_t)length < sizeof(path) &&
        strcmp(path, "/usr/bin/sudo") == 0;
}

static bool
whosudod_pam_invocation_is_allowed(pam_handle_t *pamh)
{
    const void *askpass_data = NULL;
    struct whosudod_pam_process_arguments process_arguments;
    bool allowed;

    if (pamh == NULL || !whosudod_pam_is_sudo_process()) {
        return false;
    }
    if (pam_get_data(
            pamh,
            WHOSUDOD_PAM_ASKPASS_DATA_KEY,
            &askpass_data) == PAM_SUCCESS) {
        return false;
    }

    if (!whosudod_pam_load_process_arguments(&process_arguments)) {
        return false;
    }
    allowed = whosudod_pam_invocation_allows_password_input(
        process_arguments.count,
        (const char *const *)process_arguments.arguments
    );
    whosudod_pam_process_arguments_clear(&process_arguments);
    return allowed;
}

static bool
whosudod_pam_callback_is_stock_sudo(const struct pam_conv *conversation)
{
    Dl_info information;
    const void *callback_address = NULL;

    if (conversation == NULL || conversation->conv == NULL ||
        sizeof(callback_address) != sizeof(conversation->conv)) {
        return false;
    }
    memcpy(
        &callback_address,
        &conversation->conv,
        sizeof(callback_address)
    );
    memset(&information, 0, sizeof(information));
    return dladdr(callback_address, &information) != 0 &&
        information.dli_fname != NULL &&
        strcmp(information.dli_fname, "/usr/bin/sudo") == 0;
}

static bool
whosudod_pam_copy_item(
    pam_handle_t *pamh,
    int item_type,
    char *destination,
    size_t capacity
)
{
    const void *item = NULL;
    const char *text;
    size_t length;

    if (pamh == NULL || destination == NULL || capacity == 0U ||
        pam_get_item(pamh, item_type, &item) != PAM_SUCCESS ||
        item == NULL) {
        return false;
    }

    text = item;
    length = strnlen(text, capacity);
    if (length == 0U || length >= capacity) {
        return false;
    }
    memcpy(destination, text, length);
    destination[length] = '\0';
    return true;
}

static bool
whosudod_pam_terminal_open(
    pam_handle_t *pamh,
    struct whosudod_pam_terminal *terminal
)
{
    char pam_terminal[WHOSUDOD_PAM_MAX_TTY_SIZE + 1U];
    struct stat expected_status;
    struct stat actual_status;
    pid_t foreground_group;

    if (terminal == NULL) {
        return false;
    }
    memset(terminal, 0, sizeof(*terminal));
    terminal->descriptor = -1;

    if (!whosudod_pam_copy_item(
            pamh,
            PAM_TTY,
            pam_terminal,
            sizeof(pam_terminal))) {
        return false;
    }

    terminal->descriptor = open(
        "/dev/tty",
        O_RDWR | O_NOCTTY | O_CLOEXEC
    );
    if (terminal->descriptor < 0) {
        return false;
    }
    if (stat(pam_terminal, &expected_status) != 0 ||
        fstat(terminal->descriptor, &actual_status) != 0 ||
        !S_ISCHR(expected_status.st_mode) ||
        !S_ISCHR(actual_status.st_mode) ||
        expected_status.st_rdev != actual_status.st_rdev) {
        whosudod_pam_close(&terminal->descriptor);
        return false;
    }

    do {
        foreground_group = tcgetpgrp(terminal->descriptor);
    } while (foreground_group < 0 && errno == EINTR);
    terminal->process_group = getpgrp();
    if (foreground_group <= 0 ||
        terminal->process_group <= 0 ||
        foreground_group != terminal->process_group) {
        whosudod_pam_close(&terminal->descriptor);
        return false;
    }

    while (tcgetattr(
            terminal->descriptor,
            &terminal->original) != 0) {
        if (errno != EINTR) {
            whosudod_pam_close(&terminal->descriptor);
            return false;
        }
    }
    if ((terminal->original.c_lflag & ICANON) == 0) {
        whosudod_pam_secure_zero(
            &terminal->original,
            sizeof(terminal->original)
        );
        whosudod_pam_close(&terminal->descriptor);
        return false;
    }

    return true;
}

static void
whosudod_pam_terminal_close(struct whosudod_pam_terminal *terminal)
{
    if (terminal == NULL) {
        return;
    }
    whosudod_pam_close(&terminal->descriptor);
    whosudod_pam_secure_zero(
        &terminal->original,
        sizeof(terminal->original)
    );
    terminal->process_group = 0;
}

static void
whosudod_pam_terminal_restore(
    const struct whosudod_pam_terminal *terminal,
    bool flush_input
)
{
    sigset_t block_set;
    sigset_t previous_set;
    bool mask_changed = false;

    if (terminal == NULL || terminal->descriptor < 0) {
        return;
    }

    if (sigemptyset(&block_set) == 0 &&
        sigaddset(&block_set, SIGTTOU) == 0 &&
        sigprocmask(SIG_BLOCK, &block_set, &previous_set) == 0) {
        mask_changed = true;
    }

    if (flush_input) {
        while (tcflush(terminal->descriptor, TCIFLUSH) != 0 &&
            errno == EINTR) {
        }
    }
    while (tcsetattr(
            terminal->descriptor,
            TCSANOW,
            &terminal->original) != 0 &&
        errno == EINTR) {
    }

    if (mask_changed) {
        while (sigprocmask(SIG_SETMASK, &previous_set, NULL) != 0 &&
            errno == EINTR) {
        }
    }
}

static void
whosudod_pam_terminal_write_newline(
    const struct whosudod_pam_terminal *terminal
)
{
    static const uint8_t newline = '\n';
    ssize_t result;

    if (terminal == NULL || terminal->descriptor < 0) {
        return;
    }
    do {
        result = write(
            terminal->descriptor,
            &newline,
            sizeof(newline)
        );
    } while (result < 0 && errno == EINTR);
}

static bool
whosudod_pam_terminal_is_eligible(pam_handle_t *pamh)
{
    struct whosudod_pam_terminal terminal;
    bool eligible = whosudod_pam_terminal_open(pamh, &terminal);

    if (eligible) {
        whosudod_pam_terminal_close(&terminal);
    }
    return eligible;
}

static bool
whosudod_pam_validate_socket_path(
    uid_t user_id,
    char socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)]
)
{
    struct stat socket_status;

    if (whosudod_pam_socket_path(
            user_id,
            socket_path,
            sizeof(((struct sockaddr_un *)0)->sun_path)) < 0) {
        return false;
    }

    if (lstat(socket_path, &socket_status) != 0 ||
        !S_ISSOCK(socket_status.st_mode) ||
        socket_status.st_uid != user_id ||
        (socket_status.st_mode & 0777U) != 0600U) {
        return false;
    }
    return true;
}

static bool
whosudod_pam_verify_peer(int descriptor, uid_t expected_user_id)
{
    uid_t peer_user_id = (uid_t)-1;
    gid_t peer_group_id = (gid_t)-1;
    audit_token_t peer_token;
    socklen_t peer_token_length = sizeof(peer_token);
    SecCodeRef peer_code = NULL;
    SecRequirementRef requirement = NULL;
    CFDataRef audit_data = NULL;
    CFDictionaryRef attributes = NULL;
    CFMutableDictionaryRef mutable_attributes = NULL;
    OSStatus status;
    bool trusted = false;

    memset(&peer_token, 0, sizeof(peer_token));
    if (getpeereid(
            descriptor,
            &peer_user_id,
            &peer_group_id) != 0 ||
        peer_user_id != expected_user_id ||
        getsockopt(
            descriptor,
            SOL_LOCAL,
            LOCAL_PEERTOKEN,
            &peer_token,
            &peer_token_length) != 0 ||
        peer_token_length != sizeof(peer_token)) {
        return false;
    }
    (void)peer_group_id;

    audit_data = CFDataCreate(
        kCFAllocatorDefault,
        (const UInt8 *)&peer_token,
        (CFIndex)sizeof(peer_token)
    );
    if (audit_data == NULL) {
        goto finished;
    }
    mutable_attributes = CFDictionaryCreateMutable(
        kCFAllocatorDefault,
        1,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );
    if (mutable_attributes == NULL) {
        goto finished;
    }
    CFDictionarySetValue(
        mutable_attributes,
        kSecGuestAttributeAudit,
        audit_data
    );
    attributes = mutable_attributes;

    status = SecCodeCopyGuestWithAttributes(
        NULL,
        attributes,
        kSecCSDefaultFlags,
        &peer_code
    );
    if (status != errSecSuccess || peer_code == NULL) {
        goto finished;
    }
    status = SecRequirementCreateWithString(
        CFSTR(WHOSUDOD_PAM_APP_SIGNING_REQUIREMENT),
        kSecCSDefaultFlags,
        &requirement
    );
    if (status != errSecSuccess || requirement == NULL) {
        goto finished;
    }
    trusted = SecCodeCheckValidity(
        peer_code,
        kSecCSStrictValidate,
        requirement
    ) == errSecSuccess;

finished:
    if (requirement != NULL) {
        CFRelease(requirement);
    }
    if (peer_code != NULL) {
        CFRelease(peer_code);
    }
    if (mutable_attributes != NULL) {
        CFRelease(mutable_attributes);
    }
    if (audit_data != NULL) {
        CFRelease(audit_data);
    }
    whosudod_pam_secure_zero(&peer_token, sizeof(peer_token));
    return trusted;
}

static int
whosudod_pam_connect_to_app(uid_t user_id)
{
    char socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    struct sockaddr_un address;
    int descriptor = -1;
    int connection_result;
    struct timespec deadline;
    short returned_events = 0;
    int socket_error = 0;
    socklen_t socket_error_length = sizeof(socket_error);

    memset(socket_path, 0, sizeof(socket_path));
    if (!whosudod_pam_validate_socket_path(user_id, socket_path)) {
        return -1;
    }

    descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
    if (descriptor < 0 ||
        !whosudod_pam_configure_socket(descriptor)) {
        whosudod_pam_close(&descriptor);
        return -1;
    }

    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, socket_path, strlen(socket_path) + 1U);

    do {
        connection_result = connect(
            descriptor,
            (const struct sockaddr *)&address,
            (socklen_t)sizeof(address)
        );
    } while (connection_result != 0 && errno == EINTR);
    if (connection_result != 0 && errno != EINPROGRESS &&
        errno != EALREADY && errno != EISCONN) {
        whosudod_pam_close(&descriptor);
        return -1;
    }
    if (connection_result != 0 && errno != EISCONN) {
        if (!whosudod_pam_add_milliseconds(
                &deadline,
                WHOSUDOD_PAM_CONNECT_TIMEOUT_MILLISECONDS) ||
            !whosudod_pam_poll_descriptor(
                descriptor,
                POLLOUT,
                &deadline,
                &returned_events) ||
            (returned_events & (POLLERR | POLLHUP | POLLNVAL)) != 0 ||
            getsockopt(
                descriptor,
                SOL_SOCKET,
                SO_ERROR,
                &socket_error,
                &socket_error_length) != 0 ||
            socket_error != 0) {
            whosudod_pam_close(&descriptor);
            return -1;
        }
    }

    if (!whosudod_pam_verify_peer(descriptor, user_id)) {
        whosudod_pam_close(&descriptor);
        return -1;
    }
    return descriptor;
}

static bool
whosudod_pam_send_begin(
    int descriptor,
    pam_handle_t *pamh,
    const char *prompt,
    const uint8_t request_id[WHOSUDOD_PAM_REQUEST_ID_SIZE]
)
{
    uint8_t payload[
        WHOSUDOD_PAM_BEGIN_PREFIX_SIZE +
        WHOSUDOD_PAM_MAX_USERNAME_SIZE +
        WHOSUDOD_PAM_MAX_TTY_SIZE +
        WHOSUDOD_PAM_MAX_PROMPT_SIZE
    ];
    char username[WHOSUDOD_PAM_MAX_USERNAME_SIZE + 1U];
    char terminal[WHOSUDOD_PAM_MAX_TTY_SIZE + 1U];
    size_t username_length;
    size_t terminal_length;
    size_t prompt_length;
    size_t payload_length;
    uint8_t *cursor;
    bool sent;

    memset(payload, 0, sizeof(payload));
    memset(username, 0, sizeof(username));
    memset(terminal, 0, sizeof(terminal));
    if (!whosudod_pam_copy_item(
            pamh,
            PAM_USER,
            username,
            sizeof(username)) ||
        !whosudod_pam_copy_item(
            pamh,
            PAM_TTY,
            terminal,
            sizeof(terminal)) ||
        prompt == NULL) {
        return false;
    }

    username_length = strlen(username);
    terminal_length = strlen(terminal);
    prompt_length = strnlen(
        prompt,
        WHOSUDOD_PAM_MAX_PROMPT_SIZE + 1U
    );
    if (prompt_length == 0U ||
        prompt_length > WHOSUDOD_PAM_MAX_PROMPT_SIZE) {
        return false;
    }

    whosudod_pam_encode_u32(payload, (uint32_t)getpid());
    whosudod_pam_encode_u32(payload + 4, (uint32_t)getuid());
    whosudod_pam_encode_u16(payload + 8, (uint16_t)username_length);
    whosudod_pam_encode_u16(payload + 10, (uint16_t)terminal_length);
    whosudod_pam_encode_u16(payload + 12, (uint16_t)prompt_length);
    whosudod_pam_encode_u16(payload + 14, 0U);
    cursor = payload + WHOSUDOD_PAM_BEGIN_PREFIX_SIZE;
    memcpy(cursor, username, username_length);
    cursor += username_length;
    memcpy(cursor, terminal, terminal_length);
    cursor += terminal_length;
    memcpy(cursor, prompt, prompt_length);
    payload_length =
        WHOSUDOD_PAM_BEGIN_PREFIX_SIZE +
        username_length +
        terminal_length +
        prompt_length;

    sent = whosudod_pam_send_frame(
        descriptor,
        WHOSUDOD_PAM_MESSAGE_BEGIN,
        request_id,
        payload,
        (uint32_t)payload_length
    );
    whosudod_pam_secure_zero(payload, sizeof(payload));
    whosudod_pam_secure_zero(username, sizeof(username));
    whosudod_pam_secure_zero(terminal, sizeof(terminal));
    return sent;
}

static void
whosudod_pam_send_end(
    int descriptor,
    const uint8_t request_id[WHOSUDOD_PAM_REQUEST_ID_SIZE]
)
{
    if (descriptor >= 0) {
        (void)whosudod_pam_send_frame(
            descriptor,
            WHOSUDOD_PAM_MESSAGE_END,
            request_id,
            NULL,
            0U
        );
    }
}

static bool
whosudod_pam_wait_for_ready(
    int descriptor,
    const uint8_t request_id[WHOSUDOD_PAM_REQUEST_ID_SIZE],
    struct whosudod_pam_frame_reader *reader
)
{
    struct timespec deadline;

    if (!whosudod_pam_add_milliseconds(
            &deadline,
            WHOSUDOD_PAM_READY_TIMEOUT_MILLISECONDS)) {
        return false;
    }

    for (;;) {
        struct whosudod_pam_frame_view view;
        enum whosudod_pam_frame_status status =
            whosudod_pam_reader_peek(reader, request_id, &view);

        if (status == WHOSUDOD_PAM_FRAME_INVALID) {
            return false;
        }
        if (status == WHOSUDOD_PAM_FRAME_COMPLETE) {
            bool ready =
                view.message_type == WHOSUDOD_PAM_MESSAGE_READY &&
                view.payload_length == 0U;
            bool rejected =
                view.message_type == WHOSUDOD_PAM_MESSAGE_CANCEL &&
                view.payload_length == 0U;

            whosudod_pam_reader_consume(reader, view.frame_length);
            if (ready) {
                return true;
            }
            if (rejected) {
                return false;
            }
            return false;
        }
        if (reader->closed) {
            return false;
        }

        {
            short returned_events = 0;

            if (!whosudod_pam_poll_descriptor(
                    descriptor,
                    POLLIN,
                    &deadline,
                    &returned_events) ||
                (returned_events & (POLLERR | POLLNVAL)) != 0 ||
                !whosudod_pam_reader_receive(descriptor, reader)) {
                return false;
            }
        }
    }
}

static bool
whosudod_pam_path_has_no_extended_acl(const char *path)
{
    acl_t access_control_list;
    acl_entry_t entry = NULL;
    int entry_result;

    access_control_list = acl_get_file(path, ACL_TYPE_EXTENDED);
    if (access_control_list == NULL) {
        return false;
    }
    entry_result = acl_get_entry(
        access_control_list,
        ACL_FIRST_ENTRY,
        &entry
    );
    (void)acl_free(access_control_list);
    return entry_result == 0;
}

static bool
whosudod_pam_safe_root_path(
    const char *path,
    bool directory,
    mode_t expected_mode
)
{
    struct stat status;

    if (lstat(path, &status) != 0 ||
        status.st_uid != 0 ||
        status.st_gid != 0 ||
        (status.st_mode & 07777U) != expected_mode ||
        !whosudod_pam_path_has_no_extended_acl(path)) {
        return false;
    }
    if (directory) {
        return S_ISDIR(status.st_mode);
    }
    return S_ISREG(status.st_mode) && status.st_nlink == 1;
}

static bool
whosudod_pam_validate_helper(void)
{
    CFURLRef helper_url = NULL;
    SecStaticCodeRef static_code = NULL;
    SecRequirementRef requirement = NULL;
    OSStatus status;
    bool valid = false;

    if (!whosudod_pam_safe_root_path(
            "/Library",
            true,
            0755U) ||
        !whosudod_pam_safe_root_path(
            "/Library/Security",
            true,
            0755U) ||
        !whosudod_pam_safe_root_path(
            WHOSUDOD_PAM_INSTALL_DIRECTORY,
            true,
            0755U) ||
        !whosudod_pam_safe_root_path(
            WHOSUDOD_PAM_TERMINAL_READER_PATH,
            false,
            0555U)) {
        return false;
    }

    helper_url = CFURLCreateFromFileSystemRepresentation(
        kCFAllocatorDefault,
        (const UInt8 *)WHOSUDOD_PAM_TERMINAL_READER_PATH,
        strlen(WHOSUDOD_PAM_TERMINAL_READER_PATH),
        false
    );
    if (helper_url == NULL) {
        goto finished;
    }
    status = SecStaticCodeCreateWithPath(
        helper_url,
        kSecCSDefaultFlags,
        &static_code
    );
    if (status != errSecSuccess || static_code == NULL) {
        goto finished;
    }
    status = SecRequirementCreateWithString(
        CFSTR(WHOSUDOD_PAM_HELPER_SIGNING_REQUIREMENT),
        kSecCSDefaultFlags,
        &requirement
    );
    if (status != errSecSuccess || requirement == NULL) {
        goto finished;
    }
    valid = SecStaticCodeCheckValidity(
        static_code,
        kSecCSStrictValidate,
        requirement
    ) == errSecSuccess;

finished:
    if (requirement != NULL) {
        CFRelease(requirement);
    }
    if (static_code != NULL) {
        CFRelease(static_code);
    }
    if (helper_url != NULL) {
        CFRelease(helper_url);
    }
    return valid;
}

static bool
whosudod_pam_move_socket_away_from_control_descriptor(
    int descriptors[2]
)
{
    size_t index;

    for (index = 0U; index < 2U; index += 1U) {
        if (descriptors[index] == WHOSUDOD_PAM_CONTROL_DESCRIPTOR) {
            int replacement;

            do {
                replacement = fcntl(
                    descriptors[index],
                    F_DUPFD_CLOEXEC,
                    WHOSUDOD_PAM_CONTROL_DESCRIPTOR + 1
                );
            } while (replacement < 0 && errno == EINTR);
            if (replacement < 0) {
                return false;
            }
            whosudod_pam_close(&descriptors[index]);
            descriptors[index] = replacement;
        }
    }
    return true;
}

static bool
whosudod_pam_create_socket_pair(int descriptors[2])
{
    descriptors[0] = -1;
    descriptors[1] = -1;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, descriptors) != 0 ||
        !whosudod_pam_move_socket_away_from_control_descriptor(descriptors) ||
        !whosudod_pam_configure_socket(descriptors[0]) ||
        !whosudod_pam_configure_socket(descriptors[1])) {
        whosudod_pam_close(&descriptors[0]);
        whosudod_pam_close(&descriptors[1]);
        return false;
    }
    return true;
}

static bool
whosudod_pam_block_sigchld(sigset_t *previous_mask)
{
    sigset_t blocked_mask;

    if (previous_mask == NULL ||
        sigemptyset(&blocked_mask) != 0 ||
        sigaddset(&blocked_mask, SIGCHLD) != 0) {
        return false;
    }
    return sigprocmask(SIG_BLOCK, &blocked_mask, previous_mask) == 0;
}

static void
whosudod_pam_restore_signal_mask(const sigset_t *previous_mask)
{
    if (previous_mask != NULL) {
        (void)sigprocmask(SIG_SETMASK, previous_mask, NULL);
    }
}

static bool
whosudod_pam_spawn_helper(
    pid_t process_group,
    const sigset_t *child_signal_mask,
    int *parent_descriptor,
    pid_t *child_process
)
{
    int descriptors[2] = { -1, -1 };
    posix_spawn_file_actions_t file_actions;
    posix_spawnattr_t attributes;
    bool actions_initialized = false;
    bool attributes_initialized = false;
    short flags = (short)(
        POSIX_SPAWN_RESETIDS |
        POSIX_SPAWN_SETPGROUP |
        POSIX_SPAWN_SETSIGMASK |
        POSIX_SPAWN_CLOEXEC_DEFAULT
    );
    char *const arguments[] = {
        (char *)WHOSUDOD_PAM_TERMINAL_READER_PATH,
        NULL,
    };
    char *const environment[] = { NULL };
    int result = EINVAL;

    if (child_signal_mask == NULL ||
        parent_descriptor == NULL || child_process == NULL ||
        process_group <= 0 ||
        !whosudod_pam_create_socket_pair(descriptors)) {
        return false;
    }
    *parent_descriptor = -1;
    *child_process = -1;

    if (posix_spawn_file_actions_init(&file_actions) != 0) {
        goto finished;
    }
    actions_initialized = true;
    if (posix_spawn_file_actions_adddup2(
            &file_actions,
            descriptors[1],
            WHOSUDOD_PAM_CONTROL_DESCRIPTOR) != 0 ||
        posix_spawn_file_actions_addclose(
            &file_actions,
            descriptors[0]) != 0 ||
        posix_spawn_file_actions_addclose(
            &file_actions,
            descriptors[1]) != 0) {
        goto finished;
    }

    if (posix_spawnattr_init(&attributes) != 0) {
        goto finished;
    }
    attributes_initialized = true;
    if (posix_spawnattr_setflags(&attributes, flags) != 0 ||
        posix_spawnattr_setpgroup(&attributes, process_group) != 0 ||
        posix_spawnattr_setsigmask(&attributes, child_signal_mask) != 0) {
        goto finished;
    }

    result = posix_spawn(
        child_process,
        WHOSUDOD_PAM_TERMINAL_READER_PATH,
        &file_actions,
        &attributes,
        arguments,
        environment
    );
    if (result == 0) {
        *parent_descriptor = descriptors[0];
        descriptors[0] = -1;
    }

finished:
    if (attributes_initialized) {
        (void)posix_spawnattr_destroy(&attributes);
    }
    if (actions_initialized) {
        (void)posix_spawn_file_actions_destroy(&file_actions);
    }
    whosudod_pam_close(&descriptors[0]);
    whosudod_pam_close(&descriptors[1]);
    return result == 0;
}

static enum whosudod_pam_child_wait_result
whosudod_pam_wait_for_child(
    pid_t child_process,
    unsigned int timeout_milliseconds,
    int *child_status
)
{
    struct timespec deadline;
    struct timespec pause = { .tv_sec = 0, .tv_nsec = 10000000L };

    if (child_process <= 0 || child_status == NULL ||
        !whosudod_pam_add_milliseconds(
            &deadline,
            timeout_milliseconds)) {
        return WHOSUDOD_PAM_CHILD_WAIT_ERROR;
    }

    for (;;) {
        pid_t result;

        do {
            result = waitpid(child_process, child_status, WNOHANG);
        } while (result < 0 && errno == EINTR);
        if (result == child_process) {
            return WHOSUDOD_PAM_CHILD_REAPED;
        }
        if (result < 0) {
            return WHOSUDOD_PAM_CHILD_WAIT_ERROR;
        }
        if (whosudod_pam_remaining_milliseconds(&deadline) <= 0) {
            return WHOSUDOD_PAM_CHILD_TIMED_OUT;
        }

        while (nanosleep(&pause, &pause) != 0 && errno == EINTR) {
        }
        pause.tv_sec = 0;
        pause.tv_nsec = 10000000L;
    }
}

static void
whosudod_pam_stop_and_reap_child(
    pid_t child_process,
    int helper_descriptor,
    const uint8_t request_id[WHOSUDOD_PAM_REQUEST_ID_SIZE],
    int *child_status,
    bool *child_status_valid
)
{
    int local_status = 0;
    enum whosudod_pam_child_wait_result wait_result;

    if (child_status_valid != NULL) {
        *child_status_valid = false;
    }
    if (child_process <= 0) {
        return;
    }

    if (helper_descriptor >= 0 && request_id != NULL) {
        (void)whosudod_pam_send_frame(
            helper_descriptor,
            WHOSUDOD_PAM_MESSAGE_CANCEL,
            request_id,
            NULL,
            0U
        );
    }
    wait_result = whosudod_pam_wait_for_child(
        child_process,
        WHOSUDOD_PAM_CHILD_GRACE_MILLISECONDS,
        &local_status
    );
    if (wait_result == WHOSUDOD_PAM_CHILD_TIMED_OUT) {
        (void)kill(child_process, SIGCONT);
        wait_result = whosudod_pam_wait_for_child(
            child_process,
            WHOSUDOD_PAM_CHILD_GRACE_MILLISECONDS,
            &local_status
        );
    }
    if (wait_result == WHOSUDOD_PAM_CHILD_TIMED_OUT) {
        (void)kill(child_process, SIGTERM);
        (void)kill(child_process, SIGCONT);
        wait_result = whosudod_pam_wait_for_child(
            child_process,
            WHOSUDOD_PAM_CHILD_GRACE_MILLISECONDS,
            &local_status
        );
    }
    if (wait_result == WHOSUDOD_PAM_CHILD_TIMED_OUT) {
        pid_t result;

        (void)kill(child_process, SIGKILL);
        do {
            result = waitpid(child_process, &local_status, 0);
        } while (result < 0 && errno == EINTR);
        wait_result = result == child_process
            ? WHOSUDOD_PAM_CHILD_REAPED
            : WHOSUDOD_PAM_CHILD_WAIT_ERROR;
    }

    if (wait_result == WHOSUDOD_PAM_CHILD_REAPED &&
        child_status != NULL) {
        *child_status = local_status;
    }
    if (child_status_valid != NULL) {
        *child_status_valid =
            wait_result == WHOSUDOD_PAM_CHILD_REAPED;
    }
}

static bool
whosudod_pam_copy_password(
    struct whosudod_pam_race_outcome *outcome,
    enum whosudod_pam_race_result result,
    const uint8_t *password,
    uint32_t password_length,
    bool permit_empty
)
{
    if (outcome == NULL || password == NULL ||
        password_length > WHOSUDOD_PAM_MAX_PASSWORD_SIZE ||
        (!permit_empty && password_length == 0U) ||
        memchr(password, '\0', password_length) != NULL) {
        return false;
    }

    if (password_length > 0U) {
        memcpy(outcome->password, password, password_length);
    }
    outcome->password_length = (size_t)password_length;
    outcome->result = result;
    return true;
}

static bool
whosudod_pam_process_helper_frame(
    struct whosudod_pam_frame_reader *reader,
    const uint8_t request_id[WHOSUDOD_PAM_REQUEST_ID_SIZE],
    bool *helper_ready,
    struct whosudod_pam_race_outcome *outcome,
    bool *made_progress
)
{
    struct whosudod_pam_frame_view view;
    enum whosudod_pam_frame_status status;

    *made_progress = false;
    status = whosudod_pam_reader_peek(reader, request_id, &view);
    if (status == WHOSUDOD_PAM_FRAME_INCOMPLETE) {
        return true;
    }
    if (status == WHOSUDOD_PAM_FRAME_INVALID) {
        return false;
    }

    *made_progress = true;
    if (!*helper_ready &&
        view.message_type == WHOSUDOD_PAM_MESSAGE_TERMINAL_READY &&
        view.payload_length == 0U) {
        *helper_ready = true;
        whosudod_pam_reader_consume(reader, view.frame_length);
        return true;
    }
    if (*helper_ready &&
        view.message_type == WHOSUDOD_PAM_MESSAGE_PASSWORD &&
        whosudod_pam_copy_password(
            outcome,
            WHOSUDOD_PAM_RACE_HELPER_PASSWORD,
            view.payload,
            view.payload_length,
            true)) {
        whosudod_pam_reader_consume(reader, view.frame_length);
        return true;
    }
    if (view.message_type == WHOSUDOD_PAM_MESSAGE_TERMINAL_FAILURE &&
        view.payload_length == 0U) {
        outcome->result = WHOSUDOD_PAM_RACE_FAILURE;
        whosudod_pam_reader_consume(reader, view.frame_length);
        return true;
    }
    return false;
}

static bool
whosudod_pam_process_app_frame(
    struct whosudod_pam_frame_reader *reader,
    const uint8_t request_id[WHOSUDOD_PAM_REQUEST_ID_SIZE],
    bool helper_ready,
    bool *app_input_active,
    struct whosudod_pam_pending_password *pending_password,
    struct whosudod_pam_race_outcome *outcome,
    bool *made_progress
)
{
    struct whosudod_pam_frame_view view;
    enum whosudod_pam_frame_status status;

    *made_progress = false;
    status = whosudod_pam_reader_peek(reader, request_id, &view);
    if (status == WHOSUDOD_PAM_FRAME_INCOMPLETE) {
        return true;
    }
    if (status == WHOSUDOD_PAM_FRAME_INVALID) {
        return false;
    }

    *made_progress = true;
    if (view.message_type == WHOSUDOD_PAM_MESSAGE_PASSWORD &&
        view.payload_length > 0U &&
        view.payload_length <= WHOSUDOD_PAM_MAX_PASSWORD_SIZE &&
        memchr(view.payload, '\0', view.payload_length) == NULL) {
        if (helper_ready) {
            if (!whosudod_pam_copy_password(
                    outcome,
                    WHOSUDOD_PAM_RACE_APP_PASSWORD,
                    view.payload,
                    view.payload_length,
                    false)) {
                return false;
            }
        } else {
            if (pending_password->available) {
                return false;
            }
            memcpy(
                pending_password->bytes,
                view.payload,
                view.payload_length
            );
            pending_password->length = view.payload_length;
            pending_password->available = true;
        }
        whosudod_pam_reader_consume(reader, view.frame_length);
        return true;
    }
    if (view.message_type == WHOSUDOD_PAM_MESSAGE_CANCEL &&
        view.payload_length == 0U) {
        *app_input_active = false;
        whosudod_pam_secure_zero(
            pending_password,
            sizeof(*pending_password)
        );
        whosudod_pam_reader_consume(reader, view.frame_length);
        return true;
    }
    return false;
}

static void
whosudod_pam_race_inputs(
    int helper_descriptor,
    int app_descriptor,
    const uint8_t request_id[WHOSUDOD_PAM_REQUEST_ID_SIZE],
    struct whosudod_pam_frame_reader *app_reader,
    struct whosudod_pam_race_outcome *outcome
)
{
    struct whosudod_pam_frame_reader helper_reader;
    struct whosudod_pam_pending_password pending_app_password;
    bool helper_ready = false;
    bool app_input_active = !app_reader->closed;

    memset(outcome, 0, sizeof(*outcome));
    memset(&helper_reader, 0, sizeof(helper_reader));
    memset(&pending_app_password, 0, sizeof(pending_app_password));
    outcome->result = WHOSUDOD_PAM_RACE_PENDING;

    for (;;) {
        bool made_progress = false;

        if (!whosudod_pam_process_helper_frame(
                &helper_reader,
                request_id,
                &helper_ready,
                outcome,
                &made_progress)) {
            break;
        }
        if (outcome->result != WHOSUDOD_PAM_RACE_PENDING) {
            break;
        }
        if (made_progress) {
            continue;
        }
        if (helper_reader.closed) {
            break;
        }
        if (helper_ready && pending_app_password.available) {
            if (!whosudod_pam_copy_password(
                    outcome,
                    WHOSUDOD_PAM_RACE_APP_PASSWORD,
                    pending_app_password.bytes,
                    (uint32_t)pending_app_password.length,
                    false)) {
                break;
            }
            whosudod_pam_secure_zero(
                &pending_app_password,
                sizeof(pending_app_password)
            );
            break;
        }

        if (app_input_active) {
            if (!whosudod_pam_process_app_frame(
                    app_reader,
                    request_id,
                    helper_ready,
                    &app_input_active,
                    &pending_app_password,
                    outcome,
                    &made_progress)) {
                app_input_active = false;
                whosudod_pam_secure_zero(
                    &pending_app_password,
                    sizeof(pending_app_password)
                );
                whosudod_pam_reader_clear(app_reader);
                app_reader->closed = true;
            } else if (outcome->result ==
                    WHOSUDOD_PAM_RACE_APP_PASSWORD) {
                break;
            } else if (made_progress) {
                continue;
            }
            if (app_reader->closed) {
                app_input_active = false;
            }
        }

        {
            struct pollfd descriptors[2];
            nfds_t descriptor_count = 1U;
            int poll_result;

            memset(descriptors, 0, sizeof(descriptors));
            descriptors[0].fd = helper_descriptor;
            descriptors[0].events = POLLIN;
            if (app_input_active) {
                descriptors[1].fd = app_descriptor;
                descriptors[1].events = POLLIN;
                descriptor_count = 2U;
            }

            do {
                poll_result = poll(descriptors, descriptor_count, -1);
            } while (poll_result < 0 && errno == EINTR);
            if (poll_result <= 0 ||
                (descriptors[0].revents & POLLNVAL) != 0) {
                break;
            }

            if (descriptors[0].revents &
                    (POLLIN | POLLHUP | POLLERR)) {
                if (!whosudod_pam_reader_receive(
                        helper_descriptor,
                        &helper_reader)) {
                    break;
                }
            }
            if (app_input_active &&
                (descriptors[1].revents &
                    (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0) {
                if (!whosudod_pam_reader_receive(
                        app_descriptor,
                        app_reader)) {
                    app_input_active = false;
                    whosudod_pam_reader_clear(app_reader);
                    app_reader->closed = true;
                }
            }
        }
    }

    whosudod_pam_reader_clear(&helper_reader);
    whosudod_pam_secure_zero(
        &pending_app_password,
        sizeof(pending_app_password)
    );
    if (outcome->result == WHOSUDOD_PAM_RACE_PENDING) {
        outcome->result = WHOSUDOD_PAM_RACE_FAILURE;
    }
}

static int
whosudod_pam_make_response(
    const uint8_t *password,
    size_t password_length,
    struct pam_response **responses
)
{
    struct pam_response *result;
    char *response;

    if (password == NULL || responses == NULL ||
        password_length > WHOSUDOD_PAM_MAX_PASSWORD_SIZE) {
        return PAM_CONV_ERR;
    }
    *responses = NULL;

    result = calloc(1U, sizeof(*result));
    response = calloc(password_length + 1U, 1U);
    if (result == NULL || response == NULL) {
        free(result);
        free(response);
        return PAM_BUF_ERR;
    }
    if (password_length > 0U) {
        memcpy(response, password, password_length);
    }
    result[0].resp = response;
    result[0].resp_retcode = 0;
    *responses = result;
    return PAM_SUCCESS;
}

static int
whosudod_pam_call_original(
    const struct pam_conv *original,
    int message_count,
    const struct pam_message **messages,
    struct pam_response **responses
)
{
    if (original == NULL || original->conv == NULL) {
        return PAM_CONV_ERR;
    }
    return original->conv(
        message_count,
        messages,
        responses,
        original->appdata_ptr
    );
}

static int
whosudod_pam_handle_password_prompt(
    pam_handle_t *pamh,
    const struct pam_conv *original,
    int message_count,
    const struct pam_message **messages,
    struct pam_response **responses
)
{
    struct whosudod_pam_terminal terminal;
    struct whosudod_pam_frame_reader app_reader;
    struct whosudod_pam_race_outcome outcome;
    uint8_t request_id[WHOSUDOD_PAM_REQUEST_ID_SIZE];
    int app_descriptor = -1;
    int helper_descriptor = -1;
    pid_t helper_process = -1;
    int helper_status = 0;
    bool helper_status_valid = false;
    int result = PAM_CONV_ERR;
    bool helper_spawned = false;
    sigset_t previous_signal_mask;
    bool sigchld_blocked = false;

    memset(&terminal, 0, sizeof(terminal));
    terminal.descriptor = -1;
    memset(&app_reader, 0, sizeof(app_reader));
    memset(&outcome, 0, sizeof(outcome));
    memset(request_id, 0, sizeof(request_id));
    memset(&previous_signal_mask, 0, sizeof(previous_signal_mask));

    if (!whosudod_pam_invocation_is_allowed(pamh) ||
        !whosudod_pam_terminal_open(pamh, &terminal)) {
        return whosudod_pam_call_original(
            original,
            message_count,
            messages,
            responses
        );
    }
    if (!whosudod_pam_validate_helper()) {
        whosudod_pam_terminal_close(&terminal);
        return whosudod_pam_call_original(
            original,
            message_count,
            messages,
            responses
        );
    }

    app_descriptor = whosudod_pam_connect_to_app(getuid());
    arc4random_buf(request_id, sizeof(request_id));
    if (app_descriptor < 0 ||
        !whosudod_pam_send_begin(
            app_descriptor,
            pamh,
            messages[0]->msg,
            request_id) ||
        !whosudod_pam_wait_for_ready(
            app_descriptor,
            request_id,
            &app_reader)) {
        whosudod_pam_send_end(app_descriptor, request_id);
        whosudod_pam_close(&app_descriptor);
        whosudod_pam_terminal_close(&terminal);
        whosudod_pam_reader_clear(&app_reader);
        whosudod_pam_secure_zero(request_id, sizeof(request_id));
        return whosudod_pam_call_original(
            original,
            message_count,
            messages,
            responses
        );
    }

    if (!whosudod_pam_block_sigchld(&previous_signal_mask)) {
        whosudod_pam_send_end(app_descriptor, request_id);
        whosudod_pam_close(&app_descriptor);
        whosudod_pam_terminal_close(&terminal);
        whosudod_pam_reader_clear(&app_reader);
        whosudod_pam_secure_zero(request_id, sizeof(request_id));
        return PAM_CONV_ERR;
    }
    sigchld_blocked = true;
    if (!whosudod_pam_spawn_helper(
            terminal.process_group,
            &previous_signal_mask,
            &helper_descriptor,
            &helper_process)) {
        whosudod_pam_send_end(app_descriptor, request_id);
        whosudod_pam_close(&app_descriptor);
        whosudod_pam_terminal_close(&terminal);
        whosudod_pam_reader_clear(&app_reader);
        whosudod_pam_secure_zero(request_id, sizeof(request_id));
        whosudod_pam_restore_signal_mask(&previous_signal_mask);
        return PAM_CONV_ERR;
    }
    helper_spawned = true;

    if (!whosudod_pam_send_frame(
            helper_descriptor,
            WHOSUDOD_PAM_MESSAGE_TERMINAL_START,
            request_id,
            messages[0]->msg,
            (uint32_t)strlen(messages[0]->msg))) {
        goto finished;
    }

    whosudod_pam_race_inputs(
        helper_descriptor,
        app_descriptor,
        request_id,
        &app_reader,
        &outcome
    );

    if (outcome.result == WHOSUDOD_PAM_RACE_APP_PASSWORD) {
        bool helper_cancelled_cleanly;

        whosudod_pam_stop_and_reap_child(
            helper_process,
            helper_descriptor,
            request_id,
            &helper_status,
            &helper_status_valid
        );
        helper_process = -1;
        helper_cancelled_cleanly =
            helper_status_valid &&
            WIFEXITED(helper_status) &&
            WEXITSTATUS(helper_status) == 0;
        whosudod_pam_terminal_restore(&terminal, true);
        if (!helper_cancelled_cleanly) {
            whosudod_pam_terminal_write_newline(&terminal);
        }
        result = whosudod_pam_make_response(
            outcome.password,
            outcome.password_length,
            responses
        );
        goto finished;
    }

    if (outcome.result == WHOSUDOD_PAM_RACE_HELPER_PASSWORD) {
        if (whosudod_pam_wait_for_child(
                helper_process,
                WHOSUDOD_PAM_CHILD_GRACE_MILLISECONDS,
                &helper_status) != WHOSUDOD_PAM_CHILD_REAPED) {
            whosudod_pam_stop_and_reap_child(
                helper_process,
                helper_descriptor,
                request_id,
                &helper_status,
                &helper_status_valid
            );
        } else {
            helper_status_valid = true;
        }
        helper_process = -1;
        whosudod_pam_terminal_restore(&terminal, false);
        if (helper_status_valid &&
            WIFEXITED(helper_status) &&
            WEXITSTATUS(helper_status) == 0) {
            result = whosudod_pam_make_response(
                outcome.password,
                outcome.password_length,
                responses
            );
        }
        goto finished;
    }

    whosudod_pam_stop_and_reap_child(
        helper_process,
        helper_descriptor,
        request_id,
        &helper_status,
        &helper_status_valid
    );
    helper_process = -1;
    whosudod_pam_terminal_restore(&terminal, true);

finished:
    if (helper_spawned && helper_process > 0) {
        whosudod_pam_stop_and_reap_child(
            helper_process,
            helper_descriptor,
            request_id,
            &helper_status,
            &helper_status_valid
        );
        helper_process = -1;
        whosudod_pam_terminal_restore(&terminal, true);
    }
    whosudod_pam_send_end(app_descriptor, request_id);
    whosudod_pam_close(&helper_descriptor);
    whosudod_pam_close(&app_descriptor);
    whosudod_pam_terminal_close(&terminal);
    whosudod_pam_reader_clear(&app_reader);
    whosudod_pam_secure_zero(&outcome, sizeof(outcome));
    whosudod_pam_secure_zero(request_id, sizeof(request_id));
    if (sigchld_blocked) {
        whosudod_pam_restore_signal_mask(&previous_signal_mask);
    }
    whosudod_pam_secure_zero(
        &previous_signal_mask,
        sizeof(previous_signal_mask)
    );
    helper_status = 0;
    helper_status_valid = false;
    return result;
}

static int
whosudod_pam_conversation(
    int message_count,
    const struct pam_message **messages,
    struct pam_response **responses,
    void *application_data
)
{
    struct whosudod_pam_state *state = application_data;
    struct pam_conv original;

    if (responses != NULL) {
        *responses = NULL;
    }
    if (state == NULL || state->pamh == NULL ||
        state->original.conv == NULL || responses == NULL) {
        return PAM_CONV_ERR;
    }

    original = state->original;
    state->armed = false;
    if (pam_set_item(state->pamh, PAM_CONV, &original) != PAM_SUCCESS) {
        return PAM_CONV_ERR;
    }

    if (!whosudod_pam_is_account_password_conversation(
            message_count,
            messages)) {
        return whosudod_pam_call_original(
            &original,
            message_count,
            messages,
            responses
        );
    }

    return whosudod_pam_handle_password_prompt(
        state->pamh,
        &original,
        message_count,
        messages,
        responses
    );
}

static void
whosudod_pam_state_cleanup(
    pam_handle_t *pamh,
    void *data,
    int error_status
)
{
    struct whosudod_pam_state *state = data;

    (void)pamh;
    (void)error_status;
    if (state == NULL) {
        return;
    }
    whosudod_pam_secure_zero(state, sizeof(*state));
    free(state);
}

static int
whosudod_pam_restore(
    pam_handle_t *pamh,
    struct whosudod_pam_state *state
)
{
    const void *current_item = NULL;
    const struct pam_conv *current;

    if (state == NULL) {
        return PAM_IGNORE;
    }
    state->armed = false;
    if (pam_get_item(
            pamh,
            PAM_CONV,
            &current_item) != PAM_SUCCESS ||
        current_item == NULL) {
        return PAM_IGNORE;
    }
    current = current_item;
    if (current->conv == whosudod_pam_conversation &&
        current->appdata_ptr == state) {
        (void)pam_set_item(pamh, PAM_CONV, &state->original);
    }
    return PAM_IGNORE;
}

static int
whosudod_pam_offer(
    pam_handle_t *pamh,
    struct whosudod_pam_state *state
)
{
    const void *current_item = NULL;
    const struct pam_conv *current;
    bool new_state = false;

    if (!whosudod_pam_invocation_is_allowed(pamh) ||
        !whosudod_pam_terminal_is_eligible(pamh) ||
        pam_get_item(
            pamh,
            PAM_CONV,
            &current_item) != PAM_SUCCESS ||
        current_item == NULL) {
        return PAM_IGNORE;
    }
    current = current_item;

    if (state != NULL && current->conv == whosudod_pam_conversation &&
        current->appdata_ptr == state && state->armed) {
        return PAM_IGNORE;
    }
    if (!whosudod_pam_callback_is_stock_sudo(current)) {
        return PAM_IGNORE;
    }
    if (state == NULL) {
        state = calloc(1U, sizeof(*state));
        if (state == NULL) {
            return PAM_IGNORE;
        }
        state->pamh = pamh;
        new_state = true;
    }

    state->original = *current;
    state->replacement.conv = whosudod_pam_conversation;
    state->replacement.appdata_ptr = state;
    state->armed = false;

    if (new_state &&
        pam_set_data(
            pamh,
            WHOSUDOD_PAM_STATE_KEY,
            state,
            whosudod_pam_state_cleanup) != PAM_SUCCESS) {
        whosudod_pam_secure_zero(state, sizeof(*state));
        free(state);
        return PAM_IGNORE;
    }
    if (pam_set_item(
            pamh,
            PAM_CONV,
            &state->replacement) != PAM_SUCCESS) {
        return PAM_IGNORE;
    }
    state->armed = true;
    return PAM_IGNORE;
}

PAM_EXTERN int
pam_sm_authenticate(
    pam_handle_t *pamh,
    int flags,
    int argument_count,
    const char **arguments
)
{
    enum whosudod_pam_mode mode;
    const void *state_data = NULL;
    struct whosudod_pam_state *state = NULL;

    (void)flags;
    if (pamh == NULL) {
        return PAM_IGNORE;
    }

    mode = whosudod_pam_parse_mode(argument_count, arguments);
    if (mode == WHOSUDOD_PAM_MODE_INVALID) {
        return PAM_IGNORE;
    }
    if (pam_get_data(
            pamh,
            WHOSUDOD_PAM_STATE_KEY,
            &state_data) == PAM_SUCCESS) {
        state = (struct whosudod_pam_state *)state_data;
    }

    if (mode == WHOSUDOD_PAM_MODE_RESTORE) {
        return whosudod_pam_restore(pamh, state);
    }
    return whosudod_pam_offer(pamh, state);
}

PAM_EXTERN int
pam_sm_setcred(
    pam_handle_t *pamh,
    int flags,
    int argument_count,
    const char **arguments
)
{
    (void)pamh;
    (void)flags;
    (void)argument_count;
    (void)arguments;
    return PAM_IGNORE;
}

PAM_MODULE_ENTRY("pam_whosudod")
