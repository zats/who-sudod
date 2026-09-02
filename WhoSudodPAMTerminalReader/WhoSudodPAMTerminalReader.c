#include "WhoSudodPAMProtocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <security/pam_constants.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define WHOSUDOD_TERMINAL_CONTROL_FD 3
#define WHOSUDOD_TERMINAL_INPUT_BUFFER_SIZE 1024U
#ifndef WHOSUDOD_TERMINAL_INPUT_TIMEOUT_SECONDS
#define WHOSUDOD_TERMINAL_INPUT_TIMEOUT_SECONDS 300
#endif

#define WHOSUDOD_SIGNAL_HUP  (1U << 0)
#define WHOSUDOD_SIGNAL_INT  (1U << 1)
#define WHOSUDOD_SIGNAL_QUIT (1U << 2)
#define WHOSUDOD_SIGNAL_TERM (1U << 3)
#define WHOSUDOD_SIGNAL_TSTP (1U << 4)
#define WHOSUDOD_SIGNAL_TTIN (1U << 5)
#define WHOSUDOD_SIGNAL_TTOU (1U << 6)
#define WHOSUDOD_TERMINATING_SIGNALS \
    (WHOSUDOD_SIGNAL_HUP | WHOSUDOD_SIGNAL_INT | \
        WHOSUDOD_SIGNAL_QUIT | WHOSUDOD_SIGNAL_TERM)

struct frame_header {
    uint32_t magic_be;
    uint16_t version_be;
    uint16_t type_be;
    uint32_t payload_length_be;
    uint8_t request_id[WHOSUDOD_PAM_REQUEST_ID_SIZE];
} __attribute__((packed));

struct frame_reader {
    uint8_t bytes[WHOSUDOD_PAM_FRAME_HEADER_SIZE +
        WHOSUDOD_PAM_MAX_FRAME_PAYLOAD];
    size_t used;
    size_t expected;
};

enum io_result {
    IO_RESULT_ERROR = -1,
    IO_RESULT_PENDING = 0,
    IO_RESULT_COMPLETE = 1,
    IO_RESULT_SIGNAL = 2,
};

static int signal_pipe_read_descriptor = -1;
static int signal_pipe_write_descriptor = -1;
static volatile sig_atomic_t pending_signal_bits;

_Static_assert(sizeof(struct frame_header) == WHOSUDOD_PAM_FRAME_HEADER_SIZE,
    "Unexpected terminal-reader frame size");
_Static_assert(WHOSUDOD_PAM_MAX_PASSWORD_SIZE < PAM_MAX_RESP_SIZE,
    "The terminal password must fit in a PAM response");

static void
secure_zero(void *pointer, size_t length)
{
    volatile uint8_t *cursor = pointer;

    while (cursor != NULL && length-- > 0) {
        *cursor++ = 0;
    }
}

static sig_atomic_t
signal_bit(int number)
{
    switch (number) {
    case SIGHUP:
        return WHOSUDOD_SIGNAL_HUP;
    case SIGINT:
        return WHOSUDOD_SIGNAL_INT;
    case SIGQUIT:
        return WHOSUDOD_SIGNAL_QUIT;
    case SIGTERM:
        return WHOSUDOD_SIGNAL_TERM;
    case SIGTSTP:
        return WHOSUDOD_SIGNAL_TSTP;
    case SIGTTIN:
        return WHOSUDOD_SIGNAL_TTIN;
    case SIGTTOU:
        return WHOSUDOD_SIGNAL_TTOU;
    default:
        return 0;
    }
}

static void
managed_signal_set(sigset_t *set)
{
    sigemptyset(set);
    sigaddset(set, SIGHUP);
    sigaddset(set, SIGINT);
    sigaddset(set, SIGQUIT);
    sigaddset(set, SIGTERM);
    sigaddset(set, SIGTSTP);
    sigaddset(set, SIGTTIN);
    sigaddset(set, SIGTTOU);
}

static void
record_signal(int number)
{
    uint8_t marker = 1;
    int saved_errno = errno;

    pending_signal_bits |= signal_bit(number);
    if (signal_pipe_write_descriptor >= 0) {
        (void)write(signal_pipe_write_descriptor, &marker, sizeof(marker));
    }
    errno = saved_errno;
}

static bool
set_descriptor_flags(int descriptor, bool nonblocking)
{
    int descriptor_flags;
    int status_flags;

    do {
        descriptor_flags = fcntl(descriptor, F_GETFD);
    } while (descriptor_flags < 0 && errno == EINTR);
    if (descriptor_flags < 0) {
        return false;
    }
    while (fcntl(descriptor, F_SETFD, descriptor_flags | FD_CLOEXEC) != 0) {
        if (errno != EINTR) {
            return false;
        }
    }

    if (!nonblocking) {
        return true;
    }
    do {
        status_flags = fcntl(descriptor, F_GETFL);
    } while (status_flags < 0 && errno == EINTR);
    if (status_flags < 0) {
        return false;
    }
    while (fcntl(descriptor, F_SETFL, status_flags | O_NONBLOCK) != 0) {
        if (errno != EINTR) {
            return false;
        }
    }
    return true;
}

static bool
install_signal_handling(void)
{
    struct sigaction action;
    struct sigaction ignored_action;
    sigset_t empty_mask;
    sigset_t managed_mask;
    int descriptors[2] = { -1, -1 };
    const int signals[] = {
        SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGTSTP, SIGTTIN, SIGTTOU,
    };
    size_t index;

    managed_signal_set(&managed_mask);
    if (sigprocmask(SIG_BLOCK, &managed_mask, NULL) != 0 ||
        pipe(descriptors) != 0 ||
        !set_descriptor_flags(descriptors[0], true) ||
        !set_descriptor_flags(descriptors[1], true)) {
        goto failed;
    }

    signal_pipe_read_descriptor = descriptors[0];
    signal_pipe_write_descriptor = descriptors[1];
    pending_signal_bits = 0;

    memset(&ignored_action, 0, sizeof(ignored_action));
    ignored_action.sa_handler = SIG_IGN;
    sigemptyset(&ignored_action.sa_mask);
    if (sigaction(SIGPIPE, &ignored_action, NULL) != 0) {
        goto failed;
    }

    memset(&action, 0, sizeof(action));
    action.sa_handler = record_signal;
    managed_signal_set(&action.sa_mask);
    for (index = 0; index < sizeof(signals) / sizeof(signals[0]); index++) {
        if (sigaction(signals[index], &action, NULL) != 0) {
            goto failed;
        }
    }

    /* An exec inherits its caller's mask. This helper owns its signal policy. */
    sigemptyset(&empty_mask);
    if (sigprocmask(SIG_SETMASK, &empty_mask, NULL) != 0) {
        goto failed;
    }
    return true;

failed:
    signal_pipe_read_descriptor = -1;
    signal_pipe_write_descriptor = -1;
    if (descriptors[0] >= 0) {
        close(descriptors[0]);
    }
    if (descriptors[1] >= 0) {
        close(descriptors[1]);
    }
    return false;
}

static void
close_signal_pipe(void)
{
    sigset_t managed_mask;
    int read_descriptor;
    int write_descriptor;

    managed_signal_set(&managed_mask);
    (void)sigprocmask(SIG_BLOCK, &managed_mask, NULL);
    read_descriptor = signal_pipe_read_descriptor;
    write_descriptor = signal_pipe_write_descriptor;
    signal_pipe_read_descriptor = -1;
    signal_pipe_write_descriptor = -1;
    if (read_descriptor >= 0) {
        close(read_descriptor);
    }
    if (write_descriptor >= 0) {
        close(write_descriptor);
    }
}

static sig_atomic_t
take_pending_signals(void)
{
    sigset_t managed_mask;
    sig_atomic_t result;
    uint8_t bytes[64];

    managed_signal_set(&managed_mask);
    if (sigprocmask(SIG_BLOCK, &managed_mask, NULL) != 0) {
        return WHOSUDOD_SIGNAL_TERM;
    }
    result = pending_signal_bits;
    pending_signal_bits = 0;
    if (signal_pipe_read_descriptor >= 0) {
        for (;;) {
            ssize_t count = read(signal_pipe_read_descriptor, bytes,
                sizeof(bytes));
            if (count > 0) {
                continue;
            }
            if (count < 0 && errno == EINTR) {
                continue;
            }
            break;
        }
    }
    (void)sigprocmask(SIG_UNBLOCK, &managed_mask, NULL);
    return result;
}

static int
stop_signal_from_bits(sig_atomic_t bits)
{
    if ((bits & WHOSUDOD_SIGNAL_TSTP) != 0) {
        return SIGTSTP;
    }
    if ((bits & WHOSUDOD_SIGNAL_TTIN) != 0) {
        return SIGTTIN;
    }
    if ((bits & WHOSUDOD_SIGNAL_TTOU) != 0) {
        return SIGTTOU;
    }
    return 0;
}

static int
termination_signal_from_bits(sig_atomic_t bits)
{
    if ((bits & WHOSUDOD_SIGNAL_HUP) != 0) {
        return SIGHUP;
    }
    if ((bits & WHOSUDOD_SIGNAL_INT) != 0) {
        return SIGINT;
    }
    if ((bits & WHOSUDOD_SIGNAL_QUIT) != 0) {
        return SIGQUIT;
    }
    if ((bits & WHOSUDOD_SIGNAL_TERM) != 0) {
        return SIGTERM;
    }
    return 0;
}

static bool
suspend_process(void)
{
    /* SIGSTOP cannot be blocked or discarded for an orphaned process group. */
    return kill(getpid(), SIGSTOP) == 0;
}

static enum io_result
wait_for_write(int descriptor)
{
    for (;;) {
        struct pollfd items[2] = {
            {
                .fd = descriptor,
                .events = POLLOUT,
            },
            {
                .fd = signal_pipe_read_descriptor,
                .events = POLLIN,
            },
        };
        int poll_result;

        if (pending_signal_bits != 0) {
            return IO_RESULT_SIGNAL;
        }
        poll_result = poll(items, 2, -1);
        if (poll_result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return IO_RESULT_ERROR;
        }
        if (pending_signal_bits != 0 ||
            (items[1].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0) {
            return IO_RESULT_SIGNAL;
        }
        if ((items[0].revents & POLLOUT) != 0) {
            return IO_RESULT_COMPLETE;
        }
        if ((items[0].revents & (POLLHUP | POLLERR | POLLNVAL)) != 0) {
            return IO_RESULT_ERROR;
        }
    }
}

static enum io_result
write_all(int descriptor, const void *bytes, size_t length, bool *wrote_any)
{
    const uint8_t *cursor = bytes;

    while (length > 0) {
        ssize_t count;

        if (pending_signal_bits != 0) {
            return IO_RESULT_SIGNAL;
        }
        count = write(descriptor, cursor, length);
        if (count > 0) {
            if (wrote_any != NULL) {
                *wrote_any = true;
            }
            cursor += (size_t)count;
            length -= (size_t)count;
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            enum io_result wait_result = wait_for_write(descriptor);
            if (wait_result == IO_RESULT_COMPLETE) {
                continue;
            }
            return wait_result;
        }
        return IO_RESULT_ERROR;
    }
    return IO_RESULT_COMPLETE;
}

static enum io_result
send_frame(int descriptor, uint16_t type,
    const uint8_t request_id[WHOSUDOD_PAM_REQUEST_ID_SIZE],
    const uint8_t *payload, uint32_t payload_length, bool *wrote_any)
{
    struct frame_header header;
    enum io_result result;

    if (payload_length > WHOSUDOD_PAM_MAX_FRAME_PAYLOAD ||
        (payload_length > 0 && payload == NULL)) {
        return IO_RESULT_ERROR;
    }
    header.magic_be = htonl(WHOSUDOD_PAM_PROTOCOL_MAGIC);
    header.version_be = htons(WHOSUDOD_PAM_PROTOCOL_VERSION);
    header.type_be = htons(type);
    header.payload_length_be = htonl(payload_length);
    memcpy(header.request_id, request_id, sizeof(header.request_id));
    result = write_all(descriptor, &header, sizeof(header), wrote_any);
    if (result == IO_RESULT_COMPLETE && payload_length > 0) {
        result = write_all(descriptor, payload, payload_length, wrote_any);
    }
    if (result != IO_RESULT_COMPLETE) {
        secure_zero(&header, sizeof(header));
        return result;
    }
    secure_zero(&header, sizeof(header));
    return IO_RESULT_COMPLETE;
}

static enum io_result
read_frame_progress(int descriptor, struct frame_reader *reader,
    size_t maximum_payload)
{
    for (;;) {
        size_t target;
        ssize_t count;

        if (reader->expected == 0 &&
            reader->used == sizeof(struct frame_header)) {
            struct frame_header header;
            uint32_t payload_length;

            memcpy(&header, reader->bytes, sizeof(header));
            payload_length = ntohl(header.payload_length_be);
            if (ntohl(header.magic_be) != WHOSUDOD_PAM_PROTOCOL_MAGIC ||
                ntohs(header.version_be) != WHOSUDOD_PAM_PROTOCOL_VERSION ||
                payload_length > maximum_payload ||
                payload_length > WHOSUDOD_PAM_MAX_FRAME_PAYLOAD) {
                secure_zero(&header, sizeof(header));
                return IO_RESULT_ERROR;
            }
            reader->expected = sizeof(header) + payload_length;
            secure_zero(&header, sizeof(header));
        }
        if (reader->expected != 0 && reader->used == reader->expected) {
            return IO_RESULT_COMPLETE;
        }

        target = reader->expected != 0 ? reader->expected :
            sizeof(struct frame_header);
        count = read(descriptor, reader->bytes + reader->used,
            target - reader->used);
        if (count > 0) {
            reader->used += (size_t)count;
            continue;
        }
        if (count == 0) {
            return IO_RESULT_ERROR;
        }
        if (errno == EINTR) {
            if (pending_signal_bits != 0) {
                return IO_RESULT_SIGNAL;
            }
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return IO_RESULT_PENDING;
        }
        return IO_RESULT_ERROR;
    }
}

static void
copy_frame_header(const struct frame_reader *reader,
    struct frame_header *header)
{
    memcpy(header, reader->bytes, sizeof(*header));
}

static bool
retry_tcgetattr(int terminal, struct termios *attributes)
{
    for (;;) {
        if (tcgetattr(terminal, attributes) == 0) {
            return true;
        }
        if (errno != EINTR || pending_signal_bits != 0) {
            return false;
        }
    }
}

static bool
retry_tcsetattr(int terminal, int action, const struct termios *attributes)
{
    for (;;) {
        if (tcsetattr(terminal, action, attributes) == 0) {
            return true;
        }
        if (errno != EINTR) {
            return false;
        }
    }
}

static bool
restore_terminal(int terminal, const struct termios *original,
    bool flush_input, bool add_newline)
{
    sigset_t managed_mask;
    bool result = true;

    managed_signal_set(&managed_mask);
    if (sigprocmask(SIG_BLOCK, &managed_mask, NULL) != 0) {
        result = false;
    }
    if (flush_input) {
        while (tcflush(terminal, TCIFLUSH) != 0) {
            if (errno != EINTR) {
                result = false;
                break;
            }
        }
    }
    if (!retry_tcsetattr(terminal, TCSANOW, original)) {
        result = false;
    }
    if (add_newline) {
        for (;;) {
            ssize_t count = write(terminal, "\n", 1);
            if (count == 1) {
                break;
            }
            if (count < 0 && errno == EINTR) {
                continue;
            }
            result = false;
            break;
        }
    }
    if (sigprocmask(SIG_UNBLOCK, &managed_mask, NULL) != 0) {
        result = false;
    }
    return result;
}

static enum io_result
activate_terminal(int terminal, const struct termios *original,
    const uint8_t *prompt, size_t prompt_length, bool *terminal_hidden,
    bool *prompt_shown)
{
    struct termios hidden = *original;
    sigset_t managed_mask;
    bool wrote_any = false;
    enum io_result result;

    /* Do not change canonical mode, signal processing, or any other tty bit. */
    hidden.c_lflag &= ~(ECHO | ECHONL);
    managed_signal_set(&managed_mask);
    if (sigprocmask(SIG_BLOCK, &managed_mask, NULL) != 0) {
        secure_zero(&hidden, sizeof(hidden));
        return IO_RESULT_ERROR;
    }
    /* Flush bytes typed before the no-echo state became active. */
    if (!retry_tcsetattr(terminal, TCSAFLUSH, &hidden)) {
        (void)sigprocmask(SIG_UNBLOCK, &managed_mask, NULL);
        secure_zero(&hidden, sizeof(hidden));
        return IO_RESULT_ERROR;
    }
    *terminal_hidden = true;
    if (sigprocmask(SIG_UNBLOCK, &managed_mask, NULL) != 0) {
        secure_zero(&hidden, sizeof(hidden));
        return IO_RESULT_ERROR;
    }
    secure_zero(&hidden, sizeof(hidden));

    result = write_all(terminal, prompt, prompt_length, &wrote_any);
    if (wrote_any) {
        *prompt_shown = true;
    }
    return result;
}

static enum io_result
read_terminal_line(int terminal, bool canonical_input, uint8_t *password,
    size_t *password_length, bool *password_too_long,
    bool *invalid_password, uint8_t *input, size_t input_capacity)
{
    bool read_canonical_record = false;

    for (;;) {
        size_t capacity = canonical_input ? input_capacity : 1U;
        ssize_t count = read(terminal, input, capacity);

        if (count > 0) {
            bool line_finished = false;
            size_t index;

            read_canonical_record = canonical_input;
            for (index = 0; index < (size_t)count; index++) {
                uint8_t byte = input[index];

                if (byte == '\n' || byte == '\r') {
                    line_finished = true;
                    break;
                }
                if (byte == '\0') {
                    *invalid_password = true;
                } else if (*password_length <
                    WHOSUDOD_PAM_MAX_PASSWORD_SIZE) {
                    password[(*password_length)++] = byte;
                } else {
                    *password_too_long = true;
                }
            }
            secure_zero(input, input_capacity);
            if (line_finished) {
                return IO_RESULT_COMPLETE;
            }
            if (canonical_input && (size_t)count < capacity) {
                /* Canonical VEOF ended the record without a newline. */
                return IO_RESULT_COMPLETE;
            }
            continue;
        }
        secure_zero(input, input_capacity);
        if (count == 0) {
            return IO_RESULT_COMPLETE;
        }
        if (errno == EINTR) {
            if (pending_signal_bits != 0) {
                return IO_RESULT_SIGNAL;
            }
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /* A canonical read starts only after newline or VEOF. If a full
             * chunk consumed that record, EAGAIN is its unambiguous end. */
            return read_canonical_record ? IO_RESULT_COMPLETE :
                IO_RESULT_PENDING;
        }
        return IO_RESULT_ERROR;
    }
}

static int
open_terminal(void)
{
    int descriptor;

    do {
        descriptor = open("/dev/tty",
            O_RDWR | O_CLOEXEC | O_NOCTTY | O_NONBLOCK);
    } while (descriptor < 0 && errno == EINTR && pending_signal_bits == 0);
    return descriptor;
}

static bool
set_input_deadline(struct timespec *deadline)
{
    if (clock_gettime(CLOCK_MONOTONIC, deadline) != 0) {
        return false;
    }
    deadline->tv_sec += WHOSUDOD_TERMINAL_INPUT_TIMEOUT_SECONDS;
    return true;
}

static int
input_timeout_milliseconds(const struct timespec *deadline)
{
    struct timespec now;
    time_t seconds;
    long nanoseconds;
    int64_t milliseconds;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    seconds = deadline->tv_sec - now.tv_sec;
    nanoseconds = deadline->tv_nsec - now.tv_nsec;
    if (nanoseconds < 0) {
        seconds--;
        nanoseconds += 1000000000L;
    }
    if (seconds < 0 || (seconds == 0 && nanoseconds == 0)) {
        return 0;
    }
    milliseconds = (int64_t)seconds * 1000 +
        (nanoseconds + 999999L) / 1000000L;
    return milliseconds > INT_MAX ? INT_MAX : (int)milliseconds;
}

static _Noreturn void
terminate_with_signal(int number)
{
    struct sigaction action;
    sigset_t signal_mask;

    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    sigemptyset(&action.sa_mask);
    (void)sigaction(number, &action, NULL);
    sigemptyset(&signal_mask);
    sigaddset(&signal_mask, number);
    (void)sigprocmask(SIG_UNBLOCK, &signal_mask, NULL);
    (void)kill(getpid(), number);
    _exit(128 + number);
}

int
main(void)
{
    struct frame_reader start_reader;
    struct frame_reader control_reader;
    struct frame_header start_header;
    struct frame_header control_header;
    struct termios original_terminal;
    struct timespec input_deadline;
    uint8_t prompt[WHOSUDOD_PAM_MAX_PROMPT_SIZE];
    uint8_t request_id[WHOSUDOD_PAM_REQUEST_ID_SIZE];
    uint8_t password[PAM_MAX_RESP_SIZE];
    uint8_t input[WHOSUDOD_TERMINAL_INPUT_BUFFER_SIZE];
    size_t password_length = 0;
    size_t prompt_length = 0;
    bool password_too_long = false;
    bool invalid_password = false;
    bool canonical_input = false;
    bool terminal_hidden = false;
    bool prompt_shown = false;
    bool request_known = false;
    bool control_stream_usable = true;
    bool ready_sent = false;
    bool send_failure = false;
    bool flush_input = true;
    bool cancelled = false;
    int terminal = -1;
    int terminating_signal = 0;
    int exit_status = 1;

    memset(&start_reader, 0, sizeof(start_reader));
    memset(&control_reader, 0, sizeof(control_reader));
    memset(&start_header, 0, sizeof(start_header));
    memset(&control_header, 0, sizeof(control_header));
    memset(&original_terminal, 0, sizeof(original_terminal));
    memset(&input_deadline, 0, sizeof(input_deadline));
    memset(prompt, 0, sizeof(prompt));
    memset(request_id, 0, sizeof(request_id));
    memset(password, 0, sizeof(password));
    memset(input, 0, sizeof(input));

    if (!set_descriptor_flags(WHOSUDOD_TERMINAL_CONTROL_FD, true) ||
        !install_signal_handling()) {
        goto finished;
    }

    for (;;) {
        sig_atomic_t signals = take_pending_signals();
        int stop_signal;

        if ((signals & WHOSUDOD_TERMINATING_SIGNALS) != 0) {
            terminating_signal = termination_signal_from_bits(signals);
            goto finished;
        }
        stop_signal = stop_signal_from_bits(signals);
        if (stop_signal != 0) {
            if (!suspend_process()) {
                goto finished;
            }
            continue;
        }

        {
            struct pollfd items[2] = {
                {
                    .fd = WHOSUDOD_TERMINAL_CONTROL_FD,
                    .events = POLLIN | POLLHUP,
                },
                {
                    .fd = signal_pipe_read_descriptor,
                    .events = POLLIN,
                },
            };
            int poll_result = poll(items, 2, -1);
            enum io_result read_result;

            if (poll_result < 0) {
                if (errno == EINTR) {
                    continue;
                }
                goto finished;
            }
            if ((items[1].revents &
                    (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0) {
                continue;
            }
            if ((items[0].revents &
                    (POLLIN | POLLHUP | POLLERR | POLLNVAL)) == 0) {
                continue;
            }
            read_result = read_frame_progress(
                WHOSUDOD_TERMINAL_CONTROL_FD, &start_reader,
                WHOSUDOD_PAM_MAX_PROMPT_SIZE);
            if (read_result == IO_RESULT_SIGNAL ||
                read_result == IO_RESULT_PENDING) {
                continue;
            }
            if (read_result != IO_RESULT_COMPLETE) {
                goto finished;
            }
        }
        break;
    }

    copy_frame_header(&start_reader, &start_header);
    if (ntohs(start_header.type_be) !=
            WHOSUDOD_PAM_MESSAGE_TERMINAL_START) {
        goto finished;
    }
    memcpy(request_id, start_header.request_id, sizeof(request_id));
    request_known = true;
    send_failure = true;
    prompt_length = ntohl(start_header.payload_length_be);
    if (prompt_length == 0 ||
        memchr(start_reader.bytes + sizeof(start_header), '\0',
            prompt_length) != NULL) {
        goto finished;
    }
    memcpy(prompt, start_reader.bytes + sizeof(start_header), prompt_length);
    secure_zero(&start_reader, sizeof(start_reader));

    terminal = open_terminal();
    if (terminal < 0 || !isatty(terminal) ||
        !retry_tcgetattr(terminal, &original_terminal)) {
        goto finished;
    }
    canonical_input = (original_terminal.c_lflag & ICANON) != 0;
    if (!set_input_deadline(&input_deadline)) {
        goto finished;
    }

activate_prompt:
    if (ready_sent && input_timeout_milliseconds(&input_deadline) == 0) {
        goto finished;
    }
    {
        enum io_result activate_result = activate_terminal(terminal,
            &original_terminal, prompt, prompt_length, &terminal_hidden,
            &prompt_shown);
        if (activate_result != IO_RESULT_COMPLETE) {
            sig_atomic_t signals = take_pending_signals();
            int stop_signal = stop_signal_from_bits(signals);

            if ((signals & WHOSUDOD_TERMINATING_SIGNALS) != 0) {
                terminating_signal = termination_signal_from_bits(signals);
                goto finished;
            }
            if (activate_result == IO_RESULT_ERROR || stop_signal == 0) {
                goto finished;
            }
            (void)restore_terminal(terminal, &original_terminal, true,
                prompt_shown);
            terminal_hidden = false;
            prompt_shown = false;
            secure_zero(password, sizeof(password));
            password_length = 0;
            password_too_long = false;
            invalid_password = false;
            if (!suspend_process()) {
                goto finished;
            }
            goto activate_prompt;
        }
    }

    {
        sig_atomic_t signals = take_pending_signals();
        int stop_signal = stop_signal_from_bits(signals);

        if ((signals & WHOSUDOD_TERMINATING_SIGNALS) != 0) {
            terminating_signal = termination_signal_from_bits(signals);
            goto finished;
        }
        if (stop_signal != 0) {
            if (!restore_terminal(terminal, &original_terminal, true,
                    prompt_shown)) {
                goto finished;
            }
            terminal_hidden = false;
            prompt_shown = false;
            secure_zero(password, sizeof(password));
            password_length = 0;
            password_too_long = false;
            invalid_password = false;
            if (!suspend_process()) {
                goto finished;
            }
            goto activate_prompt;
        }
    }

    if (!ready_sent) {
        bool wrote_any = false;
        enum io_result send_result = send_frame(
            WHOSUDOD_TERMINAL_CONTROL_FD,
            WHOSUDOD_PAM_MESSAGE_TERMINAL_READY, request_id, NULL, 0,
            &wrote_any);

        if (send_result != IO_RESULT_COMPLETE) {
            if (wrote_any || send_result != IO_RESULT_SIGNAL) {
                control_stream_usable = false;
            }
            if (send_result == IO_RESULT_SIGNAL) {
                sig_atomic_t signals = take_pending_signals();
                int stop_signal = stop_signal_from_bits(signals);

                if ((signals & WHOSUDOD_TERMINATING_SIGNALS) != 0) {
                    terminating_signal = termination_signal_from_bits(signals);
                } else if (!wrote_any && stop_signal != 0) {
                    if (!restore_terminal(terminal, &original_terminal, true,
                            prompt_shown)) {
                        goto finished;
                    }
                    terminal_hidden = false;
                    prompt_shown = false;
                    if (!suspend_process()) {
                        goto finished;
                    }
                    goto activate_prompt;
                }
            }
            goto finished;
        }
        ready_sent = true;
    }

    for (;;) {
        struct pollfd items[3];
        sig_atomic_t signals = take_pending_signals();
        int stop_signal;
        int poll_result;
        int timeout_milliseconds;

        if ((signals & WHOSUDOD_TERMINATING_SIGNALS) != 0) {
            terminating_signal = termination_signal_from_bits(signals);
            goto finished;
        }
        stop_signal = stop_signal_from_bits(signals);
        if (stop_signal != 0) {
            if (!restore_terminal(terminal, &original_terminal, true,
                    prompt_shown)) {
                goto finished;
            }
            terminal_hidden = false;
            prompt_shown = false;
            secure_zero(password, sizeof(password));
            password_length = 0;
            password_too_long = false;
            invalid_password = false;
            if (!suspend_process()) {
                goto finished;
            }
            goto activate_prompt;
        }

        items[0].fd = WHOSUDOD_TERMINAL_CONTROL_FD;
        items[0].events = POLLIN | POLLHUP;
        items[0].revents = 0;
        items[1].fd = control_reader.used == 0 ? terminal : -1;
        items[1].events = POLLIN | POLLHUP;
        items[1].revents = 0;
        items[2].fd = signal_pipe_read_descriptor;
        items[2].events = POLLIN;
        items[2].revents = 0;

        timeout_milliseconds = input_timeout_milliseconds(&input_deadline);
        if (timeout_milliseconds == 0) {
            goto finished;
        }
        poll_result = poll(items, 3, timeout_milliseconds);
        if (poll_result == 0) {
            goto finished;
        }
        if (poll_result < 0) {
            if (errno == EINTR) {
                continue;
            }
            goto finished;
        }
        if ((items[2].revents &
                (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0) {
            continue;
        }

        /* Once a control frame starts, finish it before accepting a line. */
        if ((items[0].revents &
                (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0) {
            enum io_result read_result = read_frame_progress(
                WHOSUDOD_TERMINAL_CONTROL_FD, &control_reader,
                WHOSUDOD_PAM_MAX_FRAME_PAYLOAD);

            if (read_result == IO_RESULT_SIGNAL ||
                read_result == IO_RESULT_PENDING) {
                continue;
            }
            if (read_result != IO_RESULT_COMPLETE) {
                goto finished;
            }
            copy_frame_header(&control_reader, &control_header);
            if (memcmp(control_header.request_id, request_id,
                    sizeof(request_id)) != 0 ||
                ntohs(control_header.type_be) !=
                    WHOSUDOD_PAM_MESSAGE_CANCEL ||
                ntohl(control_header.payload_length_be) != 0) {
                goto finished;
            }
            cancelled = true;
            send_failure = false;
            exit_status = 0;
            goto finished;
        }

        if ((items[1].revents &
                (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0) {
            enum io_result read_result = read_terminal_line(terminal,
                canonical_input, password, &password_length,
                &password_too_long, &invalid_password, input,
                sizeof(input));

            if (read_result == IO_RESULT_SIGNAL ||
                read_result == IO_RESULT_PENDING) {
                continue;
            }
            if (read_result != IO_RESULT_COMPLETE) {
                goto finished;
            }

            /* Give a cancellation that arrived with the line priority. */
            {
                struct pollfd control_item = {
                    .fd = WHOSUDOD_TERMINAL_CONTROL_FD,
                    .events = POLLIN | POLLHUP,
                };
                int control_poll;

                do {
                    control_poll = poll(&control_item, 1, 0);
                } while (control_poll < 0 && errno == EINTR &&
                    pending_signal_bits == 0);
                if (control_poll > 0 &&
                    (control_item.revents &
                        (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0) {
                    continue;
                }
                if (pending_signal_bits != 0) {
                    continue;
                }
            }

            flush_input = password_too_long || invalid_password;
            (void)restore_terminal(terminal, &original_terminal, flush_input,
                prompt_shown);
            terminal_hidden = false;
            prompt_shown = false;

            if (password_too_long || invalid_password) {
                goto finished;
            }
            send_failure = false;
            control_stream_usable = false;
            {
                bool wrote_any = false;
                enum io_result send_result = send_frame(
                    WHOSUDOD_TERMINAL_CONTROL_FD,
                    WHOSUDOD_PAM_MESSAGE_PASSWORD, request_id, password,
                    (uint32_t)password_length, &wrote_any);

                if (send_result == IO_RESULT_COMPLETE) {
                    exit_status = 0;
                }
            }
            goto finished;
        }
    }

finished:
    if (terminal_hidden) {
        (void)restore_terminal(terminal, &original_terminal,
            flush_input || cancelled || send_failure, prompt_shown);
        terminal_hidden = false;
        prompt_shown = false;
    }
    secure_zero(password, sizeof(password));
    secure_zero(input, sizeof(input));
    if (terminating_signal == 0 && pending_signal_bits != 0) {
        sig_atomic_t signals = take_pending_signals();
        terminating_signal = termination_signal_from_bits(signals);
    }
    if (send_failure && request_known && control_stream_usable) {
        if (send_frame(WHOSUDOD_TERMINAL_CONTROL_FD,
                WHOSUDOD_PAM_MESSAGE_TERMINAL_FAILURE, request_id, NULL, 0,
                NULL) == IO_RESULT_COMPLETE) {
            exit_status = 0;
        }
    }
    if (terminating_signal == 0 && pending_signal_bits != 0) {
        sig_atomic_t signals = take_pending_signals();
        terminating_signal = termination_signal_from_bits(signals);
    }
    if (terminal >= 0) {
        close(terminal);
    }
    close(WHOSUDOD_TERMINAL_CONTROL_FD);
    close_signal_pipe();
    secure_zero(&start_reader, sizeof(start_reader));
    secure_zero(&control_reader, sizeof(control_reader));
    secure_zero(&start_header, sizeof(start_header));
    secure_zero(&control_header, sizeof(control_header));
    secure_zero(&original_terminal, sizeof(original_terminal));
    secure_zero(&input_deadline, sizeof(input_deadline));
    secure_zero(prompt, sizeof(prompt));
    secure_zero(request_id, sizeof(request_id));
    if (terminating_signal != 0) {
        terminate_with_signal(terminating_signal);
    }
    return exit_status;
}
