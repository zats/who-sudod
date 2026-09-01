#!/bin/zsh

set -euo pipefail
umask 077

tool_directory="${0:A:h}"
repository_directory="${tool_directory:h}"
build_directory="${repository_directory}/.build"
app_executable="${build_directory}/Build/Products/Debug/Who Sudo'd.app/Contents/MacOS/Who Sudo'd"
waiter="${tool_directory}/wait-for-live-tree.swift"
expected_tree_writer="${tool_directory}/write-expected-process-tree.swift"
temporary_directory="$(mktemp -d /private/tmp/who-sudod-live-sudo.XXXXXX)"
/bin/chmod 700 "${temporary_directory}"
run_identifier="$(uuidgen)"
state_path="${temporary_directory}/state.json"
expected_path="${temporary_directory}/expected.json"
sudo_log="${temporary_directory}/sudo.log"
app_log="${temporary_directory}/app.log"
lock_path="/private/tmp/who-sudod-live-check.lock"
lock_acquired=false
sudo_state_touched=false
app_process_id=0
sudo_process_id=0

process_matches() {
    local process_id="$1"
    local expected_executable="$2"
    local executable
    executable="$(/bin/ps -ww -p "${process_id}" -o comm= 2>/dev/null || true)"
    [[ "${executable}" == "${expected_executable}" ]]
}

stop_process_tree() {
    local process_id="$1"
    if (( process_id <= 0 )) || ! kill -0 "${process_id}" 2>/dev/null; then
        return
    fi
    kill -STOP "${process_id}" 2>/dev/null || true
    local child_process_ids
    child_process_ids="$(
        /bin/ps -axo pid=,ppid= |
            /usr/bin/awk -v parent="${process_id}" '$2 == parent { print $1 }'
    )"
    local child_process_id
    for child_process_id in ${(f)child_process_ids}; do
        if [[ "$(/bin/ps -p "${child_process_id}" -o ppid= 2>/dev/null | /usr/bin/tr -d ' ')" == "${process_id}" ]]; then
            stop_process_tree "${child_process_id}"
        fi
    done
    kill "${process_id}" 2>/dev/null || true
    kill -CONT "${process_id}" 2>/dev/null || true
    local attempt
    for attempt in {1..20}; do
        if ! kill -0 "${process_id}" 2>/dev/null; then
            return
        fi
        /bin/sleep 0.1
    done
    kill -KILL "${process_id}" 2>/dev/null || true
}

stop_expected_process_tree() {
    local process_id="$1"
    local expected_executable="$2"
    if (( process_id <= 0 )); then
        return
    fi
    if ! process_matches "${process_id}" "${expected_executable}"; then
        wait "${process_id}" 2>/dev/null || true
        return
    fi
    stop_process_tree "${process_id}"
    wait "${process_id}" 2>/dev/null || true
}

running_who_sudod_process_ids() {
    local suffix="/Who Sudo'd.app/Contents/MacOS/Who Sudo'd"
    /bin/ps -ww -axo pid=,comm= |
        WHO_SUDOD_PROCESS_SUFFIX="${suffix}" /usr/bin/awk '
            {
                suffix = ENVIRON["WHO_SUDOD_PROCESS_SUFFIX"]
                pid = $1
                sub(/^[[:space:]]*[0-9]+[[:space:]]+/, "")
                if (length($0) >= length(suffix) && substr($0, length($0) - length(suffix) + 1) == suffix) {
                    print pid
                }
            }
        '
}

require_no_existing_app() {
    local existing_process_id="$(running_who_sudod_process_ids)"
    if [[ -n "${existing_process_id}" ]]; then
        print -u2 "Stop the existing Who Sudo'd process first: ${existing_process_id}"
        exit 69
    fi
}

cleanup() {
    local exit_code="$?"
    trap - EXIT INT TERM
    stop_expected_process_tree "${sudo_process_id}" "/usr/bin/sudo"
    stop_expected_process_tree "${app_process_id}" "${app_executable}"
    if [[ "${sudo_state_touched}" == true ]]; then
        /usr/bin/sudo -K >/dev/null 2>&1 || true
    fi
    if (( exit_code != 0 )) && {
        [[ -f "${state_path}" ]] ||
        [[ -f "${expected_path}" ]] ||
        [[ -f "${sudo_log}" ]] ||
        [[ -f "${app_log}" ]]
    }; then
        local result_directory="${build_directory}/live-results/${run_identifier}"
        /bin/mkdir -p "${result_directory}"
        /bin/chmod 700 "${result_directory}"
        /bin/cp -f "${state_path}" "${result_directory}/" 2>/dev/null || true
        /bin/cp -f "${expected_path}" "${result_directory}/" 2>/dev/null || true
        /bin/cp -f "${sudo_log}" "${result_directory}/" 2>/dev/null || true
        /bin/cp -f "${app_log}" "${result_directory}/" 2>/dev/null || true
        /usr/bin/find "${result_directory}" -type f -exec /bin/chmod 600 {} +
        print -u2 "Live check artifacts: ${result_directory}"
    fi
    if [[ "${temporary_directory}" == /private/tmp/who-sudod-live-sudo.* ]]; then
        /bin/rm -rf "${temporary_directory}"
    fi
    if [[ "${lock_acquired}" == true ]]; then
        /bin/unlink "${lock_path}" 2>/dev/null || true
    fi
    exit "${exit_code}"
}

interrupt() {
    exit 130
}

terminate() {
    exit 143
}

trap cleanup EXIT
trap interrupt INT
trap terminate TERM

cd "${repository_directory}"

if ! /usr/bin/shlock -p "$$" -f "${lock_path}"; then
    print -u2 "Another live-tree check is already running."
    exit 75
fi
lock_acquired=true

require_no_existing_app

/usr/bin/xcodebuild \
    -project WhoSudod.xcodeproj \
    -scheme WhoSudod \
    -configuration Debug \
    -derivedDataPath "${build_directory}" \
    -quiet \
    build

require_no_existing_app
WHO_SUDOD_TEST_RUN_ID="${run_identifier}" \
WHO_SUDOD_TEST_STATE_PATH="${state_path}" \
WHO_SUDOD_DISPLAY_MODE="fullTree" \
    "${app_executable}" >"${app_log}" 2>&1 &
app_process_id="$!"

"${waiter}" ready "${state_path}" "${run_identifier}" "${app_process_id}" 5
baseline_sequence="$(/usr/bin/plutil -extract promptSequence raw "${state_path}")"

sudo_state_touched=true
/usr/bin/sudo -K
/usr/bin/sudo -- ls -l >"${sudo_log}" 2>&1 &
sudo_process_id="$!"

for attempt in {1..20}; do
    if process_matches "${sudo_process_id}" "/usr/bin/sudo"; then
        break
    fi
    if ! kill -0 "${sudo_process_id}" 2>/dev/null; then
        print -u2 "The sudo requester exited early. Its private log will be saved with the failure artifacts."
        exit 70
    fi
    /bin/sleep 0.05
done
if ! process_matches "${sudo_process_id}" "/usr/bin/sudo"; then
    print -u2 "The sudo requester did not start with the expected executable."
    exit 70
fi

"${expected_tree_writer}" \
    "${sudo_process_id}" \
    securityAgent \
    sudo \
    authorizationLog \
    "${expected_path}" \
    --pending \
    ls \
    "ls -l"

"${waiter}" tree \
    "${state_path}" \
    "${run_identifier}" \
    "${baseline_sequence}" \
    "${expected_path}" \
    "${app_process_id}" \
    "${sudo_process_id}" \
    10 \
    --exact

prompt_sequence="$(/usr/bin/plutil -extract promptSequence raw "${state_path}")"
stop_expected_process_tree "${sudo_process_id}" "/usr/bin/sudo"
sudo_process_id=0
"${waiter}" hidden \
    "${state_path}" \
    "${run_identifier}" \
    "${prompt_sequence}" \
    "${app_process_id}" \
    5

/usr/bin/sudo -K
sudo_state_touched=false
print "PASS sudo live process tree"
