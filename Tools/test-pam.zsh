#!/bin/zsh

set -euo pipefail

tool_directory="${0:A:h}"
repository_directory="${tool_directory:h}"
temporary_directory="$(mktemp -d /private/tmp/who-sudod-pam-tests.XXXXXX)"
compiler="$(xcrun --find clang)"
sdk_path="$(xcrun --sdk macosx --show-sdk-path)"

cleanup() {
    if [[ "${temporary_directory}" == /private/tmp/who-sudod-pam-tests.* ]]; then
        /bin/rm -rf "${temporary_directory}"
    fi
}
trap cleanup EXIT

cd "${repository_directory}"

common_flags=(
    -arch arm64
    -std=c17
    -Wall
    -Wextra
    -Werror
    -isysroot "${sdk_path}"
    -I WhoSudodPAM
)

"${compiler}" "${common_flags[@]}" \
    WhoSudodPAMTests/WhoSudodPAMInvocationPolicyTests.c \
    WhoSudodPAM/WhoSudodPAMInvocationPolicy.c \
    -o "${temporary_directory}/invocation-policy-tests"
"${temporary_directory}/invocation-policy-tests"

"${compiler}" "${common_flags[@]}" \
    WhoSudodPAMTests/WhoSudodPAMPromptClassifierTests.c \
    WhoSudodPAM/WhoSudodPAMPromptClassifier.c \
    -o "${temporary_directory}/prompt-classifier-tests"
"${temporary_directory}/prompt-classifier-tests"

"${compiler}" "${common_flags[@]}" \
    WhoSudodPAMTests/WhoSudodPAMModuleSupportTests.c \
    WhoSudodPAM/WhoSudodPAMInvocationPolicy.c \
    WhoSudodPAM/WhoSudodPAMPromptClassifier.c \
    -framework CoreFoundation \
    -framework Security \
    -lpam \
    -o "${temporary_directory}/module-support-tests"
"${temporary_directory}/module-support-tests"
