#!/bin/zsh

set -euo pipefail

tool_directory="${0:A:h}"
repository_directory="${tool_directory:h}"

cd "${repository_directory}"
SWIFT_DETERMINISTIC_HASHING=1 xcodegen generate --spec project.yml
