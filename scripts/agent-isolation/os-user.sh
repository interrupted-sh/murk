#!/bin/sh
# SPDX-FileCopyrightText: murk contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

# The separate-OS-user recipe on Linux. Run it as root. It creates an agent
# user (if it does not exist yet), gives that user its own clone of the
# repository and a copy of one grant key file, and nothing else from murk. Then
# it runs check.sh as that user in the clone.
#
# Usage: sudo sh os-user.sh GRANT_KEY_FILE REPO_DIR OPERATOR_USER IN_SCOPE_KEY OUT_OF_SCOPE_KEY
# AGENT_USER sets the agent's user name (default murk-agent).
#
# The agent gets a clone because murk writes .murk with mode 0600, so another
# user cannot read the operator's working copy. murk creates ~/.config/murk
# with mode 0700, so the agent cannot read the operator's keys either.
set -eu

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
grant=${1:?usage: os-user.sh GRANT_KEY_FILE REPO_DIR OPERATOR_USER IN OUT}
repo=${2:?usage: os-user.sh GRANT_KEY_FILE REPO_DIR OPERATOR_USER IN OUT}
operator=${3:?usage: os-user.sh GRANT_KEY_FILE REPO_DIR OPERATOR_USER IN OUT}
in_scope=${4:?usage: os-user.sh GRANT_KEY_FILE REPO_DIR OPERATOR_USER IN OUT}
out_of_scope=${5:?usage: os-user.sh GRANT_KEY_FILE REPO_DIR OPERATOR_USER IN OUT}
agent=${AGENT_USER:-murk-agent}
here=$(cd "$(dirname "$0")" && pwd)

# 1. Create the agent user.
id "$agent" >/dev/null 2>&1 || useradd --create-home --shell /bin/sh "$agent"
agent_home=$(getent passwd "$agent" | cut -d: -f6)
operator_home=$(getent passwd "$operator" | cut -d: -f6)

# 2. Give it the grant key file, owned by the agent, mode 0600.
install -d -m 0700 -o "$agent" -g "$agent" "$agent_home/.config/murk-grant"
install -m 0600 -o "$agent" -g "$agent" "$grant" "$agent_home/.config/murk-grant/key"

# 3. Give it its own clone of the repository. git refuses a repository owned
# by another user until that user lists it in safe.directory.
runuser -u "$agent" -- env HOME="$agent_home" \
    git config --global --add safe.directory "$repo/.git"
runuser -u "$agent" -- env HOME="$agent_home" git clone -q "$repo" "$agent_home/repo"

# 4. Run the check as the agent user, in the clone, with a clean environment.
cd "$agent_home/repo"
exec runuser -u "$agent" -- env -i PATH="$PATH" HOME="$agent_home" \
    GRANT_KEY_FILE="$agent_home/.config/murk-grant/key" \
    OPERATOR_KEYS="$operator_home/.config/murk/keys" \
    sh "$here/check.sh" "$in_scope" "$out_of_scope"
