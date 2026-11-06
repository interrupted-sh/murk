#!/bin/sh
# SPDX-FileCopyrightText: murk contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

# Test the agent isolation recipes end to end with a throwaway vault.
#
#   sh scripts/agent-isolation/run-checks.sh container      # docker run
#   sh scripts/agent-isolation/run-checks.sh devcontainer   # devcontainer CLI
#   sh scripts/agent-isolation/run-checks.sh os-user        # a second Linux user
#
# container and devcontainer need docker and a murk on PATH (or MURK=path) to
# create the vault on the host. os-user needs only docker: it runs the whole
# recipe (operator, vault, grant, agent user) inside one Linux container.
# Each mode runs check.sh as the agent and exits non-zero if a check fails.
#
# ISOLATION_WORK_ROOT sets where the scratch vault is created (default
# ${TMPDIR:-/tmp}). With Docker Desktop or colima on macOS, pick a directory
# the docker VM shares, such as one under $HOME.
set -eu

mode=${1:?usage: run-checks.sh container|devcontainer|os-user}
here=$(cd "$(dirname "$0")" && pwd)
murk=${MURK:-murk}
image="murk-agent-isolation"

work=$(mktemp -d "${ISOLATION_WORK_ROOT:-${TMPDIR:-/tmp}}/murk-isolation.XXXXXX")
trap 'rm -rf "$work"' EXIT

docker build -q -t "$image" "$here" >/dev/null

# A throwaway operator: its own HOME, a vault with two secrets, and a grant
# that can read only API_KEY.
make_vault() {
    mkdir -p "$work/operator-home" "$work/repo"
    (
        cd "$work/repo"
        export HOME="$work/operator-home"
        unset MURK_AGENT MURK_STRICT MURK_KEY MURK_KEY_FILE MURK_TRUSTED_SIGNERS
        git init -q
        echo operator | "$murk" init >/dev/null 2>&1
        echo in-scope-value | "$murk" add API_KEY >/dev/null 2>&1
        echo out-of-scope-value | "$murk" add OTHER >/dev/null 2>&1
        "$murk" agent grant --name agent --only API_KEY --ttl 1h \
            --out "$work/grant.key" >/dev/null 2>&1
    )
}

case "$mode" in
container)
    make_vault
    docker run --rm \
        --user "$(id -u):$(id -g)" -e HOME=/tmp \
        -v "$work/repo:/work:ro" \
        -v "$work/grant.key:/run/murk/key:ro" \
        -e GRANT_KEY_FILE=/run/murk/key \
        -e OPERATOR_KEYS="$work/operator-home/.config/murk/keys" \
        "$image" murk-isolation-check API_KEY OTHER
    ;;
devcontainer)
    make_vault
    if command -v devcontainer >/dev/null 2>&1; then
        dc=devcontainer
    else
        dc="npx --yes @devcontainers/cli"
    fi
    mkdir -p "$work/repo/.devcontainer"
    cp "$here/devcontainer.json" "$here/Dockerfile" "$here/check.sh" "$work/repo/.devcontainer/"
    export MURK_GRANT_KEY_FILE="$work/grant.key"
    id_label="murk-isolation=$(basename "$work")"
    $dc up --workspace-folder "$work/repo" --id-label "$id_label" >/dev/null
    status=0
    $dc exec --workspace-folder "$work/repo" --id-label "$id_label" \
        env GRANT_KEY_FILE=/run/murk/key \
        OPERATOR_KEYS="$work/operator-home/.config/murk/keys" \
        murk-isolation-check API_KEY OTHER || status=$?
    docker ps -aq --filter "label=$id_label" | xargs docker rm -f >/dev/null
    exit "$status"
    ;;
os-user)
    docker run --rm --user root -v "$here:/recipe:ro" "$image" sh -eu -c '
        useradd --create-home alice
        install -d -o alice -g alice /srv/repo
        cd /srv/repo
        runuser -u alice -- env -u MURK_KEY_FILE -u MURK_AGENT HOME=/home/alice sh -eu -c "
            echo operator | murk init >/dev/null 2>&1
            echo in-scope-value | murk add API_KEY >/dev/null 2>&1
            echo out-of-scope-value | murk add OTHER >/dev/null 2>&1
            murk agent grant --name agent --only API_KEY --ttl 1h --out /tmp/grant.key >/dev/null 2>&1
            git init -q && git add .murk
            git -c user.name=alice -c user.email=alice@example.com commit -qm vault
        "
        sh /recipe/os-user.sh /tmp/grant.key /srv/repo alice API_KEY OTHER
    '
    ;;
*)
    echo "unknown mode: $mode (container, devcontainer or os-user)" >&2
    exit 2
    ;;
esac
