#!/bin/sh
# SPDX-FileCopyrightText: murk contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

# Test the agent isolation recipes end to end with a throwaway vault.
#
#   sh scripts/agent-isolation/run-checks.sh container      # docker run
#   sh scripts/agent-isolation/run-checks.sh devcontainer   # devcontainer CLI
#   sh scripts/agent-isolation/run-checks.sh os-user        # a second Linux user
#   sh scripts/agent-isolation/run-checks.sh stop           # docker stop, murk as PID 1
#
# container, devcontainer and stop need docker and a murk on PATH (or
# MURK=/absolute/path) to create the vault on the host. os-user needs only
# docker: it runs the whole recipe (operator, vault, grant, agent user) inside
# one Linux container. Each recipe mode runs check.sh as the agent and exits
# non-zero if a check fails. stop checks that `docker stop` reaches an app
# that `murk agent exec` runs as the container's PID 1.
#
# IMAGE_MURK names a Linux murk binary to install in the image instead of the
# release the Dockerfile downloads, to test a local build. The devcontainer
# mode builds its own image and always uses the release.
#
# ISOLATION_WORK_ROOT sets where the scratch vault is created (default
# ${TMPDIR:-/tmp}). With Docker Desktop or colima on macOS, pick a directory
# the docker VM shares, such as one under $HOME.
set -eu

mode=${1:?usage: run-checks.sh container|devcontainer|os-user|stop}
here=$(cd "$(dirname "$0")" && pwd)
murk=${MURK:-murk}
image="murk-agent-isolation"

work=$(mktemp -d "${ISOLATION_WORK_ROOT:-${TMPDIR:-/tmp}}/murk-isolation.XXXXXX")
trap 'rm -rf "$work"' EXIT

if [ -n "${IMAGE_MURK:-}" ]; then
    mkdir "$work/murk-bin"
    cp "$IMAGE_MURK" "$work/murk-bin/murk"
    docker build -q -t "$image" --build-context murk-bin="$work/murk-bin" "$here" >/dev/null
else
    docker build -q -t "$image" "$here" >/dev/null
fi

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
        # Load the key pointer init wrote: murk reads only MURK_KEY and
        # MURK_KEY_FILE, not a key it stored by itself.
        . ./.env
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
            . ./.env
            echo in-scope-value | murk add API_KEY >/dev/null 2>&1
            echo out-of-scope-value | murk add OTHER >/dev/null 2>&1
            murk agent grant --name agent --only API_KEY --ttl 1h --out /tmp/grant.key >/dev/null 2>&1
            git init -q && git add .murk
            git -c user.name=alice -c user.email=alice@example.com commit -qm vault
        "
        sh /recipe/os-user.sh /tmp/grant.key /srv/repo alice API_KEY OTHER
    '
    ;;
stop)
    make_vault
    # The app exits 3 on SIGTERM. If murk, as PID 1, does not pass on the
    # SIGTERM from docker stop, docker kills the container after the timeout
    # instead (exit 137).
    cid=$(docker run -d \
        --user "$(id -u):$(id -g)" -e HOME=/tmp \
        -v "$work/repo:/work:ro" \
        -v "$work/grant.key:/run/murk/key:ro" \
        --entrypoint murk "$image" agent exec --only API_KEY -- \
        sh -c 'trap "exit 3" TERM; echo ready; while :; do sleep 0.1; done')
    trap 'docker rm -f "$cid" >/dev/null 2>&1; rm -rf "$work"' EXIT
    tries=0
    until docker logs "$cid" 2>&1 | grep -qx ready; do
        tries=$((tries + 1))
        if [ "$tries" -gt 100 ] || [ "$(docker inspect -f '{{.State.Running}}' "$cid")" != true ]; then
            echo "FAIL the app did not start under murk agent exec:"
            docker logs "$cid"
            exit 1
        fi
        sleep 0.1
    done
    docker stop -t 10 "$cid" >/dev/null
    status=$(docker inspect -f '{{.State.ExitCode}}' "$cid")
    if [ "$status" -eq 3 ]; then
        echo "ok   docker stop reached the app under murk agent exec as PID 1 (exit 3)"
    else
        echo "FAIL docker stop ended the container with exit $status, not the app's exit 3"
        exit 1
    fi
    ;;
*)
    echo "unknown mode: $mode (container, devcontainer, os-user or stop)" >&2
    exit 2
    ;;
esac
