#!/bin/sh
# SPDX-FileCopyrightText: murk contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

# Run this as the agent, inside the isolation recipe (a container, a
# devcontainer or a separate OS user), from the directory that holds the vault.
# It checks that the grant key is the only murk key the agent can reach:
#
#   1. the operator's key directory is not readable;
#   2. with MURK_AGENT, MURK_STRICT, MURK_KEY and MURK_KEY_FILE unset, murk
#      finds no key, so an out-of-scope read fails;
#   3. with the grant key, an in-scope read works;
#   4. with the grant key, an out-of-scope read fails with "outside this
#      grant's scope".
#
# Usage: GRANT_KEY_FILE=/run/murk/key sh check.sh IN_SCOPE_KEY OUT_OF_SCOPE_KEY
# OPERATOR_KEYS is the operator's key directory as this identity would see it.
# It defaults to $HOME/.config/murk/keys. Set it to the operator's real path
# (for example /home/alice/.config/murk/keys) for a separate OS user.
set -u

in_scope=${1:?usage: check.sh IN_SCOPE_KEY OUT_OF_SCOPE_KEY}
out_of_scope=${2:?usage: check.sh IN_SCOPE_KEY OUT_OF_SCOPE_KEY}
grant=${GRANT_KEY_FILE:?set GRANT_KEY_FILE to the grant key file}
operator_keys=${OPERATOR_KEYS:-$HOME/.config/murk/keys}
murk=${MURK:-murk}
failed=0

pass() { echo "ok   $1"; }
fail() { echo "FAIL $1"; failed=1; }

# 1. The operator's key directory is not readable.
if ls "$operator_keys" >/dev/null 2>&1; then
    fail "operator key directory $operator_keys is readable"
else
    pass "operator key directory $operator_keys is not readable"
fi

# 2. No murk variables: murk must find no key at all.
if out=$(env -u MURK_AGENT -u MURK_STRICT -u MURK_KEY -u MURK_KEY_FILE \
    "$murk" get "$out_of_scope" 2>&1); then
    fail "with no murk variables set, murk get $out_of_scope printed a value"
else
    pass "with no murk variables set, murk get $out_of_scope fails: $(echo "$out" | head -n 1)"
fi

# 3. The grant key reads its own key.
if env -u MURK_KEY MURK_KEY_FILE="$grant" MURK_AGENT=1 \
    "$murk" get "$in_scope" >/dev/null 2>&1; then
    pass "the grant reads $in_scope"
else
    fail "the grant cannot read $in_scope"
fi

# 4. The grant key refuses a key outside its scope.
out=$(env -u MURK_KEY MURK_KEY_FILE="$grant" MURK_AGENT=1 \
    "$murk" get "$out_of_scope" 2>&1)
status=$?
if [ "$status" -ne 0 ] && echo "$out" | grep -q "outside this grant's scope"; then
    pass "the grant refuses $out_of_scope: $(echo "$out" | head -n 1)"
else
    fail "the grant did not refuse $out_of_scope as out of scope (exit $status): $out"
fi

if [ "$failed" -ne 0 ]; then
    echo "isolation check failed"
    exit 1
fi
echo "isolation check passed: the grant key is the only murk key here"
