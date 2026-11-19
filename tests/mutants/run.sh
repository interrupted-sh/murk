#!/usr/bin/env bash
# SPDX-FileCopyrightText: murk contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

# Check that every enforced invariant row fails with its guard disabled.
#
# tests/invariant_rows.tsv names, for each enforced row, a patch under
# tests/mutants/ that disables the guard the row exists for, and the test that
# runs the row. For each patch this script applies it to a scratch copy of the
# tree, builds, and runs each of the patch's rows: every one must fail. A row
# that stays green with its guard gone is vacuous. Before any patch, every row
# must pass on the unpatched tree, so a failure under a patch means something.
#
# The working tree is never modified. Builds go to target/row-mutants.
#
# Usage: tests/mutants/run.sh [ROW-ID...]   (default: every enforced row)
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
table=tests/invariant_rows.tsv
# ROW_MUTANTS_DIR lets two runs work side by side.
export CARGO_TARGET_DIR="${ROW_MUTANTS_DIR:-$root/target/row-mutants}"
export MURK_ROWS=

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
home="$scratch/home"
tree="$CARGO_TARGET_DIR-tree"
mkdir -p "$home"

# Enforced lines (optionally only the named rows): id, binary, test, patch.
lines="$(awk -F'\t' -v want=" $* " '
  /^#/ || NF == 0 { next }
  $2 == "enforced" && (want == "  " || index(want, " " $1 " ")) { print $1 "\t" $4 "\t" $5 "\t" $6 }
' "$table")"
if [ -z "$lines" ]; then
  echo "no enforced rows selected" >&2
  exit 1
fi

# A fixed path keeps cargo's fingerprints, so only what a patch touches is
# rebuilt. Every source is touched after the copy: a file restored from the
# unpatched tree keeps its old mtime, which cargo would take as up to date.
fresh_tree() {
  rm -rf "$tree"
  mkdir -p "$tree"
  tar -C "$root" --exclude=./target --exclude=./.git --exclude=./node/node_modules \
    --exclude=./docs-site --exclude=./demo -cf - . | tar -C "$tree" -xf -
  find "$tree/src" -name '*.rs' -exec touch {} +
}

# Run one row's test in the scratch tree. Prints the test output; returns the
# test's exit status, or 2 when the filter matched no test.
run_test() {
  local binary="$1" test="$2" out status=0
  local target=(--test "$binary")
  [ "$binary" = lib ] && target=(--lib)
  out="$(cd "$tree" && env -u MURK_KEY -u MURK_KEY_FILE -u MURK_AGENT -u MURK_TRUSTED_SIGNERS \
    HOME="$home" cargo test --quiet "${target[@]}" "$test" 2>&1)" || status=$?
  printf '%s\n' "$out" | tail -n 20
  if ! printf '%s\n' "$out" | grep -Eq 'test result: [a-zA-Z]+\. ([1-9][0-9]* passed|[0-9]+ passed; [1-9][0-9]* failed)'; then
    return 2
  fi
  return "$status"
}

fresh_tree
echo "== baseline: every selected row passes on the unpatched tree"
while IFS=$'\t' read -r id binary test patch; do
  if ! run_test "$binary" "$test" >"$scratch/log"; then
    cat "$scratch/log"
    echo "::error title=Row fails unpatched::$id ($binary $test) fails or matches no test without its mutant" >&2
    exit 1
  fi
  echo "ok   $id $test"
done <<<"$lines"

failures=0
for patch in $(printf '%s\n' "$lines" | cut -f4 | sort -u); do
  echo "== $patch"
  fresh_tree
  # The tree sits inside this repository's target/, and git apply run inside
  # a repository resolves paths against it (a patch with `diff --git` headers
  # then applies to nothing). The ceiling makes it a plain patch tool here.
  before="$(find "$tree/src" -type f -exec cksum {} + | sort)"
  if ! (cd "$tree" && GIT_CEILING_DIRECTORIES="$(dirname "$tree")" git apply "$root/$patch"); then
    echo "::error title=Mutant patch does not apply::$patch no longer applies; update it to disable the same guard in the current code" >&2
    failures=$((failures + 1))
    continue
  fi
  if [ "$before" = "$(find "$tree/src" -type f -exec cksum {} + | sort)" ]; then
    echo "::error title=Mutant patch changes nothing::$patch applied but left src/ unchanged" >&2
    failures=$((failures + 1))
    continue
  fi
  while IFS=$'\t' read -r id binary test p; do
    [ "$p" = "$patch" ] || continue
    status=0
    run_test "$binary" "$test" >"$scratch/log" || status=$?
    case "$status" in
      0)
        cat "$scratch/log"
        echo "::error title=Vacuous row::$id ($test) passes with its guard disabled by $patch" >&2
        failures=$((failures + 1))
        ;;
      2)
        cat "$scratch/log"
        echo "::error title=Mutant does not build or row not found::$id ($test) under $patch ran no test" >&2
        failures=$((failures + 1))
        ;;
      *) echo "caught $id $test" ;;
    esac
  done <<<"$lines"
done

if [ "$failures" -ne 0 ]; then
  echo "$failures row mutant check(s) failed" >&2
  exit 1
fi
echo "every selected row fails with its guard disabled"
