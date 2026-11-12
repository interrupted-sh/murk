# SPDX-FileCopyrightText: murk contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

# An agent image whose only murk credential is a grant key mounted at run time.
# The image holds the murk binary and nothing secret. The operator's
# ~/.config/murk is never mounted, so the grant key is the only key present.

# A directory with a Linux murk binary to install instead of the release, for
# testing a local build. It is empty unless you name one at build time:
#   docker build --build-context local-binary=DIR scripts/agent-isolation
# where DIR holds only the `murk` binary.
FROM scratch AS local-binary

FROM debian:bookworm-slim

ARG MURK_VERSION=v0.15.0
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git \
 && rm -rf /var/lib/apt/lists/*
RUN --mount=type=bind,from=local-binary,target=/tmp/local-binary \
    set -eu; \
    if [ -e /tmp/local-binary/murk ]; then \
        install -m 0755 /tmp/local-binary/murk /usr/local/bin/murk; \
        exit 0; \
    fi; \
    archive="murk-${MURK_VERSION}-$(uname -m)-unknown-linux-gnu.tar.gz"; \
    base="https://github.com/interrupted-sh/murk/releases/download/${MURK_VERSION}"; \
    cd /tmp; \
    curl -fsSLO "$base/$archive"; \
    curl -fsSL "$base/SHA256SUMS" | grep " $archive\$" | sha256sum -c -; \
    tar -xzf "$archive" -C /usr/local/bin murk; \
    rm "$archive"

# Run as an unprivileged user. The grant key file must be owned by this user
# (uid 1000 here) with mode 0600 or 0400: murk refuses a key file that others
# can read.
RUN useradd --create-home --uid 1000 agent
USER agent
WORKDIR /work
ENV MURK_KEY_FILE=/run/murk/key MURK_AGENT=1
COPY --chmod=0755 check.sh /usr/local/bin/murk-isolation-check
