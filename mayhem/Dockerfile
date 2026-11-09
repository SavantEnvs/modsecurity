# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile — ModSecurity (libmodsecurity v3) on the org C/C++ base image.
#
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile --build-arg COMMIT=$(git rev-parse HEAD) -t mytag .
#
# The build context must contain the submodules (libinjection, mbedtls, secrules-language-tests):
# `git submodule update --init --recursive others/libinjection others/mbedtls test/test-cases/secrules-language-tests`

FROM ghcr.io/savantenvs/base:20261023

ARG COMMIT
ARG REPO_URL
ARG SOURCE_DATE_EPOCH
ARG SANITIZER_FLAGS
ARG COVERAGE_FLAGS=
ARG MAYHEM_JOBS=

# Build dependencies (apt, pinned via SOURCE_DATE_EPOCH when set). libpcre3 is gone from Debian
# trixie, so the build uses PCRE2. git: configure runs `git describe` in the submodules.
USER root
RUN [ -n "$SOURCE_DATE_EPOCH" ] && repro-sources-list.sh || true ; \
    apt-get update && apt-get install -yq --no-install-recommends \
        git libtool libpcre2-dev libyajl-dev libxml2-dev libcurl4-openssl-dev \
        liblua5.3-dev libmaxminddb-dev libfuzzy-dev liblmdb-dev libgeoip-dev \
 && rm -rf /var/lib/apt/lists/*
USER mayhem

WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

# build.sh and test.sh only use files that are committed or that build.sh itself (re)creates, so
# they survive the grader's `git clean -ffdX` (SPEC §6.2 item 16).
RUN if [ -x /opt/mayhem/ccache/prefill ]; then /opt/mayhem/ccache/prefill bash mayhem/build.sh; \
    else bash mayhem/build.sh; fi

RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh — repo ships no functional tests"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.fix="352b7056646ef6b5bd9c4decb1ee124c2ff2d099" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
