#!/usr/bin/env sh
set -eu

printf '%s\n' \
  'AccordLock public pre-release retrieval is disabled.' \
  'No signed installer or approved artifact channel exists for this source alpha.' >&2
exit 64
