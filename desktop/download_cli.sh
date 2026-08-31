#!/usr/bin/env sh
# Modified by AccordLock contributors; see UPSTREAM.md.
set -eu

printf '%s\n' \
  'AccordLock is source-only alpha software.' \
  'This inherited installer is disabled and does not download or install anything.' \
  'Use the repository README for controlled local source validation.' >&2
exit 64
