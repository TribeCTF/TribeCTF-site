#!/usr/bin/env bash
# Publish closing-2026-slides/ to https://www.cs.wm.edu/~pniroula/closing/
# (host bg13.cs.wm.edu, dir ~/public_html/closing). Replaces the dir wholesale.
# Usage: scripts/push_closing.sh [--stats]   (--stats: regenerate stats first)
# Why not rsync/scp: remote ~/.bashrc ends in a bare `zsh`, which swallows ssh
# stdin. So stdin is itself a POSIX script (tarball inline as base64): that zsh
# runs it; if the bashrc is ever fixed, `sh -s` runs it instead.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ "${1:-}" == "--stats" ]] && python3 scripts/closing_stats.py
{
  echo 'set -e; cd "$HOME/public_html"; rm -rf closing.new; mkdir closing.new'
  echo 'base64 -d <<"__TARB64__" | tar -xzf - -C closing.new'
  COPYFILE_DISABLE=1 tar -C closing-2026-slides --exclude .DS_Store --no-xattrs -czf - . | base64 -b 76
  echo '__TARB64__'
  echo 'find closing.new -type d -exec chmod 755 {} +; find closing.new -type f -exec chmod 644 {} +'
  echo 'rm -rf closing; mv closing.new closing; echo REMOTE-OK; exit 0'
} | ssh -o BatchMode=yes bg13.cs.wm.edu 'sh -s' 2>&1 | grep -v -E 'post-quantum|store now|server may'
echo "Live: https://www.cs.wm.edu/~pniroula/closing/"
