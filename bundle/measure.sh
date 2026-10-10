#!/usr/bin/env bash
# Measures the bundle fixtures with Effect's own bundle tooling.
#
# Usage: bundle/measure.sh /path/to/effect-checkout
#
# The Effect checkout must be on the `jose` branch of jpowersdev/effect, with
# dependencies installed (`pnpm install`). The script builds it, copies the
# fixtures into its git-ignored scratchpad, makes this repository's `jose`
# resolvable from there, and prints the gzipped size of each fixture.
set -euo pipefail

EFFECT="${1:?usage: bundle/measure.sh /path/to/effect-checkout}"
HERE="$(cd "$(dirname "$0")" && pwd)"
TARGET="$EFFECT/scratchpad/bundle"

mkdir -p "$TARGET/node_modules"
cp "$HERE"/fixtures/*.ts "$TARGET/"
ln -sfn "$HERE/../node_modules/jose" "$TARGET/node_modules/jose"

cd "$EFFECT"
pnpm build >/dev/null
# The tool reads stdin; close it so it does not wait for input.
node packages/tools/bundle/src/bin.ts report "$TARGET"/*.ts < /dev/null | grep '^|'
