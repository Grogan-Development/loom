#!/usr/bin/env bash
# Ordered owner commands to bootstrap the first fleet on a fresh loomd.
# Requires: LOOM_URL + LOOM_TOKEN in the environment (or `loom login` first).
set -euo pipefail

IMPORTS=(
  "loom loom"
  "grogan www"
  "gachagang www"
  "printprecision app"
  "printprecision pathfinders"
  "nero assistant"
  "nero chat"
  "tracedb engine"
  "tracedb www"
  "tzp core"
  "tzp pack"
  "tzp server"
  "tzp infra"
  "tzp web"
  "tzp launcher"
)

echo "# 1. Import every project/repo (empty import; push real history over /git after)."
for pair in "${IMPORTS[@]}"; do
  set -- $pair
  echo "$ loom repo import --project $1 --name $2"
  loom repo import --project "$1" --name "$2" || true
done

echo "# 2. Close the loop: one feature through both gates on loom/loom."
echo "#    Write a feature JSON, then:"
echo "#      loom feature create --file feature.json"
echo "#      loom feature approve <id>"
echo "#      loom candidate submit --feature <id> --file candidate.json"
echo "#      loom feature accept <id>"

echo "# 3. Optional: register the GitHub outbound mirror via loomd ORIGIN_* env."
