#!/usr/bin/env bash
set -euo pipefail
run_tlc() {
  local jar="$1"
  (cd specs && java -XX:+UseParallelGC -cp "$jar" tlc2.TLC -workers auto -config NoBypass.cfg NoBypass.tla)
}
if command -v java >/dev/null 2>&1; then
  if [ -n "${TLA2TOOLS_JAR:-}" ] && [ -f "$TLA2TOOLS_JAR" ]; then
    run_tlc "$TLA2TOOLS_JAR"
  elif [ -f "/tools/tla2tools.jar" ]; then
    run_tlc /tools/tla2tools.jar
  else
    echo "SKIP TLC: tla2tools.jar not found"
  fi
else
  echo "SKIP TLC: java not found"
fi