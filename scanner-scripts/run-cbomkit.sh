#!/bin/sh
WORKSPACE="${1:-/tmp/repo}"
# Placeholder CLI: replace with actual cbomkit container/command
docker run --rm -v "$WORKSPACE":/src cyclonedx/cyclonedx-cli:latest   cyclonedx create --type java --output-format json --output-file /src/cbomkit-out.json /src >/dev/null 2>&1
cat "$WORKSPACE/cbomkit-out.json" || echo "{}"
