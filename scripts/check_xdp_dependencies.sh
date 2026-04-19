#!/bin/bash
set -e

echo "XDP dependency check"

if go list ./... >/dev/null 2>&1; then
  echo "go list ./... passed"
else
  echo "go list ./... failed"
  exit 1
fi

if grep -R "internal/plugins/types" pkg/sdk --include="*.go" >/dev/null 2>&1; then
  echo "pkg/sdk imports internal/plugins/types"
  exit 1
else
  echo "pkg/sdk import guard passed"
fi

if grep -R "internal/platform/" internal/datapath/xdp --include="*.go" >/dev/null 2>&1; then
  echo "internal/datapath/xdp imports internal/platform"
  exit 1
else
  echo "internal/datapath/xdp platform import guard passed"
fi

xdp_imports=$(go list -f '{{join .Imports "\n"}}' ./internal/datapath/xdp/...)
if echo "$xdp_imports" | grep -E '^github\.com/netxfw/netxfw/cmd/' >/dev/null 2>&1; then
  echo "internal/datapath/xdp imports cmd layer"
  exit 1
else
  echo "internal/datapath/xdp cmd import guard passed"
fi

go list -deps ./internal/datapath/xdp/... >/dev/null
go list -deps ./pkg/sdk >/dev/null
echo "xdp and sdk dependency traversal passed"
