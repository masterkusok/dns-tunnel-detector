#!/bin/sh

set -f -x -e

go="${GO:-go}"
readonly go

"$go" test -race=1 -count=2 ./...