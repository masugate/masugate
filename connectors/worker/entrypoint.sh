#!/bin/sh
set -eu

exec /usr/local/bin/python -u -c 'from masugate.operations.worker import main; main()' "$@"
