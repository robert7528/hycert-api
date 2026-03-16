#!/bin/sh
set -e

echo "=== [serve] Starting HyCert API server ==="
exec ./hycert-api serve
