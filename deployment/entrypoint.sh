#!/bin/sh
set -e

echo "=== [migrate] Applying admin DB migrations ==="
./hycert migrate admin

echo "=== [migrate] Applying tenant DB migrations ==="
./hycert migrate all-tenants

echo "=== [serve] Starting HyCert API server ==="
exec ./hycert serve
