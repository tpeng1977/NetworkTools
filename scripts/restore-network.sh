#!/usr/bin/env bash
# Alias: kill + full network restore.
exec "$(cd "$(dirname "$0")" && pwd)/cleanup-linux-network.sh"
