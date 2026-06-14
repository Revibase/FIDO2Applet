#!/usr/bin/env bash
# Root wrapper — see tools/register_card.sh
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/tools/register_card.sh" "$@"
