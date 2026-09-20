#!/usr/bin/with-contenv bashio
set -euo pipefail

bashio::log.info "Starting Local HTTPS Onboarding"
exec python3 /app/server.py
