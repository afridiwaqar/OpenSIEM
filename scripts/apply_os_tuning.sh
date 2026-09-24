#!/bin/bash
#
# OpenSIEM / Chronicler — system tuning replication script
# ----------------------------------------------------------
# Replicates the OS-level changes made during troubleshooting on the
# reference server, but CALCULATES every numeric value from the target
# machine's actual RAM/CPU/Postgres settings instead of hardcoding the
# reference server's numbers. Safe to re-run (idempotent).
#
# What this script does:
#   1. php-fpm pool sizing        (pm.max_children etc.)
#   2. PostgreSQL memory tuning   (shared_buffers, effective_cache_size, work_mem)
#   3. pg_trgm extension          (needed for fast log search)
#   4. Daily archiver systemd timer
#
# What this script deliberately does NOT do:
#   - Create Postgres indexes (those are schema/data-specific — see the
#     separate index list from the incident writeup, applied by hand with
#     CREATE INDEX CONCURRENTLY so you can watch disk space while it runs)
#   - Touch application code or credentials
#   - Restart PostgreSQL for you (shared_buffers needs a restart — see the
#     final message this script prints; do that at a moment of your choosing)
#
# Usage:
#   sudo ./apply_os_tuning.sh <database_name>
#
# Example:
#   sudo ./apply_os_tuning.sh museum

set -euo pipefail

# ── 0. Preflight ─────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo ./apply_os_tuning.sh <database_name>)" >&2
    exit 1
fi

DB_NAME="${1:-}"
if [ -z "$DB_NAME" ]; then
    echo "Usage: sudo ./apply_os_tuning.sh <database_name>" >&2
    exit 1
fi

echo "=== OpenSIEM system tuning — calculating values for this machine ==="
echo ""

# ── 1. Detect system specs ───────────────────────────────────────────────
TOTAL_MEM_MB=$(free -m | awk '/^Mem:/{print $2}')
CPU_CORES=$(nproc)

echo "Detected: ${TOTAL_MEM_MB}MB RAM, ${CPU_CORES} CPU cores"

if [ "$TOTAL_MEM_MB" -lt 2048 ]; then
    echo "WARNING: under 2GB RAM detected — the calculated values below will"
    echo "         be conservative. Review them before applying to production."
fi

# ── 2. php-fpm pool sizing ───────────────────────────────────────────────
echo ""
echo "--- php-fpm pool ---"

PHP_POOL_CONF=$(find /etc/php -path "*/fpm/pool.d/www.conf" 2>/dev/null | sort -V | tail -1)
if [ -z "$PHP_POOL_CONF" ]; then
    echo "Could not find a php-fpm pool config under /etc/php — skipping this section."
else
    echo "Using pool config: $PHP_POOL_CONF"

    # Budget: reserve 1GB for the OS, reserve a Postgres-sized chunk (same
    # 25% we use for shared_buffers below, kept consistent), then give
    # php-fpm half of whatever's left — leaves headroom for OS page cache
    # and any other services on the box rather than claiming everything.
    PG_RESERVE_MB=$(( TOTAL_MEM_MB / 4 ))
    OS_RESERVE_MB=1024
    REMAINING_MB=$(( TOTAL_MEM_MB - OS_RESERVE_MB - PG_RESERVE_MB ))
    if [ "$REMAINING_MB" -lt 512 ]; then REMAINING_MB=512; fi
    PHP_BUDGET_MB=$(( REMAINING_MB / 2 ))

    # Measure actual per-worker memory if php-fpm is already running,
    # instead of assuming a fixed number — falls back to 30MB (observed
    # on the reference server) only if no workers are currently up.
    AVG_WORKER_MB=$(ps -o rss= -C "php-fpm8.3" 2>/dev/null | awk '{s+=$1; n++} END {if (n>0) print int(s/n/1024); else print 0}')
    if [ -z "$AVG_WORKER_MB" ] || [ "$AVG_WORKER_MB" -eq 0 ]; then
        AVG_WORKER_MB=30
        echo "No running php-fpm workers detected — assuming ~30MB/worker (measured on reference server)."
    else
        echo "Measured live php-fpm workers averaging ${AVG_WORKER_MB}MB each."
    fi

    MAX_CHILDREN=$(( PHP_BUDGET_MB / AVG_WORKER_MB ))
    if [ "$MAX_CHILDREN" -lt 5 ]; then MAX_CHILDREN=5; fi

    START_SERVERS=$(( MAX_CHILDREN * 20 / 100 ))
    MIN_SPARE=$(( MAX_CHILDREN * 10 / 100 ))
    MAX_SPARE=$(( MAX_CHILDREN * 40 / 100 ))
    [ "$START_SERVERS" -lt 1 ] && START_SERVERS=1
    [ "$MIN_SPARE" -lt 1 ] && MIN_SPARE=1
    [ "$MAX_SPARE" -le "$MIN_SPARE" ] && MAX_SPARE=$(( MIN_SPARE + 1 ))
    # Enforce FPM's own validation rule (min_spare <= start_servers <= max_spare)
    # up front — this exact ordering mistake broke php-fpm on the reference
    # server, so the script clamps it rather than letting it happen again.
    [ "$START_SERVERS" -lt "$MIN_SPARE" ] && START_SERVERS=$MIN_SPARE
    [ "$START_SERVERS" -gt "$MAX_SPARE" ] && START_SERVERS=$MAX_SPARE

    echo "Calculated: pm.max_children=${MAX_CHILDREN} start_servers=${START_SERVERS} min_spare=${MIN_SPARE} max_spare=${MAX_SPARE}"

    cp "$PHP_POOL_CONF" "${PHP_POOL_CONF}.bak.$(date +%s)"

    for pair in \
        "pm.max_children = ${MAX_CHILDREN}" \
        "pm.start_servers = ${START_SERVERS}" \
        "pm.min_spare_servers = ${MIN_SPARE}" \
        "pm.max_spare_servers = ${MAX_SPARE}" \
        "pm.process_idle_timeout = 10s" \
        "pm.max_requests = 500"
    do
        key="${pair%% =*}"
        if grep -qE "^${key}[[:space:]]*=" "$PHP_POOL_CONF"; then
            sed -i "s|^${key}[[:space:]]*=.*|${pair}|" "$PHP_POOL_CONF"
        else
            echo "$pair" >> "$PHP_POOL_CONF"
        fi
    done

    if php-fpm8.3 -t 2>/dev/null; then
        systemctl restart php8.3-fpm
        echo "php-fpm pool updated and restarted."
    else
        echo "WARNING: php-fpm config test failed — reverted nothing automatically."
        echo "         Check $PHP_POOL_CONF against its .bak file before restarting."
    fi
fi

# ── 3. PostgreSQL memory tuning ──────────────────────────────────────────
echo ""
echo "--- PostgreSQL memory ---"

if ! command -v psql >/dev/null 2>&1; then
    echo "psql not found — skipping PostgreSQL tuning."
else
    PG_SHARED_BUFFERS_MB=$(( TOTAL_MEM_MB / 4 ))          # 25% of RAM
    PG_EFFECTIVE_CACHE_MB=$(( TOTAL_MEM_MB * 70 / 100 ))   # 70% of RAM

    PG_MAX_CONN=$(sudo -u postgres psql -tAc "SHOW max_connections;" 2>/dev/null | tr -d ' ')
    if [ -z "$PG_MAX_CONN" ] || [ "$PG_MAX_CONN" -eq 0 ]; then PG_MAX_CONN=100; fi

    # work_mem is PER sort/hash operation, not global — sized against
    # max_connections so concurrent queries can't collectively exhaust
    # RAM. Deliberately conservative (quarter of RAM divided across all
    # possible connections) since this server also runs php-fpm workers
    # that need their own headroom.
    PG_WORK_MEM_MB=$(( (TOTAL_MEM_MB / 4) / PG_MAX_CONN ))
    [ "$PG_WORK_MEM_MB" -lt 4 ] && PG_WORK_MEM_MB=4
    [ "$PG_WORK_MEM_MB" -gt 256 ] && PG_WORK_MEM_MB=256

    echo "Calculated: shared_buffers=${PG_SHARED_BUFFERS_MB}MB effective_cache_size=${PG_EFFECTIVE_CACHE_MB}MB work_mem=${PG_WORK_MEM_MB}MB (max_connections=${PG_MAX_CONN})"

    sudo -u postgres psql -c "ALTER SYSTEM SET shared_buffers = '${PG_SHARED_BUFFERS_MB}MB';"
    sudo -u postgres psql -c "ALTER SYSTEM SET effective_cache_size = '${PG_EFFECTIVE_CACHE_MB}MB';"
    sudo -u postgres psql -c "ALTER SYSTEM SET work_mem = '${PG_WORK_MEM_MB}MB';"

    echo "Applied via ALTER SYSTEM. shared_buffers needs a full PostgreSQL"
    echo "restart to take effect — NOT done automatically by this script."
fi

# ── 4. pg_trgm extension (needed for fast ILIKE / substring log search) ──
echo ""
echo "--- pg_trgm extension ---"

if ! dpkg -l 2>/dev/null | grep -q "postgresql-contrib"; then
    echo "Installing postgresql-contrib..."
    apt-get update -qq && apt-get install -y -qq postgresql-contrib
fi
sudo -u postgres psql -d "$DB_NAME" -c "CREATE EXTENSION IF NOT EXISTS pg_trgm;"
echo "pg_trgm ready on database '$DB_NAME'."
echo "NOTE: trigram indexes on large text columns still need to be created"
echo "      by hand with CREATE INDEX CONCURRENTLY — see the incident writeup."

# ── 5. Daily archiver systemd timer ──────────────────────────────────────
echo ""
echo "--- Daily archiver timer ---"

ARCHIVER_SCRIPT="${ARCHIVER_SCRIPT_PATH:-/opt/opensiem/run_archive.py}"
RUN_USER="${ARCHIVER_RUN_USER:-www-data}"
LOG_DIR="${ARCHIVER_LOG_DIR:-/var/log/opensiem}"

if [ ! -f "$ARCHIVER_SCRIPT" ]; then
    echo "WARNING: $ARCHIVER_SCRIPT not found — writing the timer anyway, but"
    echo "         it will fail nightly until the archiver is deployed there."
    echo "         (override the path with: ARCHIVER_SCRIPT_PATH=/other/path $0 ...)"
fi

mkdir -p "$LOG_DIR"
chown "$RUN_USER":"$RUN_USER" "$LOG_DIR"

cat > /etc/systemd/system/opensiem-archive.service <<EOF
[Unit]
Description=OpenSIEM daily log archiver
After=postgresql.service network.target

[Service]
Type=oneshot
User=${RUN_USER}
Group=${RUN_USER}
ExecStart=/bin/bash -c '/usr/bin/python3 ${ARCHIVER_SCRIPT} --date \$(date -d "yesterday" +\%%Y-\%%m-\%%d)'
StandardOutput=append:${LOG_DIR}/archive_cron.log
StandardError=append:${LOG_DIR}/archive_cron.log
EOF

cat > /etc/systemd/system/opensiem-archive.timer <<'EOF'
[Unit]
Description=Run OpenSIEM archiver daily

[Timer]
OnCalendar=*-*-* 02:15:00
Persistent=true
RandomizedDelaySec=120

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now opensiem-archive.timer
echo "Timer installed and enabled — next run:"
systemctl list-timers opensiem-archive.timer --no-pager | head -2

# ── Summary ───────────────────────────────────────────────────────────────
echo ""
echo "=== Done ==="
echo "Still needed, manually, at a time of your choosing:"
echo "  1. Restart PostgreSQL for shared_buffers to take effect:"
echo "       sudo systemctl restart postgresql"
echo "  2. Create the schema-specific indexes (message/calendar/alerts) by hand"
echo "     with CREATE INDEX CONCURRENTLY, watching disk space as you go."
echo "  3. Configure and activate an archive storage backend in the UI —"
echo "     the timer will run nightly but do nothing without one."
