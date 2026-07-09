#!/bin/sh
set -e

# EFF-Monitoring v2.1.3  entrypoint
# Wait for PostgreSQL to become available before starting the application.

if [ -n "$DATABASE_URL" ]; then
    echo "entrypoint: checking database connectivity..."
    # Extract host and port from DATABASE_URL format:
    #   postgresql+psycopg://user:pass@host:port/db
    DB_HOST=$(echo "$DATABASE_URL" | sed -n 's|.*@\([^:/]*\).*|\1|p')
    DB_PORT=$(echo "$DATABASE_URL" | sed -n 's|.*:\([0-9]*\)/.*|\1|p')
    DB_PORT=${DB_PORT:-5432}

    if [ -z "$DB_HOST" ]; then
        echo "entrypoint: could not parse host from DATABASE_URL, skipping wait"
    else
        MAX_RETRIES=30
        RETRY=1
        while [ $RETRY -le $MAX_RETRIES ]; do
            if nc -z "$DB_HOST" "$DB_PORT" 2>/dev/null; then
                echo "entrypoint: database is ready ($DB_HOST:$DB_PORT)"
                break
            fi
            echo "entrypoint: waiting for database at $DB_HOST:$DB_PORT ... ($RETRY/$MAX_RETRIES)"
            sleep 2
            RETRY=$((RETRY + 1))
        done
        if [ $RETRY -gt $MAX_RETRIES ]; then
            echo "entrypoint: WARNING - database not reachable after ${MAX_RETRIES} attempts, starting anyway"
        fi
    fi
fi

exec "$@"
