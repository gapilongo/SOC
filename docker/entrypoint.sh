#!/bin/bash
set -e

# Wait for database to be ready
echo "Waiting for database to be ready..."
until python -c "import asyncio; import sys; sys.path.insert(0, '/app/src'); from lg_sotf.storage.postgres import PostgreSQLStorage; asyncio.run(PostgreSQLStorage('${DATABASE_CONNECTION_STRING}').health_check())"; do
    echo "Database is unavailable - sleeping"
    sleep 1
done

echo "Database is ready!"

# Wait for Redis to be ready
echo "Waiting for Redis to be ready..."
until python -c "import asyncio; import sys; sys.path.insert(0, '/app/src'); from lg_sotf.storage.redis import RedisStorage; asyncio.run(RedisStorage('${REDIS_CONNECTION_STRING}').health_check())"; do
    echo "Redis is unavailable - sleeping"
    sleep 1
done

echo "Redis is ready!"

# Run migrations if needed
echo "Running database migrations..."
python scripts/setup_db.py

# Start the application
echo "Starting LG-SOTF..."
exec "$@"