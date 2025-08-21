"""
Database setup script for LG-SOTF.

This script sets up the database schema and initial data
for development and testing environments.
"""

import asyncio
import os
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from lg_sotf.core.config.manager import ConfigManager
from lg_sotf.storage.postgres import PostgreSQLStorage
from lg_sotf.storage.redis import RedisStorage


async def setup_database():
    """Set up the database schema and initial data."""
    print("Setting up database...")
    
    # Load configuration
    config = ConfigManager()
    
    # Get database configuration
    db_config = config.get_database_config()
    connection_string = (
        f"postgresql://{db_config.username}:{db_config.password}@"
        f"{db_config.host}:{db_config.port}/{db_config.database}"
    )
    
    # Initialize PostgreSQL storage
    postgres_storage = PostgreSQLStorage(connection_string)
    
    try:
        # Initialize storage (creates tables)
        await postgres_storage.initialize()
        print("✅ PostgreSQL database initialized successfully")
        
        # Test connection
        is_healthy = await postgres_storage.health_check()
        if is_healthy:
            print("✅ PostgreSQL health check passed")
        else:
            print("❌ PostgreSQL health check failed")
            return False
        
    except Exception as e:
        print(f"❌ Failed to set up PostgreSQL: {e}")
        return False
    finally:
        await postgres_storage.close()
    
    # Set up Redis
    print("\nSetting up Redis...")
    
    redis_config = config.get_redis_config()
    redis_connection_string = config.get('storage.redis.connection_string', 'redis://localhost:6379/0')
    
    redis_storage = RedisStorage(redis_connection_string)
    
    try:
        # Initialize Redis storage
        await redis_storage.initialize()
        print("✅ Redis initialized successfully")
        
        # Test connection
        is_healthy = await redis_storage.health_check()
        if is_healthy:
            print("✅ Redis health check passed")
        else:
            print("❌ Redis health check failed")
            return False
        
    except Exception as e:
        print(f"❌ Failed to set up Redis: {e}")
        return False
    finally:
        await redis_storage.close()
    
    print("\n🎉 Database setup completed successfully!")
    return True


async def main():
    """Main function."""
    try:
        success = await setup_database()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\nSetup cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())