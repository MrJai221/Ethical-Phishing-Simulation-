# src/database_manager.py

import sqlite3
import time
import logging
import asyncio
import json
import os
from typing import Optional, Dict, Any

# Use aiosqlite for async database operations
try:
    import aiosqlite
except ImportError:
    aiosqlite = None  # Flag that it's missing

logger = logging.getLogger(__name__)

class DatabaseManager:
    """
    Manages the SQLite database connection and caching operations for VirusTotal results
    using asynchronous I/O with aiosqlite.
    """

    def __init__(self, db_path: str, cache_duration_seconds: int):
        """
        Initializes the DatabaseManager.

        Args:
            db_path (str): The file path for the SQLite database.
            cache_duration_seconds (int): How long cache entries should be considered valid (in seconds).
        """
        self.db_path = db_path
        self.cache_duration_seconds = cache_duration_seconds
        self._init_lock = asyncio.Lock()
        self._db_initialized = False

        if aiosqlite is None:
            logger.warning(
                "⚠️ aiosqlite is not installed. VirusTotal results will NOT be cached. "
                "Install it with: pip install aiosqlite"
            )
        else:
            logger.info(f"✅ DatabaseManager initialized with cache at {db_path}")

    async def _get_connection(self) -> Optional["aiosqlite.Connection"]:
        """Establishes and returns an async database connection."""
        if aiosqlite is None:
            logger.debug("Skipping DB connection — aiosqlite not available.")
            return None

        try:
            db_dir = os.path.dirname(self.db_path)
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir, exist_ok=True)
                logger.info(f"Created database directory: {db_dir}")

            conn = await aiosqlite.connect(self.db_path, isolation_level=None)
            conn.row_factory = aiosqlite.Row
            return conn
        except Exception as e:
            logger.error(f"❌ Failed to connect to database {self.db_path}: {e}")
            return None

    async def init_db(self) -> None:
        """Initializes the database schema."""
        if aiosqlite is None or self._db_initialized:
            return

        async with self._init_lock:
            if self._db_initialized:
                return

            conn = await self._get_connection()
            if not conn:
                logger.error("❌ Cannot initialize DB schema — no connection.")
                self._db_initialized = True
                return

            try:
                async with conn.cursor() as cursor:
                    await cursor.execute("""
                        CREATE TABLE IF NOT EXISTS vt_cache (
                            indicator TEXT PRIMARY KEY,
                            indicator_type TEXT NOT NULL CHECK(indicator_type IN ('ip', 'url', 'hash')),
                            result TEXT NOT NULL,
                            timestamp INTEGER NOT NULL
                        )
                    """)
                    await cursor.execute("""
                        CREATE INDEX IF NOT EXISTS idx_vt_cache_timestamp ON vt_cache (timestamp)
                    """)
                await conn.commit()
                self._db_initialized = True
                logger.info(f"✅ Database schema initialized at {self.db_path}")
            except Exception as e:
                logger.error(f"❌ Failed to initialize DB schema: {e}")
                self._db_initialized = True
            finally:
                await conn.close()

    async def get_cached_result(self, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        """Retrieve a cached VirusTotal result if still valid."""
        if aiosqlite is None:
            logger.debug("Skipping cache lookup — aiosqlite not available.")
            return None

        await self.init_db()
        if not self._db_initialized:
            logger.warning("DB not initialized, cannot retrieve cached result.")
            return None

        conn = await self._get_connection()
        if not conn:
            return None

        try:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    "SELECT result, timestamp FROM vt_cache WHERE indicator = ? AND indicator_type = ?",
                    (indicator, indicator_type),
                )
                row = await cursor.fetchone()

            if not row:
                logger.debug(f"Cache miss for {indicator_type}: {indicator}")
                return None

            age = time.time() - row["timestamp"]
            if age < self.cache_duration_seconds:
                logger.debug(f"Cache hit for {indicator_type}: {indicator} (age {age:.0f}s)")
                return json.loads(row["result"])
            else:
                logger.debug(f"Cache expired for {indicator_type}: {indicator} (age {age:.0f}s)")
                return None

        except Exception as e:
            logger.error(f"❌ Error reading cache for {indicator_type} '{indicator}': {e}")
            return None
        finally:
            await conn.close()

    async def store_result(self, indicator: str, indicator_type: str, result: Dict[str, Any]) -> None:
        """Store or update a VirusTotal result in the cache DB."""
        if aiosqlite is None:
            logger.debug("Skipping store — aiosqlite not available.")
            return

        await self.init_db()
        if not self._db_initialized:
            return

        conn = await self._get_connection()
        if not conn:
            return

        try:
            result_json = json.dumps(result)
            now = int(time.time())
            async with conn.cursor() as cursor:
                await cursor.execute(
                    "INSERT OR REPLACE INTO vt_cache (indicator, indicator_type, result, timestamp) VALUES (?, ?, ?, ?)",
                    (indicator, indicator_type, result_json, now),
                )
            await conn.commit()
            logger.debug(f"✅ Cached {indicator_type}: {indicator}")
        except Exception as e:
            logger.error(f"❌ Error caching {indicator_type} '{indicator}': {e}")
        finally:
            await conn.close()

    async def delete_cached_result(self, indicator: str, indicator_type: str) -> None:
        """Delete a specific cached result."""
        if aiosqlite is None:
            return

        conn = await self._get_connection()
        if not conn:
            return

        try:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    "DELETE FROM vt_cache WHERE indicator = ? AND indicator_type = ?",
                    (indicator, indicator_type),
                )
            await conn.commit()
            logger.debug(f"🗑️ Deleted cache for {indicator_type}: {indicator}")
        except Exception as e:
            logger.error(f"❌ Error deleting cache for {indicator_type} '{indicator}': {e}")
        finally:
            await conn.close()

    async def prune_old_cache(self) -> None:
        """Remove old cache entries past expiry."""
        if aiosqlite is None:
            return

        await self.init_db()
        if not self._db_initialized:
            return

        conn = await self._get_connection()
        if not conn:
            return

        cutoff = int(time.time()) - self.cache_duration_seconds
        try:
            async with conn.cursor() as cursor:
                await cursor.execute("DELETE FROM vt_cache WHERE timestamp < ?", (cutoff,))
            await conn.commit()
            logger.info(f"🧹 Pruned cache entries older than {self.cache_duration_seconds} seconds")
        except Exception as e:
            logger.error(f"❌ Error pruning old cache: {e}")
        finally:
            await conn.close()
