"""Fixed-window rate limiting backed by Redis, with an in-process fallback.

If Redis is unreachable the limiter degrades to a per-process window rather
than failing open entirely.
"""

from __future__ import annotations

import threading
import time

import redis

from app.core.config import get_settings
from app.core.errors import RateLimited
from app.core.logging import get_logger

log = get_logger(__name__)


class RateLimiter:
    def __init__(self, redis_url: str | None):
        self._redis = redis.Redis.from_url(redis_url, socket_timeout=0.5) if redis_url else None
        self._local: dict[str, tuple[int, float]] = {}
        self._lock = threading.Lock()

    def _local_hit(self, key: str, window: int) -> int:
        now = time.time()
        with self._lock:
            count, reset = self._local.get(key, (0, now + window))
            if now >= reset:
                count, reset = 0, now + window
            count += 1
            self._local[key] = (count, reset)
            return count

    def hit(self, key: str, limit: int, window: int) -> None:
        bucket = f"cw:rl:{key}:{int(time.time() // window)}"
        count: int
        if self._redis is not None:
            try:
                pipe = self._redis.pipeline()
                pipe.incr(bucket)
                pipe.expire(bucket, window + 1)
                count = int(pipe.execute()[0])
            except redis.RedisError:
                log.warning("rate_limiter_redis_unavailable")
                count = self._local_hit(key, window)
        else:
            count = self._local_hit(key, window)
        if count > limit:
            raise RateLimited(
                "Too many requests. Please wait and try again.", details={"retry_after": window}
            )

    def reset(self) -> None:
        with self._lock:
            self._local.clear()


_limiter: RateLimiter | None = None


def get_limiter() -> RateLimiter:
    global _limiter
    if _limiter is None:
        settings = get_settings()
        _limiter = RateLimiter(settings.redis_url if settings.environment != "test" else None)
    return _limiter
