import os
import time
from collections import defaultdict, deque
from threading import Lock

from flask import jsonify, request


class SlidingWindowRateLimiter:
    def __init__(self, limit, window_seconds, clock=time.monotonic):
        if limit <= 0 or window_seconds <= 0:
            raise ValueError('rate-limit values must be positive')
        self.limit = limit
        self.window_seconds = window_seconds
        self.clock = clock
        self.requests = defaultdict(deque)
        self.lock = Lock()
        self.last_cleanup = self.clock()

    def discard_expired_clients(self, cutoff):
        expired_clients = []
        for stored_key, timestamps in self.requests.items():
            while timestamps and timestamps[0] <= cutoff:
                timestamps.popleft()
            if not timestamps:
                expired_clients.append(stored_key)
        for stored_key in expired_clients:
            del self.requests[stored_key]

    def check(self, key):
        now = self.clock()
        cutoff = now - self.window_seconds
        with self.lock:
            if now - self.last_cleanup >= self.window_seconds:
                self.discard_expired_clients(cutoff)
                self.last_cleanup = now
            timestamps = self.requests[key]
            while timestamps and timestamps[0] <= cutoff:
                timestamps.popleft()
            if len(timestamps) >= self.limit:
                retry_after = max(1, int(self.window_seconds - (now - timestamps[0])))
                return False, retry_after
            timestamps.append(now)
            return True, 0


def configure_rate_limiting(app, limiter=None):
    limiter = limiter or SlidingWindowRateLimiter(
        limit=int(os.getenv('VAMPI_RATE_LIMIT', 30)),
        window_seconds=int(os.getenv('VAMPI_RATE_WINDOW', 60)))

    @app.before_request
    def enforce_rate_limit():
        if request.method == 'OPTIONS':
            return None
        route = request.url_rule.rule if request.url_rule else request.path
        key = (request.remote_addr or 'unknown', request.method, route)
        allowed, retry_after = limiter.check(key)
        if allowed:
            return None
        # ASVS 2.4.1: bound repeated calls per client and API operation.
        response = jsonify({'status': 'fail', 'message': 'Rate limit exceeded.'})
        response.status_code = 429
        response.headers['Retry-After'] = str(retry_after)
        return response

    app.extensions['vampi_rate_limiter'] = limiter
    return limiter
