"""
ratelimiter.py
--------------
Behavior monitoring. Tracks how many requests each IP sends inside a sliding
time window and flags abusive IPs.

Two things can get an IP banned (temporarily):
  * "rate"   - it keeps exceeding the request limit (brute force / flooding)
  * "attack" - several of its requests were blocked as malicious

All methods take `now` (seconds) as an argument, so the same code works for
real traffic and for simulated traffic with fixed timestamps.
"""

from collections import defaultdict, deque


class RateLimiter:
    def __init__(self, limit=10, window=10.0, ban_after=None, ban_seconds=300.0):
        self.limit = limit                    # max requests per window
        self.window = window                  # window length in seconds
        self.ban_after = ban_after or {"rate": 5, "attack": 3}
        self.ban_seconds = ban_seconds
        self._hits = defaultdict(deque)       # ip -> timestamps in the window
        self._strikes = defaultdict(int)      # (ip, kind) -> count
        self._banned = {}                     # ip -> ban expiry time
        self.ban_events = []                  # history, used by the report

    def is_banned(self, ip: str, now: float) -> bool:
        until = self._banned.get(ip)
        if until is None:
            return False
        if now >= until:                      # ban has expired
            del self._banned[ip]
            for kind in self.ban_after:
                self._strikes[(ip, kind)] = 0
            return False
        return True

    def over_limit(self, ip: str, now: float) -> bool:
        """Record one request and report whether the IP is now over its limit."""
        hits = self._hits[ip]
        while hits and now - hits[0] >= self.window:
            hits.popleft()
        hits.append(now)
        return len(hits) > self.limit

    def add_strike(self, ip: str, kind: str, now: float) -> bool:
        """Count a violation. Returns True if this strike caused a ban."""
        self._strikes[(ip, kind)] += 1
        if self._strikes[(ip, kind)] >= self.ban_after[kind]:
            self._banned[ip] = now + self.ban_seconds
            self.ban_events.append({
                "ip": ip,
                "reason": kind,
                "strikes": self._strikes[(ip, kind)],
                "banned_at": now,
                "banned_until": now + self.ban_seconds,
            })
            return True
        return False
