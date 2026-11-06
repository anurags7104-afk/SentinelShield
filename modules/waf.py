"""
waf.py
------
The decision engine. Ties the pieces together in the order of the project's
workflow:

    request -> banned? -> rate limit -> inspect -> decision -> log

Actions and the HTTP status the client would receive:
    ALLOW        200  request is clean
    SUSPICIOUS   200  low score: let it through but log it
    BLOCK        403  score reached the block threshold
    RATE_LIMIT   429  IP sent too many requests in the window
    BLOCK_IP     403  IP is temporarily banned
"""

from datetime import datetime, timezone

from .inspector import inspect
from .ratelimiter import RateLimiter

STATUS = {"ALLOW": 200, "SUSPICIOUS": 200, "BLOCK": 403, "RATE_LIMIT": 429, "BLOCK_IP": 403}


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="milliseconds")


class SentinelShield:
    def __init__(self, limiter: RateLimiter = None, logger=None):
        self.limiter = limiter or RateLimiter()
        self.logger = logger

    def handle(self, req: dict) -> dict:
        ip, now = req["ip"], req["ts"]
        decision = {"action": "ALLOW", "score": 0, "matches": [], "reason": "clean request"}

        if self.limiter.is_banned(ip, now):
            decision.update(action="BLOCK_IP", reason="IP is temporarily banned")
        elif self.limiter.over_limit(ip, now):
            banned = self.limiter.add_strike(ip, "rate", now)
            reason = "request limit exceeded"
            if banned:
                reason += "; IP banned"
            decision.update(action="RATE_LIMIT", reason=reason)
        else:
            result = inspect(req)
            decision.update(action=result["verdict"], score=result["score"],
                            matches=result["matches"])
            if result["verdict"] == "BLOCK":
                banned = self.limiter.add_strike(ip, "attack", now)
                decision["reason"] = "signature match, blocked" + ("; IP banned" if banned else "")
            elif result["verdict"] == "SUSPICIOUS":
                decision["reason"] = "low-score match, allowed and logged"

        decision["status"] = STATUS[decision["action"]]
        decision["categories"] = sorted({m["category"] for m in decision["matches"]})
        decision["rule_ids"] = [m["rule_id"] for m in decision["matches"]]

        if self.logger:
            qs = f"?{req['query']}" if req.get("query") else ""
            self.logger.write({
                "timestamp": iso(now),
                "ip": ip,
                "method": req.get("method", "GET"),
                "url": f"{req.get('path', '/')}{qs}",
                "action": decision["action"],
                "status": decision["status"],
                "score": decision["score"],
                "categories": decision["categories"],
                "rules": decision["rule_ids"],
                "reason": decision["reason"],
            })
        return decision
