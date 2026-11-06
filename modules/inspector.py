"""
inspector.py
------------
HTTP request inspection. Breaks a request into its parts (path, query
parameters, headers, body), decodes each part, and checks it against the rules.

Decoding matters because attackers hide payloads with URL encoding, double
encoding and HTML entities. Without it, %27%20OR%20%271%27%3D%271 would not
match the "OR '1'='1" signature.
"""

import html
from urllib.parse import parse_qsl, unquote_plus

from .rules import RULES

BLOCK_THRESHOLD = 5      # score at or above this is blocked
MAX_SCORE = 20


def normalize(value: str) -> str:
    """URL-decode and HTML-unescape repeatedly (up to 3 passes) until stable."""
    current = value or ""
    for _ in range(3):
        decoded = html.unescape(unquote_plus(current))
        if decoded == current:
            break
        current = decoded
    return current.replace("\x00", "")


def _components(req: dict):
    """Yield (location, text) pairs for every part of the request worth checking."""
    yield "path", normalize(req.get("path", ""))

    query = req.get("query", "") or ""
    for name, value in parse_qsl(query, keep_blank_values=True):
        yield f"query:{name}", normalize(value)
        yield f"query-name:{name}", normalize(name)
    if query:
        # the whole string catches payloads that contain & or ; separators
        yield "query-string", normalize(query)

    for name, value in (req.get("headers") or {}).items():
        if name.lower() == "host":
            continue
        yield f"header:{name}", normalize(str(value))

    body = req.get("body", "") or ""
    if body:
        for name, value in parse_qsl(body, keep_blank_values=True):
            yield f"body:{name}", normalize(value)
        yield "body", normalize(body)


def inspect(req: dict) -> dict:
    """Return {score, verdict, matches[]} for one request."""
    found = {}   # rule_id -> match info; a rule counts once per request
    for location, text in _components(req):
        if not text:
            continue
        for rule in RULES:
            if rule.rule_id in found:
                continue
            m = rule.regex.search(text)
            if m:
                found[rule.rule_id] = {
                    "rule_id": rule.rule_id,
                    "category": rule.category,
                    "name": rule.name,
                    "severity": rule.severity,
                    "weight": rule.weight,
                    "location": location,
                    "snippet": m.group(0)[:60],
                }
    matches = list(found.values())
    score = min(MAX_SCORE, sum(m["weight"] for m in matches))
    if score >= BLOCK_THRESHOLD:
        verdict = "BLOCK"
    elif score > 0:
        verdict = "SUSPICIOUS"
    else:
        verdict = "ALLOW"
    return {"score": score, "verdict": verdict, "matches": matches}
