"""
analyzer.py
-----------
Log analysis. Turns the raw log into the summary the project asks for:
number of malicious requests, distribution by attack category, repeatedly
flagged IPs, plus an accuracy evaluation against the labeled test traffic.
"""

from collections import Counter, defaultdict


def _category_of(entry: dict) -> list:
    if entry["categories"]:
        return entry["categories"]
    if entry["action"] == "RATE_LIMIT":
        return ["rate_limit"]
    if entry["action"] == "BLOCK_IP":
        return ["banned_ip"]
    return []


def summarize(entries: list, ban_events: list) -> dict:
    by_action = Counter(e["action"] for e in entries)
    flagged = [e for e in entries if e["action"] != "ALLOW"]

    by_category = Counter()
    for e in flagged:
        for c in _category_of(e):
            by_category[c] += 1

    per_ip = defaultdict(lambda: {"count": 0, "actions": Counter()})
    for e in flagged:
        per_ip[e["ip"]]["count"] += 1
        per_ip[e["ip"]]["actions"][e["action"]] += 1
    repeat_ips = sorted(
        ({"ip": ip, "flagged": d["count"], "actions": dict(d["actions"])}
         for ip, d in per_ip.items() if d["count"] >= 3),
        key=lambda x: -x["flagged"])

    return {
        "total_requests": len(entries),
        "by_action": dict(by_action),
        "malicious_detected": len(flagged),
        "blocked": by_action.get("BLOCK", 0) + by_action.get("RATE_LIMIT", 0) + by_action.get("BLOCK_IP", 0),
        "by_category": dict(by_category.most_common()),
        "repeat_ips": repeat_ips,
        "ban_events": ban_events,
        "unique_ips": len({e["ip"] for e in entries}),
    }


def evaluate(results: list) -> dict:
    """results: dicts with label, category, id, action. Positive = flagged (action != ALLOW)."""
    tp = fp = tn = fn = 0
    fps, fns = [], []
    per_cat = defaultdict(lambda: {"total": 0, "detected": 0})
    for r in results:
        flagged = r["action"] != "ALLOW"
        malicious = r["label"] == "malicious"
        if malicious:
            per_cat[r["category"]]["total"] += 1
            if flagged:
                per_cat[r["category"]]["detected"] += 1
        if malicious and flagged:
            tp += 1
        elif malicious and not flagged:
            fn += 1
            fns.append(r)
        elif not malicious and flagged:
            fp += 1
            fps.append(r)
        else:
            tn += 1
    total = tp + fp + tn + fn
    return {
        "total": total, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "accuracy": round((tp + tn) / total * 100, 1) if total else 0.0,
        "precision": round(tp / (tp + fp) * 100, 1) if (tp + fp) else 0.0,
        "recall": round(tp / (tp + fn) * 100, 1) if (tp + fn) else 0.0,
        "false_positives": fps,
        "false_negatives": fns,
        "per_category": {k: v for k, v in sorted(per_cat.items())},
        "malicious_total": tp + fn,
        "benign_total": tn + fp,
    }
