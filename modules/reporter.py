"""
reporter.py
-----------
Writes the markdown practical report (output/sentinel_report.md) from the
analysis summary and the evaluation, so the numbers always match the logs.
"""

from datetime import datetime, timezone


def _table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def build_report(summary: dict, evaluation: dict, mode: str = "simulation") -> str:
    ev, sm = evaluation, summary
    lines = ["# SentinelShield: Detection Report", ""]
    lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  ")
    lines.append(f"Mode: {mode}  ")
    lines.append(f"Requests processed: **{sm['total_requests']}** from {sm['unique_ips']} source IPs")
    lines.append("")

    lines.append("## 1. Outcome of every request")
    lines.append(_table(["Action", "Count"], [(k, v) for k, v in sorted(sm["by_action"].items())]))
    lines.append("")
    lines.append(f"Flagged (anything except ALLOW): **{sm['malicious_detected']}**. "
                 f"Blocked outright (BLOCK, RATE_LIMIT, BLOCK_IP): **{sm['blocked']}**.")
    lines.append("")

    lines.append("## 2. Distribution by attack category")
    lines.append(_table(["Category", "Flagged requests"], list(sm["by_category"].items())))
    lines.append("")

    lines.append("## 3. Repeatedly flagged IP addresses")
    if sm["repeat_ips"]:
        lines.append(_table(["IP", "Flagged requests", "Actions"],
                            [(r["ip"], r["flagged"], ", ".join(f"{k}={v}" for k, v in r["actions"].items()))
                             for r in sm["repeat_ips"]]))
    else:
        lines.append("No IP was flagged three or more times.")
    lines.append("")
    if sm["ban_events"]:
        lines.append("Temporary bans issued:")
        lines.append("")
        lines.append(_table(["IP", "Reason", "Strikes"],
                            [(b["ip"], b["reason"], b["strikes"]) for b in sm["ban_events"]]))
        lines.append("")

    lines.append("## 4. Detection accuracy on labeled traffic")
    lines.append(_table(["Metric", "Value"], [
        ("Total labeled requests", ev["total"]),
        ("Malicious requests sent", ev["malicious_total"]),
        ("Benign requests sent", ev["benign_total"]),
        ("True positives", ev["tp"]), ("True negatives", ev["tn"]),
        ("False positives", ev["fp"]), ("False negatives", ev["fn"]),
        ("Accuracy", f"{ev['accuracy']}%"),
        ("Precision", f"{ev['precision']}%"),
        ("Recall (detection rate)", f"{ev['recall']}%"),
    ]))
    lines.append("")
    lines.append(_table(["Attack category", "Sent", "Detected"],
                        [(c, v["total"], v["detected"]) for c, v in ev["per_category"].items()]))
    lines.append("")

    lines.append("## 5. False positives")
    if ev["false_positives"]:
        for r in ev["false_positives"]:
            lines.append(f"- **{r['id']}**: {r['method']} {r['url']} was flagged as {r['action']}. {r.get('note', '')}")
    else:
        lines.append("None.")
    lines.append("")
    lines.append("## 6. False negatives")
    if ev["false_negatives"]:
        for r in ev["false_negatives"]:
            lines.append(f"- **{r['id']}**: {r['method']} {r['url']} was allowed. {r.get('note', '')}")
    else:
        lines.append("None.")
    lines.append("")

    lines.append("## 7. Suggested rule improvements")
    if ev["false_negatives"]:
        lines.append("- Decode base64 values and re-inspect them to catch encoded script tags.")
        lines.append("- Add rules for blind SQL injection functions such as ASCII, SUBSTRING and @@version.")
    if ev["false_positives"]:
        lines.append("- Lower the weight of single signatures in free-text fields (search, comments), or require two matching signals before blocking.")
        lines.append("- Add an allow-list for known-safe endpoints that legitimately accept code-like text.")
    lines.append("- Tune the rate limit per endpoint: a login page needs a much lower limit than a static page.")
    lines.append("")
    return "\n".join(lines)
