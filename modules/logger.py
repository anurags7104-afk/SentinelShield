"""
logger.py
---------
Writes one JSON object per line (JSON Lines) for every request handled, and
can also export the same log as CSV for opening in Excel.
"""

import csv
import json
from pathlib import Path

CSV_FIELDS = ["timestamp", "ip", "method", "url", "action", "status",
              "score", "categories", "rules", "reason"]


class EventLogger:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def reset(self):
        self.path.write_text("", encoding="utf-8")

    def write(self, entry: dict):
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    def read(self) -> list:
        if not self.path.exists():
            return []
        with self.path.open(encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def export_csv(self, csv_path):
        rows = self.read()
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
            w.writeheader()
            for r in rows:
                r = dict(r)
                r["categories"] = ";".join(r["categories"])
                r["rules"] = ";".join(r["rules"])
                w.writerow(r)
