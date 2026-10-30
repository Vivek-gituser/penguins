from pathlib import Path
from datetime import datetime, timezone
import json

class ReportSaver:
    def __init__(self, folder="saved_reports"):
        self.folder = Path(folder)
        self.folder.mkdir(parents=True, exist_ok=True)

    def save_sample(self):
        report = {
            "report_id": "demo-report-001",
            "content": "AGENTGATE demonstration report",
            "label": "INTERNAL",
            "provenance": {
                "source_ids": ["sample_internal.txt"],
                "transformation": "summary"
            },
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        path = self.folder / "demo-report-001.json"
        path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return {"saved_to": str(path), "label": report["label"]}
