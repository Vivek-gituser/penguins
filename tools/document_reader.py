from pathlib import Path

class DocumentReader:
    def __init__(self, folder="sample_documents"):
        self.folder = Path(folder)

    def read_sample(self):
        path = self.folder / "sample_internal.txt"
        if not path.exists():
            raise FileNotFoundError(path)
        return {
            "document_id": path.name,
            "content": path.read_text(encoding="utf-8"),
            "label": "INTERNAL"
        }
