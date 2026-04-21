"""Append-only JSONL audit log.

Every request — naive or protected — produces exactly one entry. The entry
captures each pipeline stage so a reviewer can reconstruct why a particular
document was or was not included.
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from app.models.schemas import AuditEntry, Redaction


class AuditLogger:
    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path

    def log(self, entry: AuditEntry) -> None:
        line = entry.model_dump_json()
        with self._lock:
            with self._path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")

    def read_all(self) -> List[AuditEntry]:
        if not self._path.exists():
            return []
        out: List[AuditEntry] = []
        with self._path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(AuditEntry.model_validate_json(line))
        return out


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def preview(text: str, limit: int = 500) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "...[truncated]"


__all__ = ["AuditLogger", "AuditEntry", "Redaction", "now_iso", "preview"]
