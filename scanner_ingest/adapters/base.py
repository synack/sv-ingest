from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from scanner_ingest.models import VulnerabilityRecord


class BaseAdapter(ABC):
    def __init__(self, source_id: str, config: dict = None):
        self.source_id = source_id
        self.config = config or {}

    @abstractmethod
    def parse(self, file_path: Path) -> list[VulnerabilityRecord]:
        ...

    def _detect_format(self, file_path: Path) -> str:
        suffix = file_path.suffix.lower()
        if suffix == ".csv":
            return "csv"
        if suffix in (".xlsx", ".xls"):
            return "excel"
        if suffix == ".json":
            return "json"
        raise ValueError(f"Unsupported file format: {suffix!r}. Expected .csv, .xlsx, .xls, or .json")

    @staticmethod
    def _parse_date(value: object) -> Optional[datetime]:
        if not value or str(value).strip() in ("", "nan", "None"):
            return None
        s = str(value).strip()
        for fmt in (
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d",
            "%m/%d/%Y",
            "%d/%m/%Y",
        ):
            try:
                dt = datetime.strptime(s, fmt)
                return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None

    @staticmethod
    def _safe_float(value: object, default: float = 0.0) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _split_ids(value: object) -> list[str]:
        """Split a comma/semicolon-delimited string into a list, or return list as-is."""
        if isinstance(value, list):
            return [str(v).strip() for v in value if str(v).strip()]
        if not value or str(value).strip() in ("", "nan", "None"):
            return []
        return [v.strip() for v in str(value).replace(";", ",").split(",") if v.strip()]
