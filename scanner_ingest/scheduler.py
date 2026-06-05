"""
File-watch service mode using APScheduler.

Watches configured directories for new .csv/.xlsx/.json files and automatically
ingests them.  Processed files are logged to avoid reprocessing on restart.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

from apscheduler.schedulers.blocking import BlockingScheduler

from scanner_ingest import pipeline

logger = logging.getLogger(__name__)

_SUPPORTED_EXTENSIONS = {".csv", ".xlsx", ".xls", ".json"}


class IngestScheduler:

    def __init__(self, config: dict):
        self._config   = config
        sched_cfg      = config.get("scheduler", {})
        self._interval = int(sched_cfg.get("poll_interval_seconds", 60))
        self._log_path = Path(sched_cfg.get("processed_log", "./processed_files.log"))
        self._watch_dirs: list[dict] = sched_cfg.get("watch_dirs") or []
        self._processed: set[str]   = self._load_processed_log()
        self._scheduler = BlockingScheduler()

    def start(self):
        if not self._watch_dirs:
            logger.warning("No watch_dirs configured in scheduler section — nothing to watch.")
            return

        self._scheduler.add_job(
            self._scan_all,
            "interval",
            seconds=self._interval,
            id="scan_dirs",
        )
        logger.info(
            "Scheduler started — polling %d director(y/ies) every %ds",
            len(self._watch_dirs),
            self._interval,
        )
        try:
            self._scheduler.start()
        except (KeyboardInterrupt, SystemExit):
            logger.info("Scheduler stopped.")

    def _scan_all(self):
        for entry in self._watch_dirs:
            path        = Path(entry.get("path", ".")).expanduser()
            source_type = entry.get("source_type", "generic")
            platform    = entry.get("platform", self._config.get("synack", {}).get("platform", "commercial"))
            org_uid     = entry.get("org_uid") or os.getenv("SYNACK_ORG_UID") or ""

            if not path.is_dir():
                logger.warning("Watch dir does not exist: %s", path)
                continue

            for file in sorted(path.iterdir()):
                if file.suffix.lower() not in _SUPPORTED_EXTENSIONS:
                    continue
                if str(file.resolve()) in self._processed:
                    continue

                logger.info("New file detected: %s (%s, platform=%s)", file.name, source_type, platform)
                result = pipeline.run(
                    file_path=file,
                    source_type=source_type,
                    org_uid=org_uid,
                    config=self._config,
                    platform=platform,
                )
                if result.success:
                    logger.info(
                        "  %s → parsed=%d submitted=%d ids=%s",
                        file.name, result.parsed, result.submitted, result.created_ids,
                    )
                else:
                    logger.error("  %s → errors: %s", file.name, result.errors)

                self._mark_processed(str(file.resolve()))

    def _load_processed_log(self) -> set[str]:
        if self._log_path.exists():
            return set(self._log_path.read_text().splitlines())
        return set()

    def _mark_processed(self, path: str):
        self._processed.add(path)
        with self._log_path.open("a") as fh:
            fh.write(path + "\n")
