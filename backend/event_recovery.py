"""Durable recovery spool for security events the database could not store.

When backend.security_logger cannot write a validated event to SQLite, it
appends the event (with its original event_id and timestamp) to the spool
instead of dropping it. Spooled events are NOT stored: they are counted as
failed, and they reach the database, the analyzer, and the JSONL log only
when replay_spool() succeeds.

Spool entries are single JSON lines with a SHA-256 checksum of the event.
Replay claims the spool by renaming it (so appends from the API continue in
a fresh file), then for each entry:
  * inserted              -> appended to the JSONL log, removed from the spool
  * same event already in the database -> removed (replay is idempotent)
  * different event with the same ID   -> moved to the "conflict" file
  * corrupt / incomplete / invalid     -> moved to the "corrupt" file
  * database still failing             -> kept, attempts + 1; after
    MAX_REPLAY_ATTEMPTS moved to the "exhausted" file
Nothing is removed from a claimed file until its entries have been written to
the database or to another file AND the caller's on_recovered callback has
recorded the recovered IDs (the analyzer saves them as pending). A crash
before that leaves the claimed file in place; the next replay finds those
events "already present" and reports them as recovered again, so they still
reach the analyzer. Known gap: an event inserted just before a crash may be
missing from the JSONL log (the database row is the record; `reconcile`
shows such gaps).

Usage:
    python -m backend.event_recovery status
    python -m backend.event_recovery replay      # needs the analyzer stopped
    python -m backend.event_recovery reconcile   # read-only JSONL/DB report
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sqlite3
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import backend.database as database
from backend.database import BASE_DIR, DuplicateEventError, get_events_by_ids, insert_event
from backend.detection.base import EVENT_REQUIRED_FIELDS, validate_event
from backend.metrics import SECURITY_EVENT_SPOOL

logger = logging.getLogger(__name__)

SPOOL_FILE = Path(
    os.environ.get("NIGRAANI_EVENT_SPOOL_PATH")
    or Path(os.environ.get("NIGRAANI_LOG_DIR") or BASE_DIR / "logs") / "event_recovery_spool.jsonl"
)
MAX_SPOOL_BYTES = int(os.environ.get("NIGRAANI_EVENT_SPOOL_MAX_BYTES") or 50 * 1024 * 1024)
MAX_REPLAY_ATTEMPTS = 10
REPLAY_BATCH_LIMIT = 1000
_SPOOL_VERSION = 1
_EVENT_FIELDS = (*EVENT_REQUIRED_FIELDS, "user_id", "resource_id", "resource_owner_id")
_spool_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _checksum(event: dict[str, Any]) -> str:
    payload = json.dumps(event, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def quarantine_file(kind: str) -> Path:
    """Where entries that will not be retried automatically are kept."""
    return SPOOL_FILE.with_name(f"{SPOOL_FILE.stem}.{kind}{SPOOL_FILE.suffix}")


def _claimed_files() -> list[Path]:
    return sorted(SPOOL_FILE.parent.glob(f"{SPOOL_FILE.stem}.replaying-*{SPOOL_FILE.suffix}"))


def locked_append(path: Path, text: str, *, fsync: bool) -> None:
    """Append text under an exclusive cross-process lock.

    Append mode alone is not atomic across processes on Windows (two API
    workers lost JSONL lines in testing). The lock also makes the "does the
    file end with a newline" check safe, so a line is never glued onto a
    partial line left by a crash.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a+b") as file:
        if os.name == "nt":
            import msvcrt

            file.seek(0)
            msvcrt.locking(file.fileno(), msvcrt.LK_LOCK, 1)  # retries for ~10 s
        else:
            import fcntl

            fcntl.flock(file.fileno(), fcntl.LOCK_EX)
        try:
            file.seek(0, os.SEEK_END)
            prefix = b""
            if file.tell() > 0:
                file.seek(-1, os.SEEK_END)
                if file.read(1) != b"\n":
                    prefix = b"\n"
                file.seek(0, os.SEEK_END)
            file.write(prefix + text.encode("utf-8"))
            file.flush()
            if fsync:
                os.fsync(file.fileno())
        finally:
            if os.name == "nt":
                file.seek(0)
                msvcrt.locking(file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(file.fileno(), fcntl.LOCK_UN)


def _append_lines(path: Path, lines: list[str]) -> None:
    """Append whole lines durably (fsync), for the spool and quarantine files."""
    if lines:
        locked_append(path, "".join(lines), fsync=True)


def _entry_line(event: dict[str, Any], *, attempts: int, error: str, queued_at: str) -> str:
    entry = {
        "spool_version": _SPOOL_VERSION,
        "queued_at": queued_at,
        "attempts": attempts,
        "last_error": error,
        "checksum": _checksum(event),
        "event": event,
    }
    return json.dumps(entry, separators=(",", ":")) + "\n"


def spool_event(event: dict[str, Any], error: BaseException) -> bool:
    """Queue a validated event for replay. Returns False if it was not queued."""
    try:
        validate_event(event)
    except ValueError as invalid:
        SECURITY_EVENT_SPOOL.labels("spool_failed").inc()
        logger.critical("Security event %s not spooled: invalid: %s", event.get("event_id"), invalid)
        return False

    stored = {name: event.get(name) for name in _EVENT_FIELDS}
    line = _entry_line(stored, attempts=0, error=type(error).__name__, queued_at=_now())
    with _spool_lock:
        try:
            size = SPOOL_FILE.stat().st_size if SPOOL_FILE.exists() else 0
            if size + len(line) > MAX_SPOOL_BYTES:
                SECURITY_EVENT_SPOOL.labels("spool_full").inc()
                logger.critical(
                    "Security event %s lost: recovery spool %s is full (%d bytes)",
                    event["event_id"], SPOOL_FILE, size,
                )
                return False
            _append_lines(SPOOL_FILE, [line])
        except OSError as write_error:
            SECURITY_EVENT_SPOOL.labels("spool_failed").inc()
            logger.critical(
                "Security event %s lost: recovery spool %s not writable: %s",
                event["event_id"], SPOOL_FILE, write_error,
            )
            return False
    SECURITY_EVENT_SPOOL.labels("queued").inc()
    logger.warning(
        "Security event %s queued for replay in %s after %s",
        event["event_id"], SPOOL_FILE, type(error).__name__,
    )
    return True


def _parse_entry(line: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return (entry, event) or raise ValueError for corrupt entries."""
    if not line.endswith("\n"):
        raise ValueError("incomplete line")
    entry = json.loads(line)
    if not isinstance(entry, dict) or entry.get("spool_version") != _SPOOL_VERSION:
        raise ValueError("unknown spool entry format")
    event = entry.get("event")
    if not isinstance(event, dict) or entry.get("checksum") != _checksum(event):
        raise ValueError("checksum mismatch")
    if not isinstance(entry.get("attempts"), int) or entry["attempts"] < 0:
        raise ValueError("invalid attempts")
    validate_event(event)
    return entry, event


def _same_event(stored: dict[str, Any], event: dict[str, Any]) -> bool:
    return all(stored.get(name) == event.get(name) for name in _EVENT_FIELDS)


@dataclass
class ReplaySummary:
    replayed: list[int] = field(default_factory=list)
    # Replayed plus already-present IDs: everything that needs analysis.
    recovered: list[int] = field(default_factory=list)
    already_present: int = 0
    requeued: int = 0
    quarantined: dict[str, int] = field(default_factory=dict)
    stopped_early: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "replayed": len(self.replayed),
            "recovered_for_analysis": len(self.recovered),
            "already_present": self.already_present,
            "requeued": self.requeued,
            "quarantined": dict(self.quarantined),
            "stopped_early": self.stopped_early,
        }


def _claim_spool() -> Path | None:
    if not SPOOL_FILE.exists() or SPOOL_FILE.stat().st_size == 0:
        return None
    claimed = SPOOL_FILE.with_name(
        f"{SPOOL_FILE.stem}.replaying-{os.getpid()}-{time.time_ns()}{SPOOL_FILE.suffix}"
    )
    for _ in range(5):
        try:
            with _spool_lock:
                os.replace(SPOOL_FILE, claimed)
            return claimed
        except PermissionError:
            # Windows: another process is appending right now.
            time.sleep(0.05)
    raise OSError(f"could not claim {SPOOL_FILE}; it stayed locked")


def replay_spool(
    *,
    limit: int = REPLAY_BATCH_LIMIT,
    on_recovered: Callable[[list[int]], None] | None = None,
) -> ReplaySummary:
    """Retry spooled events through the validated insert path.

    Processes at most `limit` entries; the rest stay queued. Stops at the
    first database failure so a down database is not hammered. on_recovered
    receives each claimed file's recovered IDs before that file is deleted;
    if it raises, the file is kept and the IDs are reported again next time.
    """
    from backend.security_logger import append_jsonl  # avoids a circular import

    summary = ReplaySummary()
    claimed = list(_claimed_files())
    fresh = _claim_spool()
    if fresh is not None:
        claimed.append(fresh)

    budget = limit
    for path in claimed:
        recovered_before = len(summary.recovered)
        requeue: list[str] = []
        quarantine: dict[str, list[str]] = {}

        def flush() -> None:
            with _spool_lock:
                _append_lines(SPOOL_FILE, requeue)
            for kind, lines in quarantine.items():
                _append_lines(quarantine_file(kind), lines)
                summary.quarantined[kind] = summary.quarantined.get(kind, 0) + len(lines)
                SECURITY_EVENT_SPOOL.labels("quarantined").inc(len(lines))
            summary.requeued += len(requeue)
            if requeue:
                SECURITY_EVENT_SPOOL.labels("requeued").inc(len(requeue))
            requeue.clear()
            quarantine.clear()

        with open(path, encoding="utf-8", newline="") as file:
            for line in file:
                if not line.strip():
                    continue
                if summary.stopped_early or budget <= 0:
                    requeue.append(line)
                else:
                    budget -= 1
                    _replay_line(line, summary, requeue, quarantine, append_jsonl)
                if len(requeue) + sum(map(len, quarantine.values())) >= 1000:
                    flush()
        flush()
        file_recovered = summary.recovered[recovered_before:]
        if on_recovered is not None and file_recovered:
            on_recovered(file_recovered)
        path.unlink()

    if summary.replayed or summary.quarantined or summary.stopped_early:
        logger.info("Event spool replay: %s", summary.as_dict())
    return summary


def _replay_line(line, summary, requeue, quarantine, append_jsonl) -> None:
    try:
        entry, event = _parse_entry(line)
    except (ValueError, json.JSONDecodeError) as error:
        logger.error("Corrupt spool entry quarantined: %s", error)
        quarantine.setdefault("corrupt", []).append(line if line.endswith("\n") else line + "\n")
        return

    try:
        insert_event(event)
    except DuplicateEventError:
        stored = get_events_by_ids([event["event_id"]])
        if stored and _same_event(stored[0], event):
            # Possibly inserted by a replay that crashed before finishing:
            # still report it so the analyzer does not skip it.
            summary.already_present += 1
            summary.recovered.append(event["event_id"])
            SECURITY_EVENT_SPOOL.labels("already_present").inc()
        else:
            logger.error(
                "Spooled event %s conflicts with a different stored event; quarantined",
                event["event_id"],
            )
            quarantine.setdefault("conflict", []).append(line)
        return
    except Exception as error:
        attempts = entry["attempts"] + 1
        retry_line = _entry_line(
            event, attempts=attempts, error=type(error).__name__, queued_at=entry["queued_at"]
        )
        if attempts >= MAX_REPLAY_ATTEMPTS:
            logger.error(
                "Spooled event %s failed %d replays (%s); moved to %s",
                event["event_id"], attempts, type(error).__name__, quarantine_file("exhausted"),
            )
            quarantine.setdefault("exhausted", []).append(retry_line)
        else:
            requeue.append(retry_line)
        summary.stopped_early = True
        logger.warning("Event spool replay paused: %s: %s", type(error).__name__, error)
        return

    summary.replayed.append(event["event_id"])
    summary.recovered.append(event["event_id"])
    SECURITY_EVENT_SPOOL.labels("replayed").inc()
    append_jsonl(event)


def spool_status() -> dict[str, Any]:
    def count(path: Path) -> int:
        if not path.exists():
            return 0
        with open(path, encoding="utf-8", errors="replace") as file:
            return sum(1 for line in file if line.strip())

    return {
        "spool_file": str(SPOOL_FILE),
        "queued": count(SPOOL_FILE) + sum(count(path) for path in _claimed_files()),
        **{kind: count(quarantine_file(kind)) for kind in ("corrupt", "conflict", "exhausted")},
    }


def reconcile(jsonl_path: Path | None = None, *, sample: int = 20) -> dict[str, Any]:
    """Compare JSONL event IDs with the database. Reads only; writes nothing."""
    if jsonl_path is None:
        from backend.security_logger import LOG_FILE

        jsonl_path = LOG_FILE
    jsonl_ids: set[int] = set()
    duplicates = 0
    malformed_lines: list[int] = []
    line_count = 0
    if jsonl_path.exists():
        with open(jsonl_path, encoding="utf-8", errors="replace", newline="") as file:
            for number, line in enumerate(file, start=1):
                line_count = number
                try:
                    if not line.endswith("\n"):
                        raise ValueError("incomplete line")
                    event_id = json.loads(line)["event_id"]
                    if not isinstance(event_id, int) or isinstance(event_id, bool):
                        raise ValueError("bad event_id")
                except (ValueError, KeyError, TypeError):
                    malformed_lines.append(number)
                    continue
                if event_id in jsonl_ids:
                    duplicates += 1
                jsonl_ids.add(event_id)

    uri = f"file:{Path(database.DB_PATH).as_posix()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as conn:
        db_ids = {row[0] for row in conn.execute("SELECT event_id FROM security_events")}

    only_jsonl = sorted(jsonl_ids - db_ids)
    only_db = sorted(db_ids - jsonl_ids)
    return {
        "jsonl_path": str(jsonl_path),
        "jsonl_lines": line_count,
        "jsonl_events": len(jsonl_ids),
        "database_events": len(db_ids),
        "duplicate_jsonl_ids": duplicates,
        "malformed_jsonl_lines": malformed_lines[:sample],
        "malformed_jsonl_line_count": len(malformed_lines),
        "only_in_jsonl": only_jsonl[:sample],
        "only_in_jsonl_count": len(only_jsonl),
        "only_in_database": only_db[:sample],
        "only_in_database_count": len(only_db),
    }


def _replay_command() -> int:
    from backend import analyzer

    try:
        lock_file = analyzer._acquire_single_instance_lock()
    except RuntimeError:
        print("The analyzer is running; it replays the spool automatically.", file=sys.stderr)
        return 1
    try:
        state = analyzer.load_analyzer_state()
        # Replayed events usually sit below the analyzer cursor; queue them so
        # the next analyzer run analyzes them.
        summary = replay_spool(
            limit=sys.maxsize,
            on_recovered=lambda ids: analyzer.record_pending_events(state, ids),
        )
    finally:
        analyzer._release_single_instance_lock(lock_file)
    print(json.dumps(summary.as_dict(), indent=2))
    return 0 if not summary.stopped_early else 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="NIGRAANI security event recovery")
    parser.add_argument("command", choices=("status", "replay", "reconcile"))
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    if args.command == "status":
        print(json.dumps(spool_status(), indent=2))
        return 0
    if args.command == "replay":
        return _replay_command()
    print(json.dumps(reconcile(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
