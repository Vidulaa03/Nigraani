"""Copy NIGRAANI data from demo.db (SQLite) into the Supabase PostgreSQL schema.

Status: DRAFT FOR REVIEW.

Modes:
    (default)      Dry run. Reads SQLite read-only, transforms and validates
                   every row, prints a summary. Never connects to PostgreSQL.
    --execute      Loads all rows in ONE transaction, advances identity
                   sequences, re-reads the target and compares it row by row
                   with the source. Commits only if everything matches;
                   otherwise rolls back and the target is left untouched.
    --verify-only  Read-only transaction: compares an already-loaded target
                   with the source. Writes nothing.

The connection string is read from an environment variable (default
DATABASE_URL), optionally loaded from an env file. It is never printed.

This script intentionally does not import backend.database: importing it runs
init_db(), which writes to demo.db.

Usage:
    python scripts/migrate_sqlite_to_postgres.py
    python scripts/migrate_sqlite_to_postgres.py --env-file .env --verify-only
    python scripts/migrate_sqlite_to_postgres.py --env-file .env --execute
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

BASE_DIR = Path(__file__).resolve().parent.parent

# (table, primary key, columns in insert order). Parents before children.
TABLES: list[tuple[str, str, list[str]]] = [
    ("users", "user_id", ["user_id", "name", "email"]),
    ("orders", "order_id", ["order_id", "owner_id", "product", "amount"]),
    (
        "security_events",
        "event_id",
        [
            "event_id", "timestamp", "ip", "user_id", "method", "endpoint",
            "endpoint_pattern", "resource_id", "resource_owner_id", "status_code",
            "response_time_ms", "sim_label",
        ],
    ),
    (
        "detections",
        "detection_id",
        [
            "detection_id", "detector", "attack_type", "severity", "ip", "user_id",
            "evidence", "event_ids", "owasp", "analysis_key",
        ],
    ),
    (
        "decisions",
        "decision_id",
        [
            "decision_id", "ip", "risk_score", "risk_level", "action", "reasons",
            "source", "event_ids", "analysis_key",
        ],
    ),
]
EXPECTED_SQLITE_TABLES = {name for name, _, _ in TABLES} | {"sqlite_sequence"}
TIMESTAMP_COLUMNS = {("security_events", "timestamp")}
JSON_COLUMNS = {
    ("detections", "event_ids"): False,  # value: nullable?
    ("decisions", "reasons"): False,
    ("decisions", "event_ids"): True,
}
FLOAT_COLUMNS = {("orders", "amount"), ("security_events", "response_time_ms")}
IDENTITY_TABLES = {"detections": "detection_id", "decisions": "decision_id"}


class MigrationError(Exception):
    pass


def parse_timestamp(value: Any) -> datetime:
    # Same rule as backend/ml/features.py parse_timestamp: naive means UTC.
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_json_array(value: Any, nullable: bool) -> Any:
    if value is None:
        if nullable:
            return None
        raise MigrationError("NULL in a NOT NULL JSON column")
    parsed = json.loads(value) if isinstance(value, str) else value
    if not isinstance(parsed, list):
        raise MigrationError(f"expected a JSON array, got {type(parsed).__name__}")
    return parsed


def normalise(table: str, column: str, value: Any) -> Any:
    """Canonical comparable form, identical for SQLite and PostgreSQL values."""
    if value is None and (table, column) not in JSON_COLUMNS:
        return None
    if (table, column) in TIMESTAMP_COLUMNS:
        return parse_timestamp(value)
    if (table, column) in JSON_COLUMNS:
        return parse_json_array(value, JSON_COLUMNS[(table, column)])
    if (table, column) in FLOAT_COLUMNS:
        return float(value)
    return value


def read_sqlite(path: Path) -> tuple[dict[str, dict[Any, tuple]], dict[str, int]]:
    if not path.is_file():
        raise MigrationError(f"SQLite file not found: {path}")
    conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    try:
        conn.row_factory = sqlite3.Row
        tables = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        if tables != EXPECTED_SQLITE_TABLES:
            raise MigrationError(
                "SQLite schema drift: unexpected tables "
                f"{sorted(tables ^ EXPECTED_SQLITE_TABLES)}"
            )
        data: dict[str, dict[Any, tuple]] = {}
        for table, pk, columns in TABLES:
            actual = [row["name"] for row in conn.execute(f"PRAGMA table_info({table})")]
            if set(actual) != set(columns):
                raise MigrationError(
                    f"SQLite schema drift in {table}: {sorted(set(actual) ^ set(columns))}"
                )
            rows: dict[Any, tuple] = {}
            for row in conn.execute(f"SELECT {', '.join(columns)} FROM {table}"):
                try:
                    rows[row[pk]] = tuple(normalise(table, c, row[c]) for c in columns)
                except (ValueError, MigrationError) as exc:
                    raise MigrationError(f"{table} {pk}={row[pk]}: {exc}") from exc
            data[table] = rows
        sequences = dict(conn.execute("SELECT name, seq FROM sqlite_sequence").fetchall())
    finally:
        conn.close()
    return data, sequences


def source_checks(data: dict[str, dict[Any, tuple]]) -> list[str]:
    """Problems that would break the target constraints. Empty means loadable."""
    problems = []
    user_ids = set(data["users"])
    orphan_orders = [oid for oid, row in data["orders"].items() if row[1] not in user_ids]
    if orphan_orders:
        problems.append(f"orders with unknown owner_id (FK would fail): {orphan_orders[:10]}")
    for table, key_index in (("detections", 9), ("decisions", 8)):
        keys = [row[key_index] for row in data[table].values() if row[key_index] is not None]
        if len(keys) != len(set(keys)):
            problems.append(f"{table}: duplicate non-null analysis_key values")
    return problems


def source_report(data: dict[str, dict[Any, tuple]], sequences: dict[str, int]) -> list[str]:
    lines = [f"  {table:16} {len(data[table]):>6} rows" for table, _, _ in TABLES]
    event_ids = set(data["security_events"])
    order_ids = set(data["orders"])
    dangling = sum(
        1 for row in data["detections"].values() for eid in row[7] if eid not in event_ids
    )
    resource_orphans = sum(
        1 for row in data["security_events"].values()
        if row[7] is not None and row[7] not in order_ids
    )
    legacy_groups = len({(r[1], r[2], r[4], r[5], tuple(r[7])) for r in data["detections"].values()})
    lines += [
        f"  sqlite_sequence  {sequences}",
        f"  detections.event_ids refs to missing events: {dangling}",
        f"  security_events.resource_id without order (info, no FK): {resource_orphans}",
        f"  distinct detection groups (legacy duplicates kept as-is): {legacy_groups}",
    ]
    return lines


def resolve_database_url(env_var: str, env_file: Path | None) -> str:
    value = os.environ.get(env_var)
    if not value and env_file is not None:
        if not env_file.is_file():
            raise MigrationError(f"env file not found: {env_file}")
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith(f"{env_var}="):
                value = line.split("=", 1)[1].strip().strip("'\"")
    if not value:
        raise MigrationError(f"{env_var} is not set")
    if not value.startswith(("postgres://", "postgresql://")):
        raise MigrationError(f"{env_var} is not a PostgreSQL URL")
    return value


def connect(url: str):
    try:
        import psycopg
    except ImportError as exc:
        raise MigrationError("psycopg is not installed: pip install 'psycopg[binary]>=3.2,<4'") from exc
    kwargs: dict[str, Any] = {"connect_timeout": 15, "autocommit": False}
    if "sslmode=" not in url:
        kwargs["sslmode"] = "require"
    try:
        conn = psycopg.connect(url, **kwargs)
    except psycopg.OperationalError as exc:
        # libpq messages name the host but never the password.
        raise MigrationError(f"could not connect: {str(exc).strip().splitlines()[0]}") from None
    conn.execute("SET TIME ZONE 'UTC'")
    return conn


def read_target(conn) -> dict[str, dict[Any, tuple]]:
    data = {}
    for table, pk, columns in TABLES:
        quoted = ", ".join(f'"{c}"' for c in columns)
        rows = {}
        for row in conn.execute(f"SELECT {quoted} FROM public.{table}"):
            values = dict(zip(columns, row))
            rows[values[pk]] = tuple(normalise(table, c, values[c]) for c in columns)
        data[table] = rows
    return data


def compare(source: dict, target: dict) -> list[str]:
    problems = []
    for table, pk, _ in TABLES:
        src, dst = source[table], target[table]
        if len(src) != len(dst):
            problems.append(f"{table}: row count source={len(src)} target={len(dst)}")
        missing = set(src) - set(dst)
        extra = set(dst) - set(src)
        if missing:
            problems.append(f"{table}: {len(missing)} {pk}s missing, e.g. {sorted(missing)[:5]}")
        if extra:
            problems.append(f"{table}: {len(extra)} unexpected {pk}s, e.g. {sorted(extra)[:5]}")
        changed = [k for k in set(src) & set(dst) if src[k] != dst[k]]
        if changed:
            problems.append(f"{table}: {len(changed)} rows differ, e.g. {pk}={sorted(changed)[:5]}")
    return problems


def target_checks(conn, sequences: dict[str, int], source: dict) -> list[str]:
    problems = []
    for table, column in IDENTITY_TABLES.items():
        floor = max(sequences.get(table, 0), max(source[table], default=0))
        next_value = conn.execute(
            "SELECT CASE WHEN is_called THEN last_value + 1 ELSE last_value END "
            f"FROM public.{table}_{column}_seq"
        ).fetchone()[0]
        if next_value <= floor:
            problems.append(f"{table}: next identity {next_value} would reuse an ID <= {floor}")
    orphan_orders = conn.execute(
        "SELECT count(*) FROM public.orders o LEFT JOIN public.users u "
        "ON u.user_id = o.owner_id WHERE u.user_id IS NULL"
    ).fetchone()[0]
    if orphan_orders:
        problems.append(f"orders: {orphan_orders} rows with unknown owner_id")
    rls_off = conn.execute(
        "SELECT array_agg(c.relname::text) FROM pg_class c "
        "JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' "
        "AND c.relname = ANY(%s) AND NOT c.relrowsecurity",
        ([t for t, _, _ in TABLES],),
    ).fetchone()[0]
    if rls_off:
        problems.append(f"RLS disabled on: {rls_off}")
    return problems


def ensure_target_ready(conn) -> None:
    for table, _, _ in TABLES:
        exists = conn.execute("SELECT to_regclass(%s)", (f"public.{table}",)).fetchone()[0]
        if exists is None:
            raise MigrationError(f"target table public.{table} missing; apply 001 up first")
        count = conn.execute(f"SELECT count(*) FROM public.{table}").fetchone()[0]
        if count:
            raise MigrationError(f"target table public.{table} already has {count} rows; refusing to merge")


def load(conn, sqlite_path: Path, sequences: dict[str, int], source: dict) -> None:
    from psycopg.types.json import Jsonb

    raw = sqlite3.connect(f"file:{sqlite_path.as_posix()}?mode=ro", uri=True)
    try:
        for table, pk, columns in TABLES:
            insert_columns = columns + (["created_at"] if table in IDENTITY_TABLES else [])
            placeholders = ", ".join(["%s"] * len(insert_columns))
            quoted = ", ".join(f'"{c}"' for c in insert_columns)
            rows = []
            for values in raw.execute(f"SELECT {', '.join(columns)} FROM {table} ORDER BY {pk}"):
                converted = []
                for column, value in zip(columns, values):
                    if (table, column) in TIMESTAMP_COLUMNS:
                        value = parse_timestamp(value)
                    elif (table, column) in JSON_COLUMNS:
                        parsed = parse_json_array(value, JSON_COLUMNS[(table, column)])
                        value = None if parsed is None else Jsonb(parsed)
                    converted.append(value)
                if table in IDENTITY_TABLES:
                    converted.append(None)  # created_at unknown for legacy rows
                rows.append(converted)
            with conn.cursor() as cur:
                cur.executemany(
                    f"INSERT INTO public.{table} ({quoted}) VALUES ({placeholders})", rows
                )
            print(f"  loaded {table}: {len(rows)}")
    finally:
        raw.close()

    for table, column in IDENTITY_TABLES.items():
        floor = max(sequences.get(table, 0), max(source[table], default=0))
        if floor:
            conn.execute(f"SELECT setval('public.{table}_{column}_seq', %s, true)", (floor,))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--sqlite", type=Path, default=BASE_DIR / "demo.db")
    parser.add_argument("--database-url-env", default="DATABASE_URL")
    parser.add_argument("--env-file", type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--execute", action="store_true")
    mode.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()

    try:
        source, sequences = read_sqlite(args.sqlite)
        print(f"Source: {args.sqlite.name}")
        print("\n".join(source_report(source, sequences)))
        problems = source_checks(source)
        if problems:
            raise MigrationError("source not loadable:\n  " + "\n  ".join(problems))
        print("Source checks: OK (all rows parse; JSON arrays and timestamps valid)")

        if not (args.execute or args.verify_only):
            print("Dry run only. Nothing was written. Use --execute to load.")
            return 0

        url = resolve_database_url(args.database_url_env, args.env_file)
        conn = connect(url)
        try:
            if args.verify_only:
                conn.execute("SET TRANSACTION READ ONLY")
            else:
                ensure_target_ready(conn)
                load(conn, args.sqlite, sequences, source)
            problems = compare(source, read_target(conn)) + target_checks(conn, sequences, source)
            if problems:
                conn.rollback()
                raise MigrationError("validation failed, rolled back:\n  " + "\n  ".join(problems))
            if args.execute:
                conn.commit()
                print("Committed. Target matches source row for row.")
            else:
                conn.rollback()
                print("Verified. Target matches source row for row.")
        finally:
            conn.close()
    except MigrationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
